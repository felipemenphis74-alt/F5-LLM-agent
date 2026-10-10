# -*- coding: utf-8 -*-
"""Testes do f5_tcpdump.py SEM depender do F5 (nem de tcpdump real).

Rodar (Python 3, a partir da raiz do repo):
    PYTHONPATH=. python onbox/test_f5_tcpdump.py

Cobre: validacao/safety, parsing de pcap (Ethernet/SLL/SLL2/VLAN/IPv6/opcoes TCP/
truncado), paridade com o parser de texto do agente (src/tcpdump_parser.py),
caminho completo run() com um `tcpdump` falso, concorrencia, CLI e um lint de
compatibilidade com Python 2.7.
"""
import ast
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import f5_tcpdump as ft  # noqa: E402

SCRIPT = os.path.join(HERE, "f5_tcpdump.py")
BLOCKED_MESSAGE = ("Capturas na porta TCP 1222 (porta de conexão com a captura RISe) "
                   "estão desabilitadas para esta ferramenta.")

TCP_SYN, TCP_SYN_ACK, TCP_PSH_ACK, TCP_RST_ACK = 0x02, 0x12, 0x18, 0x14


# ---------------------------------------------------------------------------
# Construtores de pacotes / pcap
# ---------------------------------------------------------------------------

def iso_payload(mti, bit70, bit11="000123"):
    """94 bytes: 7 de prefixo + MTI(4) + bitmap(32) + campos (offsets do parser)."""
    prefix = b"\x00\x5a" + b"ISO01"
    bitmap = b"8220000000000000" + b"0400000000000000"
    fields = (b"0920140102" + bit11.encode() + b"123456" + b"000000000123"
              + bit70.encode() + b"12345" + b"123456789")
    return prefix + mti.encode() + bitmap + fields


def tcp_segment(sport, dport, flags, payload=b"", options=b""):
    assert len(options) % 4 == 0
    data_off = (20 + len(options)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, data_off << 4, flags,
                       65535, 0, 0) + options + payload


def ipv4_packet(src, dst, l4, proto=6, frag=0, ihl_options=b""):
    ihl = (20 + len(ihl_options)) // 4
    total = 20 + len(ihl_options) + len(l4)
    header = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, total, 0, frag, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + ihl_options + l4


def ipv6_packet(src, dst, l4, next_header=6):
    header = struct.pack("!IHBB16s16s", 6 << 28, len(l4), next_header, 64,
                         socket.inet_pton(socket.AF_INET6, src),
                         socket.inet_pton(socket.AF_INET6, dst))
    return header + l4


def eth(ip, ethertype=0x0800, vlan=None):
    mac = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
    if vlan is not None:
        return mac + struct.pack("!HHH", 0x8100, vlan, ethertype) + ip
    return mac + struct.pack("!H", ethertype) + ip


def sll(ip, proto=0x0800):
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, proto) + ip


def sll2(ip, proto=0x0800):
    return struct.pack("!HHIHBB8s", proto, 0, 1, 1, 0, 6, b"\x00" * 8) + ip


def pcap(frames, linktype=1, endian="<", magic=0xA1B2C3D4, stamps=None):
    """`stamps`: instante de cada quadro (s, float); padrao = 1 s entre quadros."""
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(frames):
        if stamps is None:
            sec, usec = 1700000000 + index, 123456
        else:
            sec = int(stamps[index])
            usec = int(round((stamps[index] - sec) * 1000000))
        out += struct.pack(endian + "IIII", sec, usec, len(frame), len(frame))
        out += frame
    return out


def one(frames, **kwargs):
    packets = ft.parse_pcap(pcap(frames, **kwargs))
    assert len(packets) == 1, packets
    return packets[0]


def fresh_dir():
    return tempfile.mkdtemp(prefix="f5tcpdump_test_")


# ---------------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------------

def test_validation():
    print("== validacao / safety ==")
    ok = ft.validate_request({"server_port": 443, "node_port": "15000",
                              "host": "10.100.2.1", "count": 50, "timeout_sec": 10})
    assert ok == {"interface": "any", "server_port": 443, "node_port": 15000,
                  "host": "10.100.2.1", "count": 50, "timeout_sec": 10,
                  "vs_addr": None, "client_addr": None, "node_addr": None,
                  "detalhes": False, "stan": None}, ok
    assert ft.validate_request({"vs_addr": "10.100.1.10", "detalhes": True})["vs_addr"] == \
        "10.100.1.10"
    # a interface de captura e fixa e interna: o cliente nao a escolhe (nem ve)
    assert ok["interface"] == ft.CAPTURE_INTERFACE == "any"
    for forbidden in ({"interface": "any"}, {"interface": "0.0"}, {"verbose": True},
                      {"verbose": False}):
        try:
            ft.validate_request(forbidden)
            raise AssertionError("parametro removido deveria ser recusado: %r" % forbidden)
        except ft.RequestError as exc:
            assert exc.status == "invalid", exc.status
    assert ft.validate_request({"host": "2001:db8::1"})["host"] == "2001:db8::1"
    defaults = ft.validate_request({})
    assert defaults["count"] == ft.DEFAULT_COUNT and defaults["interface"] == "any"
    # teto de captura: 180 s (o padrao do pedido continua curto)
    assert ft.MAX_TIMEOUT_SEC == 180 and defaults["timeout_sec"] == ft.DEFAULT_TIMEOUT_SEC
    assert ft.validate_request({"timeout_sec": 180})["timeout_sec"] == 180

    invalid = {
        "chave desconhecida": {"nodeport": 1},
        "interface com opcao": {"interface": "-w"},
        "interface com ;": {"interface": "any;reboot"},
        "interface com espaco": {"interface": "a b"},
        "host nome DNS": {"host": "evil.example.com"},
        "host opcao": {"host": "-w"},
        "host IPv4 incompleto": {"host": "10.1.1"},
        "host com filtro": {"host": "10.1.1.1 or port 1222"},
        "porta 0": {"node_port": 0},
        "porta 70000": {"node_port": 70000},
        "porta texto": {"node_port": "ssh"},
        "porta bool": {"node_port": True},
        "porta float": {"node_port": 15000.0},
        "count 0": {"count": 0},
        "count acima": {"count": ft.MAX_COUNT + 1},
        "timeout 0": {"timeout_sec": 0},
        "timeout acima": {"timeout_sec": ft.MAX_TIMEOUT_SEC + 1},
        "verbose texto": {"verbose": "sim"},
        "verbose numero": {"verbose": 1},
        "vs_addr DNS": {"vs_addr": "vs.example.com"},
        "vs_addr com filtro": {"vs_addr": "10.1.1.1 or port 1222"},
        "node_addr DNS": {"node_port": 15000, "node_addr": "node.example.com"},
        "client_addr com filtro": {"server_port": 17000, "client_addr": "1.1.1.1 or port 22"},
        "client_addr sem server_port": {"client_addr": "192.168.0.9"},
        "node_addr sem node_port": {"node_addr": "192.168.0.9"},
        "detalhes texto": {"detalhes": "sim"},
        "stan letras": {"stan": "12a"},
        "stan vazio": {"stan": ""},
        "stan bool": {"stan": True},
        "stan longo": {"stan": "1234567890123"},
        "stan com filtro": {"stan": "1 or port 1222"},
    }
    assert ft.validate_request({"stan": 123456, "detalhes": True})["stan"] == "123456"
    assert ft.validate_request({"stan": " 000123 "})["stan"] == "000123"
    for label, request in invalid.items():
        try:
            ft.validate_request(request)
            raise AssertionError("deveria recusar: " + label)
        except ft.RequestError as exc:
            assert exc.status == "invalid", (label, exc.status)

    for form in (1222, "1222", " 1222 ", "01222"):
        for key in ("server_port", "node_port"):
            try:
                ft.validate_request({key: form})
                raise AssertionError("deveria bloquear %r em %s" % (form, key))
            except ft.RequestError as exc:
                assert exc.status == "blocked" and exc.message == BLOCKED_MESSAGE, exc.message
    print("OK: %d pedidos invalidos recusados; 1222 bloqueada em 8 formas" % len(invalid))


def test_build_argv():
    print("== argv do tcpdump (sem shell) ==")
    base = ft.validate_request({"node_port": 15000, "host": "10.100.2.1", "count": 20,
                                "timeout_sec": 5})
    argv = ft.build_argv(base, "/usr/sbin/tcpdump")
    assert argv == ["/usr/sbin/tcpdump", "-nn", "-U", "-s", "512", "-c", "20", "-i", "any",
                    "-w", "-", "--", "port", "15000", "and", "host", "10.100.2.1"], argv
    both = ft.validate_request({"server_port": 443, "node_port": 15000})
    assert ft.build_argv(both, "t")[-7:] == ["(", "port", "443", "or", "port", "15000", ")"]
    # IP E porta por perna: duas VS no mesmo IP (:17000 e :15000) nao se misturam
    legs = ft.validate_request({"server_port": 17000, "vs_addr": "10.100.1.10",
                                "client_addr": "192.168.0.50", "node_port": 15000,
                                "node_addr": "192.168.0.9"})
    tail = ft.build_argv(legs, "t")
    assert tail[tail.index("--") + 1:] == [
        "(", "(", "port", "17000", "and", "host", "10.100.1.10", "and", "host",
        "192.168.0.50", ")", "or", "(", "port", "15000", "and", "host", "192.168.0.9", ")",
        ")"], tail
    vs_only = ft.build_argv(ft.validate_request({"server_port": 17000,
                                                 "vs_addr": "10.100.1.10"}), "t")
    assert vs_only[vs_only.index("--") + 1:] == ["port", "17000", "and", "host",
                                                 "10.100.1.10"], vs_only
    same = ft.build_argv(ft.validate_request({"server_port": 15000, "node_port": 15000}), "t")
    assert same[same.index("--") + 1:] == ["port", "15000"], same
    bare = ft.build_argv(ft.validate_request({}), "t")
    assert "--" not in bare and bare[-2:] == ["-w", "-"], bare
    assert all(isinstance(token, str) for token in argv)

    # ultima camada: uma porta bloqueada que "escape" da validacao e recusada no argv
    sneaky = ft.validate_request({"node_port": 15000})
    sneaky["server_port"] = 1222
    try:
        ft.build_argv(sneaky, "t")
        raise AssertionError("porta 1222 injetada deveria ser recusada no argv")
    except ft.RequestError as exc:
        assert exc.status == "blocked", exc.status
    print("OK: argv como lista, '--' antes do filtro, 1222 recusada na ultima camada")


def test_pcap_parsing():
    print("== parsing de pcap ==")
    a, b = "10.1.1.5", "10.1.1.10"
    syn = ipv4_packet(a, b, tcp_segment(51000, 443, TCP_SYN))

    # Ethernet + IPv4
    pkt = one([eth(syn)])
    assert pkt["src"] == "10.1.1.5.51000" and pkt["dst"] == "10.1.1.10.443", pkt
    assert pkt["flags"] == "S" and pkt["flags_label"] == "SYN" and pkt["mti"] is None, pkt
    assert pkt["markers_found"] == [], pkt

    # Linux cooked (-i any), SLL e SLL2, big-endian, nanossegundos
    assert one([sll(syn)], linktype=113)["flags_label"] == "SYN"
    assert one([sll2(syn)], linktype=276)["flags_label"] == "SYN"
    assert one([eth(syn)], endian=">")["flags_label"] == "SYN"
    assert one([eth(syn)], magic=0xA1B23C4D)["flags_label"] == "SYN"
    assert one([syn], linktype=101)["flags_label"] == "SYN"
    assert one([eth(syn, vlan=100)])["flags_label"] == "SYN"

    # flags
    for flag, label, raw in ((TCP_SYN_ACK, "SYN-ACK", "S."), (TCP_PSH_ACK, "PSH-ACK", "P."),
                             (TCP_RST_ACK, "RST-ACK", "R."), (0x10, "ACK", "."),
                             (0x04, "RST", "R"), (0x01, "FIN", "F"), (0x11, "FIN-ACK", "F.")):
        p = one([eth(ipv4_packet(a, b, tcp_segment(1, 2, flag)))])
        assert (p["flags"], p["flags_label"]) == (raw, label), (flag, p)

    # ISO 8583 + opcoes TCP (data offset 8) + opcoes IP (IHL 6)
    payload = iso_payload("0800", "301")
    seg = tcp_segment(51000, 443, TCP_PSH_ACK, payload, options=b"\x01\x01\x08\x0a" + b"\x00" * 8)
    iso = one([eth(ipv4_packet(a, b, seg, ihl_options=b"\x01\x01\x01\x00"))])
    assert iso["mti"] == "0800" and iso["bit70"] == "301" and iso["bit70_desc"] == "Echo Test", iso
    assert (iso["bit7"], iso["bit11"], iso["bit32"]) == ("0920140102", "000123", "123456"), iso
    assert (iso["bit37"], iso["bit100"], iso["bit127"]) == ("000000000123", "12345", "123456789")
    assert iso["is_echo_test"] and not iso["is_signon"] and not iso["is_signoff"], iso
    assert iso["markers_found"][0] == "MTI:0800" and "NMIC:301" in iso["markers_found"], iso

    # IPv6
    v6 = ipv6_packet("2001:db8::1", "2001:db8::2", tcp_segment(40000, 443, TCP_PSH_ACK, payload))
    p6 = one([eth(v6, ethertype=0x86DD)])
    assert p6["src"] == "2001:db8::1.40000" and p6["mti"] == "0800", p6

    # nao-ISO (SSH) nao gera MTI/bits/marcadores; padding de camada 2 e descartado
    ssh = ipv4_packet(a, b, tcp_segment(40000, 22, TCP_PSH_ACK, b"SSH-2.0-OpenSSH_7.4\r\n"))
    p_ssh = one([eth(ssh) + b"\x00" * 6])
    assert p_ssh["mti"] is None and p_ssh["markers_found"] == [], p_ssh
    assert p_ssh["payload_ascii_preview"] == "SSH-2.0-OpenSSH_7.4..", p_ssh["payload_ascii_preview"]

    # fallback legado: payload curto com o token 0800
    legacy = ipv4_packet(a, b, tcp_segment(40001, 9000, TCP_PSH_ACK, b"xx0800yy"))
    assert one([eth(legacy)])["markers_found"] == ["request_0800(ascii)"]

    # fragmento nao-inicial / UDP / ARP / lixo
    frag = ipv4_packet(a, b, tcp_segment(1, 2, TCP_PSH_ACK, payload), frag=185)
    pf = one([eth(frag)])
    assert pf["mti"] is None and pf["flags_label"] == "UNKNOWN", pf
    udp = one([eth(ipv4_packet(a, b, b"\x00" * 16, proto=17))])
    assert udp["flags_label"] == "UNKNOWN" and udp["src"] == "10.1.1.5", udp
    assert ft.parse_pcap(pcap([eth(b"\x00" * 28, ethertype=0x0806)])) == []
    assert ft.parse_pcap(b"") == [] and ft.parse_pcap(b"not a pcap at all, nope" * 3) == []

    # registro final truncado: o que veio antes ainda e devolvido
    good = pcap([eth(syn), eth(syn)])
    assert len(ft.parse_pcap(good)) == 2
    assert len(ft.parse_pcap(good[:-10])) == 1
    print("OK: Ethernet/SLL/SLL2/VLAN/raw, BE/ns, IPv6, opcoes IP/TCP, ISO, fallback, lixo")


def test_summary():
    print("== summarize ==")
    a, b = "10.1.1.5", "10.1.1.10"
    frames = [
        eth(ipv4_packet(a, b, tcp_segment(1, 443, TCP_SYN))),
        eth(ipv4_packet(b, a, tcp_segment(443, 1, TCP_SYN_ACK))),
        eth(ipv4_packet(a, b, tcp_segment(1, 443, TCP_PSH_ACK, iso_payload("0800", "301")))),
        eth(ipv4_packet(b, a, tcp_segment(443, 1, TCP_PSH_ACK, iso_payload("0810", "301")))),
        eth(ipv4_packet(a, b, tcp_segment(1, 443, TCP_PSH_ACK, iso_payload("0800", "001")))),
        eth(ipv4_packet(b, a, tcp_segment(443, 1, TCP_RST_ACK))),
    ]
    summary = ft.summarize(ft.parse_pcap(pcap(frames)))
    assert summary["total_packets"] == 6 and summary["psh_ack"] == 3, summary
    assert summary["mti_counts"] == {"0800": 2, "0810": 1}, summary
    assert summary["network_codes"] == {"301": 2, "001": 1}, summary
    assert (summary["echo_tests"], summary["signon"], summary["signoff"]) == (2, 1, 0), summary
    assert summary["request_0800_count"] == 2 and summary["response_0810_count"] == 1, summary
    print("OK:", summary)


def test_parity_with_agent_parser():
    print("== paridade com src/tcpdump_parser.py (parser de texto do agente) ==")
    try:
        from src import _selftest as st
        from src import tcpdump_parser as tp
    except ImportError as exc:
        print("PULADO (rode a partir da raiz do repo com PYTHONPATH=.): %s" % exc)
        return

    a, b = "10.1.1.5", "10.1.1.10"
    spec = [  # src, dst, sport, dport, flag_txt, flags, payload
        (a, b, 51000, 443, "S", TCP_SYN, b""),
        (b, a, 443, 51000, "S.", TCP_SYN_ACK, b""),
        (a, b, 51000, 443, "P.", TCP_PSH_ACK, iso_payload("0800", "301")),
        (b, a, 443, 51000, "P.", TCP_PSH_ACK, iso_payload("0810", "301")),
        (a, b, 51000, 443, "P.", TCP_PSH_ACK, iso_payload("0800", "001", bit11="000124")),
        (a, b, 40000, 22, "P.", TCP_PSH_ACK, b"SSH-2.0-OpenSSH_7.4\r\n"),
        (a, b, 40001, 9000, "P.", TCP_PSH_ACK, b"xx0800yy"),
        (b, a, 443, 51000, "R.", TCP_RST_ACK, b""),
    ]
    text, frames = "", []
    for index, (src, dst, sport, dport, flag_txt, flags, payload) in enumerate(spec):
        text += st._entry("14:01:%02d.000000" % index, src, sport, dst, dport, flag_txt, flags, payload)
        frames.append(eth(st._build_ipv4_tcp_packet(src, dst, sport, dport, flags, payload)))

    agent = tp.parse_tcpdump_output(text)
    onbox = ft.parse_pcap(pcap(frames))
    assert len(agent) == len(onbox) == len(spec), (len(agent), len(onbox))

    keys = ("src", "dst", "flags", "flags_label", "payload_len", "mti", "bit7", "bit11", "bit32", "bit37",
            "bit70", "bit70_desc", "bit100", "bit127", "is_echo_test", "is_signon",
            "is_signoff", "markers_found")
    for index, (left, right) in enumerate(zip(agent, onbox)):
        for key in keys:
            assert left[key] == right[key], (index, key, left[key], right[key])
    assert tp.summarize(agent) == ft.summarize(onbox), (tp.summarize(agent), ft.summarize(onbox))
    print("OK: %d pacotes - todos os campos e o summarize identicos aos do agente" % len(spec))


FAKE_TCPDUMP = """#!/usr/bin/env python3
import json, os, sys, time
sc = json.load(open(os.environ["FAKE_SCENARIO"]))
if sc.get("record"):
    json.dump(sys.argv, open(sc["record"], "w"))
sys.stderr.write(sc.get("stderr", "")); sys.stderr.flush()
data = open(sc["pcap"], "rb").read() if sc.get("pcap") else b""
sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
if sc.get("sleep"):
    time.sleep(sc["sleep"])
sys.exit(sc.get("exit", 0))
"""


def make_fake(workdir):
    path = os.path.join(workdir, "fake_tcpdump")
    with open(path, "w") as handle:
        handle.write(FAKE_TCPDUMP)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


def set_scenario(workdir, **scenario):
    path = os.path.join(workdir, "scenario.json")
    with open(path, "w") as handle:
        json.dump(scenario, handle)
    os.environ["FAKE_SCENARIO"] = path
    return scenario


def fake_proc_dir(workdir, comms):
    proc = os.path.join(workdir, "proc")
    os.makedirs(proc)
    for index, comm in enumerate(comms):
        os.makedirs(os.path.join(proc, str(100 + index)))
        with open(os.path.join(proc, str(100 + index), "comm"), "w") as handle:
            handle.write(comm + "\n")
    os.makedirs(os.path.join(proc, "999"))        # pid sem comm (terminou no meio)
    os.makedirs(os.path.join(proc, "self_dir"))   # nao numerico
    return proc


def test_run_end_to_end():
    print("== run() ponta a ponta com tcpdump falso ==")
    work = fresh_dir()
    fake = make_fake(work)
    lock_dir = os.path.join(work, "locks")
    proc = fake_proc_dir(work, ["bash", "sshd"])
    record = os.path.join(work, "argv.json")

    a, b = "10.100.1.20", "10.100.2.1"
    frames = [eth(ipv4_packet(a, b, tcp_segment(2264, 15000, TCP_SYN))),
              eth(ipv4_packet(a, b, tcp_segment(3264, 15000, TCP_RST_ACK))),
              eth(ipv4_packet(a, b, tcp_segment(2265, 15000, TCP_PSH_ACK, iso_payload("0800", "301"))))]
    pcap_path = os.path.join(work, "cap.pcap")
    with open(pcap_path, "wb") as handle:
        handle.write(pcap(frames))

    common = dict(tcpdump_bin=fake, lock_dir=lock_dir, proc_dir=proc, audit=False)

    # 1) caminho feliz
    set_scenario(work, pcap=pcap_path, record=record,
                 stderr="tcpdump: listening on any\n3 packets captured\n")
    t0 = time.time()
    result = ft.run({"node_port": 15000, "host": b, "count": 10, "timeout_sec": 5}, **common)
    assert result["status"] == "ok", result
    assert result["janela"] == {"max_s": 5, "encerrou_por": "limite de pacotes"}, result
    assert result["trafego"]["pacotes"] == 3 and result["trafego"]["syn"] == 1, result
    assert result["trafego"]["rst"] == 1 and result["trafego"]["mensagens_iso"] == 1, result
    assert result["avisos"] == [] or all("Não foi possível separar" in a
                                         for a in result["avisos"]), result
    for hidden in ("command", "exit_status", "timed_out", "stderr", "summary", "packets",
                   "warnings"):
        assert hidden not in result, "nao pode expor %r" % hidden
    with open(record) as handle:
        argv = json.load(handle)
    assert argv[1:] == ["-nn", "-U", "-s", "512", "-c", "10", "-i", "any", "-w", "-", "--",
                        "port", "15000", "and", "host", b], argv
    assert time.time() - t0 < 5

    # 2) 1222 pedida -> bloqueada e o tcpdump NUNCA e executado
    os.remove(record)
    blocked = ft.run({"node_port": 1222}, **common)
    assert blocked == {"status": "blocked", "message": BLOCKED_MESSAGE}, blocked
    assert not os.path.exists(record), "tcpdump nao pode ser executado para a 1222"

    # 3) estouro de prazo -> exit 124, pacotes ja emitidos continuam aproveitados
    set_scenario(work, pcap=pcap_path, sleep=30)
    t0 = time.time()
    slow = ft.run({"node_port": 15000, "timeout_sec": 1}, **common)
    elapsed = time.time() - t0
    assert slow["status"] == "ok" and slow["janela"]["encerrou_por"] == "prazo", slow
    assert slow["trafego"]["pacotes"] == 3 and elapsed < 8, (slow["trafego"], elapsed)

    # 4) aviso do TMOS no stderr vira warning explicito
    set_scenario(work, pcap=pcap_path,
                 stderr="WARNING - The recommended number of tmm tcpdump instances (2) "
                        "has been exceeded (2).\n")
    warned = ft.run({"node_port": 15000}, **common)
    assert warned["status"] == "ok" and ft.MSG_CONCURRENT in warned["avisos"], warned
    assert "tmm" not in json.dumps(warned) and "tcpdump" not in json.dumps(warned), warned

    # 4b) falha do proprio tcpdump (interface inexistente, filtro...) -> error, nunca "ok"
    set_scenario(work, stderr="tcpdump: bogus0: No such device exists\n", exit=1)
    broken = ft.run({"node_port": 15000}, **common)
    assert broken == {"status": "error", "message": ft.MSG_CAPTURE_FAILED}, broken
    assert "bogus0" not in json.dumps(broken) and "No such device" not in json.dumps(broken)

    # 5) concorrencia: 1 rodando -> ok; 2 rodando -> busy, sem executar
    set_scenario(work, pcap=pcap_path, record=record)
    if os.path.exists(record):
        os.remove(record)
    one_running = fake_proc_dir(fresh_dir(), ["tcpdump", "bash"])
    assert ft.run({"node_port": 15000}, **dict(common, proc_dir=one_running))["status"] == "ok"
    os.remove(record)
    two_running = fake_proc_dir(fresh_dir(), ["tcpdump", "tcpdump", "sshd"])
    assert ft.count_running_tcpdump(two_running) == 2
    busy = ft.run({"node_port": 15000}, **dict(common, proc_dir=two_running))
    assert busy == {"status": "busy", "message": ft.MSG_BUSY, "retry_after_minutes": 5}, busy
    assert "5 minutos" in busy["message"] and "tcpdump" not in busy["message"], busy["message"]
    assert socket.gethostname() not in busy["message"], busy["message"]
    assert not os.path.exists(record), "nada pode ser iniciado quando esta no teto"

    # 6) guarda atomica ocupada por outra chamada -> busy, sem esperar para sempre
    import fcntl
    os.makedirs(lock_dir, exist_ok=True)
    holder = os.open(os.path.join(lock_dir, "guard.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        t0 = time.time()
        contended = ft.run({"node_port": 15000}, **dict(common, guard_wait_sec=0.3))
        assert contended["status"] == "busy", contended
        assert time.time() - t0 < 3
    finally:
        os.close(holder)

    # 7) tcpdump ausente -> erro claro (sem excecao)
    missing = ft.run({"node_port": 15000}, tcpdump_bin=os.path.join(work, "nao_existe"),
                     lock_dir=lock_dir, proc_dir=proc, audit=False)
    assert missing == {"status": "error", "message": ft.MSG_UNAVAILABLE}, missing
    assert "/usr/sbin" not in json.dumps(missing), missing
    print("OK: feliz / 1222 / timeout 124 / warning TMM / teto / guarda / binario ausente "
          "(todos sem comando/stderr/caminhos)")


def _vs_scenario_frames():
    """Cliente->VS 10.100.1.10:17000 (SNAT 10.100.1.20 -> node 192.168.0.9:15000) com
    DUAS transacoes (0800 e 0100, ambas respondidas) + 3 sondas do monitor do pool."""
    client, vs, snat, node = "192.168.0.9", "10.100.1.10", "10.100.1.20", "192.168.0.9"
    ACK, RST = 0x10, 0x04
    frames = []

    def add(src, dst, sport, dport, flags, payload=b""):
        frames.append(eth(ipv4_packet(src, dst, tcp_segment(sport, dport, flags, payload))))

    # handshake nas duas pernas
    add(client, vs, 50000, 17000, TCP_SYN)
    add(snat, node, 50000, 15000, TCP_SYN)
    add(node, snat, 15000, 50000, TCP_SYN_ACK)
    add(vs, client, 17000, 50000, TCP_SYN_ACK)
    add(client, vs, 50000, 17000, ACK)
    add(snat, node, 50000, 15000, ACK)
    # transacao 0800 (STAN 111111) e 0100 (STAN 222222), nos 4 saltos
    for req, resp, stan in (("0800", "0810", "111111"), ("0100", "0110", "222222")):
        nmic = "301" if req == "0800" else "000"
        add(client, vs, 50000, 17000, TCP_PSH_ACK, iso_payload(req, nmic, bit11=stan))
        add(snat, node, 50000, 15000, TCP_PSH_ACK, iso_payload(req, nmic, bit11=stan))
        add(node, snat, 15000, 50000, TCP_PSH_ACK, iso_payload(resp, nmic, bit11=stan))
        add(vs, client, 17000, 50000, TCP_PSH_ACK, iso_payload(resp, nmic, bit11=stan))
    # sondas do monitor (tcp_half_open): SYN / SYN-ACK / RST, portas efemeras diferentes
    for port in (4321, 4322, 4323):
        add(snat, node, port, 15000, TCP_SYN)
        add(node, snat, 15000, port, TCP_SYN_ACK)
        add(snat, node, port, 15000, RST)
    return frames


def _shared_vs_frames():
    """Cenario da captura real: OUTRA VS no MESMO IP (10.100.1.10:15000) e com o MESMO
    member (192.168.0.9:15000), com 1 transacao 0100 (STAN 333333)."""
    client, vs, snat, node = "192.168.0.9", "10.100.1.10", "10.100.1.20", "192.168.0.9"
    frames = []

    def add(src, dst, sport, dport, flags, payload=b""):
        frames.append(eth(ipv4_packet(src, dst, tcp_segment(sport, dport, flags, payload))))

    add(client, vs, 50100, 15000, TCP_PSH_ACK, iso_payload("0100", "000", bit11="333333"))
    add(snat, node, 50100, 15000, TCP_PSH_ACK, iso_payload("0100", "000", bit11="333333"))
    add(node, snat, 15000, 50100, TCP_PSH_ACK, iso_payload("0110", "000", bit11="333333"))
    add(vs, client, 15000, 50100, TCP_PSH_ACK, iso_payload("0110", "000", bit11="333333"))
    return frames


def test_simplified_output():
    print("== resposta simples: so o trafego da VS, sem sondas do monitor ==")
    work = fresh_dir()
    fake = make_fake(work)
    proc = fake_proc_dir(work, ["bash"])
    pcap_path = os.path.join(work, "cap.pcap")
    with open(pcap_path, "wb") as handle:
        handle.write(pcap(_vs_scenario_frames()))
    set_scenario(work, pcap=pcap_path)
    common = dict(tcpdump_bin=fake, lock_dir=os.path.join(work, "locks"), proc_dir=proc,
                  audit=False)
    request = {"server_port": 17000, "node_port": 15000, "host": "192.168.0.9",
               "vs_addr": "10.100.1.10", "timeout_sec": 5}

    simple = ft.run(request, **common)
    assert simple["status"] == "ok", simple
    for noisy in ("command", "packets", "stderr", "summary", "exit_status", "timed_out"):
        assert noisy not in simple, "resposta simples nao deve trazer %r" % noisy
    assert sorted(simple) == ["avisos", "janela", "membros", "resultado", "status",
                              "trafego", "transacoes"], sorted(simple)
    # o membro do pool respondeu ao SYN (sondas do monitor + conexao da VS)
    assert simple["membros"] == [{"membro": "192.168.0.9:15000", "situacao": "responde ao SYN",
                                  "syn": simple["membros"][0]["syn"], "syn_ack": simple["membros"][0]["syn_ack"],
                                  "rst": 0}], simple["membros"]
    assert simple["membros"][0]["syn"] >= 4 and simple["membros"][0]["syn_ack"] >= 4
    tx = simple["transacoes"]
    assert [(t["stan"], t["pedido"], t["resposta"], t["respondida"]) for t in tx] == [
        ("111111", "0800", "0810", True), ("222222", "0100", "0110", True)], tx
    assert tx[0]["tipo"] == "Echo Test" and tx[0]["origem"] == "192.168.0.9", tx[0]
    assert tx[1]["tipo"] == "Pedido de autorização", tx[1]
    assert simple["resultado"] == ("2 transação(ões) ISO 8583 na VS (1×0100, 1×0800): "
                                   "2 respondida(s), 0 sem resposta."), simple["resultado"]
    # sondas (9 pacotes) fora; 1 conexao da VS em 2 pernas = 2 fluxos, 14 pacotes
    assert simple["trafego"]["conexoes"] == 2 and simple["trafego"]["pacotes"] == 14, simple["trafego"]
    assert simple["trafego"]["syn"] == 2 and simple["trafego"]["syn_ack"] == 2, simple["trafego"]
    assert simple["trafego"]["rst"] == 0 and simple["trafego"]["mensagens_iso"] == 8
    assert simple["janela"] == {"max_s": 5, "encerrou_por": "limite de pacotes"}, simple["janela"]
    # o que foi descartado NAO e reportado (nem sondas, nem outras VS)
    assert simple["avisos"] == [], simple["avisos"]

    # sem como separar a VS (so a porta do node): nada e descartado, e avisa
    broad = ft.run({"node_port": 15000, "host": "192.168.0.9"}, **common)
    assert broad["trafego"]["pacotes"] == 23, broad["trafego"]
    assert any("Não foi possível separar" in a for a in broad["avisos"]), broad["avisos"]

    # portas de VS e node diferentes bastam para separar (sem vs_addr)
    by_ports = ft.run({"server_port": 17000, "node_port": 15000}, **common)
    assert by_ports["trafego"]["pacotes"] == 14 and len(by_ports["transacoes"]) == 2, by_ports

    # VS sem nenhuma resposta do node: pedido sem resposta, e SYN sem SYN-ACK
    only_req = [eth(ipv4_packet("192.168.0.9", "10.100.1.10",
                                tcp_segment(50001, 17000, TCP_PSH_ACK,
                                            iso_payload("0800", "301", bit11="333333"))))]
    unanswered = ft.simplified_view(ft.parse_pcap(pcap(only_req)), 17000, 15000, "10.100.1.10")[0]
    assert unanswered["transacoes"][0]["respondida"] is False, unanswered
    assert "1 sem resposta" in unanswered["resultado"] or "0 respondida(s), 1 sem" in \
        unanswered["resultado"], unanswered["resultado"]
    syn_only = [eth(ipv4_packet("192.168.0.9", "10.100.1.10", tcp_segment(50002, 17000, TCP_SYN)))]
    view = ft.simplified_view(ft.parse_pcap(pcap(syn_only)), 17000, 15000, "10.100.1.10")[0]
    assert "SYN sem nenhum SYN-ACK" in view["resultado"], view["resultado"]

    # detalhes: tabela no padrao pedido + campos ISO, trajeto e RTT por transacao
    det = ft.run(dict(request, detalhes=True), **common)
    assert det["status"] == "ok" and "tabela_markdown" in det, det
    table = det["tabela_markdown"].splitlines()
    assert table[0] == "**Transações (VS 10.100.1.10:17000)** — 2 respondida(s) de 2", table[0]
    assert table[2] == "| # | Tipo | STAN | Enviada | Resposta | RTT | Rastreio |", table[2]
    assert table[3] == "|---|---|---|---|---|---|---|", table[3]
    row = [c.strip() for c in table[4].strip("|").split("|")]
    assert row[0:3] == ["1", "0800", "111111"] and row[4] == "0810 / 111111", row
    assert row[6] == "4/4" and row[5].endswith(" ms"), row
    assert table[5].startswith("| 2 | 0100 | 222222 | ") and "0110 / 222222" in table[5], table[5]
    assert any(l.startswith("- **Respondidas:** 2 de 2 (1×0100→0110, 1×0800→0810)") for l in table)
    assert any(l.startswith("- **RTT:** mín ") for l in table)
    assert any(l.startswith("- **Rastreio:** 2 de 2 com os 4 saltos") for l in table)
    first = det["transacoes"][0]
    assert first["campos"]["bit11"] == "111111" and first["campos"]["bit70"] == "301", first
    assert first["saltos"] == 4 and len(first["trajeto"]) == 4, first
    assert [h["mti"] for h in first["trajeto"]] == ["0800", "0800", "0810", "0810"], first
    assert (first["trajeto"][0]["de"], first["trajeto"][0]["para"]) == \
        ("192.168.0.9.50000", "10.100.1.10.17000"), first["trajeto"][0]
    assert first["rtt_ms"] is not None and first["rtt_ms"] >= 0, first
    for leak in ("payload", "packets", "command"):
        assert leak not in json.dumps(det), leak
    # a resposta simples (padrao) continua SEM esses campos
    assert "campos" not in simple["transacoes"][0] and "tabela_markdown" not in simple

    # filtro por STAN
    one_tx = ft.run(dict(request, detalhes=True, stan="222222"), **common)
    assert [t["stan"] for t in one_tx["transacoes"]] == ["222222"], one_tx["transacoes"]
    assert one_tx["tabela_markdown"].splitlines()[0].endswith("1 respondida(s) de 1")
    none_tx = ft.run(dict(request, detalhes=True, stan="999999"), **common)
    assert none_tx["transacoes"] == [] and "tabela_markdown" not in none_tx, none_tx
    assert none_tx["resultado"] == "Nenhuma transação com STAN 999999 na janela capturada."

    # outra VS no mesmo IP e com o mesmo member: suas 2 pernas ficam de fora (com aviso)
    mixed = ft.parse_pcap(pcap(_vs_scenario_frames() + _shared_vs_frames()))
    for args in ((17000, 15000, "10.100.1.10"), (17000, 15000, None)):
        view, notes = ft.simplified_view(mixed, *args)
        assert [t["stan"] for t in view["transacoes"]] == ["111111", "222222"], (args, view)
        assert view["trafego"]["pacotes"] == 14 and view["trafego"]["conexoes"] == 2, view
        assert notes == [], notes      # sem mencionar a outra VS
    # a outra VS, pedida pelo seu proprio IP:porta, sai sozinha
    other = ft.simplified_view(mixed, 15000, 15000, "10.100.1.10")[0]
    assert [t["stan"] for t in other["transacoes"]] == ["333333"], other

    # nada da VS na janela
    probes_only = [f for f in _vs_scenario_frames()[-9:]]
    empty = ft.simplified_view(ft.parse_pcap(pcap(probes_only)), 17000, 15000, "10.100.1.10")
    assert empty[0]["resultado"] == "Nenhum tráfego da VS na janela capturada.", empty
    assert empty[0]["trafego"]["pacotes"] == 0 and empty[1] == [], empty
    print("OK: sem command/packets/stderr; 2 transacoes por STAN; sondas e outras VS fora, "
          "sem citar nenhuma")


def _two_vs_same_stan_frames(gap):
    """Captura da app1 (10.100.1.10:15000) com a conexao dela E a perna de node de OUTRA VS
    (10.100.1.10:17000) que usa o MESMO node e o MESMO STAN, `gap` s depois."""
    client, vs, snat, node = "192.168.0.9", "10.100.1.10", "10.100.1.20", "192.168.0.9"
    frames, stamps = [], []

    def add(at, src, dst, sport, dport, flags, payload):
        frames.append(eth(ipv4_packet(src, dst, tcp_segment(sport, dport, flags, payload))))
        stamps.append(1700000100.0 + at)

    req, resp = iso_payload("0800", "301", bit11="000001"), iso_payload("0810", "301", bit11="000001")
    # app1 (a VS pedida)
    add(0.000, client, vs, 50200, 15000, TCP_PSH_ACK, req)
    add(0.001, snat, node, 50200, 15000, TCP_PSH_ACK, req)
    add(0.030, node, snat, 15000, 50200, TCP_PSH_ACK, resp)
    add(0.031, vs, client, 15000, 50200, TCP_PSH_ACK, resp)
    # outra VS, mesmo node, MESMO STAN (contador por terminal repete valores)
    add(gap, snat, node, 50300, 15000, TCP_PSH_ACK, req)
    add(gap + 0.030, node, snat, 15000, 50300, TCP_PSH_ACK, resp)
    return frames, stamps


def test_same_stan_other_vs_and_no_internal_details():
    print("== STAN repetido em outra VS no mesmo node + nada interno nas respostas ==")
    for gap, expected_packets, expected_tx in ((30.0, 4, 1), (5.0, 4, 1)):
        frames, stamps = _two_vs_same_stan_frames(gap)
        packets = ft.parse_pcap(pcap(frames, stamps=stamps))
        view, notes = ft.simplified_view(packets, 15000, 15000, "10.100.1.10", detalhes=True)
        assert view["trafego"]["pacotes"] == expected_packets, (gap, view["trafego"])
        assert len(view["transacoes"]) == expected_tx, (gap, view["transacoes"])
        assert view["transacoes"][0]["saltos"] == 4, (gap, view["transacoes"][0])
        assert notes == [], notes
        for citing in ("outra", "50300", "17000"):
            assert citing not in json.dumps(view, ensure_ascii=False), (gap, citing)

    # respostas de todos os caminhos (ok/busy/blocked/invalid/error/inesperado): sem nada
    # que revele metodo, comando, caminho, host ou texto do equipamento
    work = fresh_dir()
    fake = make_fake(work)
    proc = fake_proc_dir(work, ["bash"])
    pcap_path = os.path.join(work, "cap.pcap")
    with open(pcap_path, "wb") as handle:
        handle.write(pcap(_vs_scenario_frames()))
    common = dict(tcpdump_bin=fake, lock_dir=os.path.join(work, "locks"), proc_dir=proc,
                  audit=False)
    responses = []
    set_scenario(work, pcap=pcap_path, stderr="WARNING - tmm tcpdump instances (2) exceeded\n")
    responses.append(ft.run({"server_port": 17000, "node_port": 15000, "vs_addr": "10.100.1.10",
                             "detalhes": True}, **common))
    responses.append(ft.run({"server_port": 1222}, **common))
    responses.append(ft.run({"host": "nao-e-ip"}, **common))
    responses.append(ft.run({"interface": "eth0"}, **common))
    responses.append(ft.run({"node_port": 15000},
                            **dict(common, proc_dir=fake_proc_dir(fresh_dir(),
                                                                  ["tcpdump", "tcpdump"]))))
    set_scenario(work, stderr="tcpdump: /etc/shadow: Permission denied secret-token\n", exit=1)
    responses.append(ft.run({"node_port": 15000}, **common))
    responses.append(ft.run({"node_port": 15000}, tcpdump_bin="/nao/existe/tcpdump",
                            lock_dir=common["lock_dir"], proc_dir=proc, audit=False))
    original = ft._run

    def explode(*args, **kwargs):
        raise RuntimeError("falha em /etc/shadow com token secret-token")

    ft._run = explode
    try:
        responses.append(ft.run({"node_port": 15000}, **common))
    finally:
        ft._run = original

    forbidden = ("tcpdump", "sudo", "restnoded", "stderr", "command", "exit_status", "/usr/",
                 "/etc/", "/nao/", "perl", "bash", "traceback", "runtimeerror", "secret",
                 "tmm", "subprocess", "popen", "flock", "/proc", "syslog",
                 socket.gethostname().lower())
    for response in responses:
        text = json.dumps(response, ensure_ascii=False).lower()
        for term in forbidden:
            if term:
                assert term not in text, "vazou %r em %s" % (term, text[:300])
    # valores do cliente aparecem sem o prefixo u"..." do repr() do Python 2
    for response in responses:
        assert "u'" not in response["message"] if "message" in response else True, response
    assert ft.run({"interface": "x"}, audit=False)["message"] == \
        "Parâmetro(s) não suportado(s): \"interface\"", ft.run({"interface": "x"}, audit=False)
    statuses = [r["status"] for r in responses]
    assert statuses == ["ok", "blocked", "invalid", "invalid", "busy", "error", "error", "error"], \
        statuses
    assert responses[-1] == {"status": "error", "message": ft.MSG_INTERNAL}, responses[-1]
    print("OK: STAN repetido noutra VS nao entra (janela de tempo); 8 respostas sem metodo/"
          "comando/caminho/host")


def _member_frames():
    """Tres membros do pool: um que NAO responde ao SYN (so tentativas + RST do proprio
    F5), um que responde (SYN-ACK) e um que RECUSA (RST vindo dele)."""
    snat = "10.100.1.20"
    frames = []

    def add(src, dst, sport, dport, flags):
        frames.append(eth(ipv4_packet(src, dst, tcp_segment(sport, dport, flags))))

    for port in (4001, 4002, 4003):                       # 10.100.2.1: mudo
        add(snat, "10.100.2.1", port, 15000, TCP_SYN)
        add(snat, "10.100.2.1", port, 15000, TCP_RST_ACK)  # o F5 desiste (nao e do membro)
    for port in (4101, 4102):                              # 192.168.0.9: responde
        add(snat, "192.168.0.9", port, 15000, TCP_SYN)
        add("192.168.0.9", snat, 15000, port, TCP_SYN_ACK)
        add(snat, "192.168.0.9", port, 15000, 0x04)
    add(snat, "10.100.3.1", 4201, 15000, TCP_SYN)          # 10.100.3.1: recusa
    add("10.100.3.1", snat, 15000, 4201, TCP_RST_ACK)
    return frames


def test_member_health():
    print("== analise por membro: node sem SYN+ACK continua sendo informado ==")
    packets = ft.parse_pcap(pcap(_member_frames()))
    health = ft.member_health(packets, [("10.100.2.1", 15000), ("192.168.0.9", 15000),
                                        ("10.100.3.1", 15000), ("10.100.9.9", 15000)])
    assert [(h["membro"], h["situacao"], h["syn"], h["syn_ack"], h["rst"]) for h in health] == [
        ("10.100.2.1:15000", "não responde ao SYN (sem SYN-ACK)", 3, 0, 0),
        ("192.168.0.9:15000", "responde ao SYN", 2, 2, 0),
        ("10.100.3.1:15000", "recusa a conexão (RST)", 1, 0, 1),
        ("10.100.9.9:15000", "sem tentativas de abertura na janela", 0, 0, 0)], health

    # ponta a ponta: capturando o "pool" de uma VS sem nenhum trafego de cliente, o veredito
    # diz QUAL membro nao responde - e nao lista as sondas nem cita outras VS
    work = fresh_dir()
    fake = make_fake(work)
    proc = fake_proc_dir(work, ["bash"])
    pcap_path = os.path.join(work, "cap.pcap")
    with open(pcap_path, "wb") as handle:
        handle.write(pcap(_member_frames()))
    set_scenario(work, pcap=pcap_path)
    common = dict(tcpdump_bin=fake, lock_dir=os.path.join(work, "locks"), proc_dir=proc,
                  audit=False)
    out = ft.run({"server_port": 16000, "node_port": 15000, "vs_addr": "10.100.1.10",
                  "node_addr": "10.100.2.1"}, **common)
    assert out["status"] == "ok", out
    assert out["resultado"] == ("Nenhum tráfego da VS na janela capturada. Membro "
                                "10.100.2.1:15000 não responde ao SYN (sem SYN-ACK) "
                                "(3 SYN, 0 SYN-ACK)."), out["resultado"]
    assert out["membros"][0]["situacao"].startswith("não responde"), out["membros"]
    assert out["trafego"]["pacotes"] == 0 and out["avisos"] == [], out
    for citing in ("sonda", "monitor", "outra", "10.100.1.20"):
        assert citing not in json.dumps(out, ensure_ascii=False), citing
    # membro que responde -> frase positiva so quando nao ha trafego da VS
    ok = ft.run({"server_port": 16000, "node_port": 15000, "vs_addr": "10.100.1.10",
                 "node_addr": "192.168.0.9"}, **common)
    assert ok["resultado"] == ("Nenhum tráfego da VS na janela capturada. "
                               "Os membros do pool responderam ao SYN."), ok["resultado"]
    print("OK: mudo -> \"não responde ao SYN\"; responde; recusa (RST); sem tentativas")


def test_simplified_parity_with_agent():
    print("== paridade da visao simples com src/tcpdump_parser.py ==")
    try:
        from src import tcpdump_parser as tp
    except ImportError as exc:
        print("PULADO (rode a partir da raiz do repo com PYTHONPATH=.): %s" % exc)
        return
    packets = ft.parse_pcap(pcap(_vs_scenario_frames() + _shared_vs_frames()))
    for args in ((17000, 15000, "10.100.1.10"), (17000, 15000, None), (None, 15000, None),
                 (17000, 17000, None), (17000, None, "10.100.1.10")):
        mine = ft.simplified_view(packets, *args)
        theirs = tp.simplified_view(packets, *args)
        assert mine == theirs, (args, mine, theirs)
        assert ft.focus_vs_traffic(packets, *args) == tp.focus_vs_traffic(packets, *args), args
        for extra in ({"detalhes": True}, {"detalhes": True, "stan": "222222"},
                      {"stan": "111111"},
                      {"members": [("192.168.0.9", 15000), ("10.100.2.1", 15000)]},
                      {"members": [(None, 15000)], "detalhes": True}):
            mine = ft.simplified_view(packets, *args, **extra)
            theirs = tp.simplified_view(packets, *args, **extra)
            assert mine == theirs, (args, extra, mine, theirs)
    print("OK: focus_vs_traffic e simplified_view (inclusive detalhes/stan) identicos nos "
          "dois parsers")


def test_cli():
    print("== CLI (JSON no stdin / --request) ==")
    proc = subprocess.Popen([sys.executable, SCRIPT], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate(json.dumps({"server_port": 1222}).encode())
    assert proc.returncode == 0, proc.returncode
    assert json.loads(out.decode("utf-8")) == {"status": "blocked", "message": BLOCKED_MESSAGE}

    done = subprocess.run([sys.executable, SCRIPT, "--request", '{"host": "nao-e-ip"}'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert json.loads(done.stdout.decode("utf-8"))["status"] == "invalid"

    bad = subprocess.run([sys.executable, SCRIPT], input=b"{nao e json",
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert bad.returncode == 2 and json.loads(bad.stdout.decode("utf-8"))["status"] == "invalid"
    print("OK: bloqueio e erros de entrada pela CLI, com JSON em todos os casos")


def test_py27_lint():
    print("== lint de compatibilidade com Python 2.7 (estatico) ==")
    with open(SCRIPT, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())

    banned_nodes = (ast.JoinedStr, ast.AnnAssign, ast.Nonlocal, ast.YieldFrom,
                    ast.AsyncFunctionDef, ast.Await, ast.NamedExpr, ast.MatMult)
    banned_names = {"removeprefix", "removesuffix", "monotonic", "DEVNULL", "JSONDecodeError",
                    "from_bytes", "to_bytes", "dataclass", "exist_ok"}
    allowed_imports = {"__future__", "binascii", "errno", "fcntl", "json", "numbers", "os",
                       "re", "socket", "struct", "subprocess", "sys", "syslog", "threading",
                       "time"}
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, banned_nodes):
            problems.append("%s (linha %d)" % (type(node).__name__, node.lineno))
        if isinstance(node, (ast.FunctionDef, ast.Lambda)):
            args = node.args
            if args.kwonlyargs or args.posonlyargs:
                problems.append("args keyword-only/posonly (linha %d)" % node.lineno)
            if isinstance(node, ast.FunctionDef):
                if node.returns is not None or any(a.annotation for a in args.args):
                    problems.append("anotacao de tipo em %s" % node.name)
        if isinstance(node, ast.Attribute) and node.attr in banned_names:
            problems.append("atributo %s (linha %d)" % (node.attr, node.lineno))
        if isinstance(node, ast.Attribute) and node.attr == "run" and \
                isinstance(node.value, ast.Name) and node.value.id == "subprocess":
            problems.append("subprocess.run (3.5+) linha %d" % node.lineno)
        if isinstance(node, ast.keyword) and node.arg in ("timeout", "input", "capture_output"):
            problems.append("kwarg %s (3.x) linha %d" % (node.arg, node.value.lineno))
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in allowed_imports:
                    problems.append("import %s" % alias.name)
        if isinstance(node, ast.ImportFrom) and node.module not in allowed_imports:
            problems.append("from %s import" % node.module)
    assert not problems, problems
    print("OK: sem f-string/anotacoes/dataclass/typing/subprocess.run; so stdlib permitida")
    print("   (checagem estatica - NAO substitui rodar num interpretador 2.7 real)")


def main():
    test_validation()
    test_build_argv()
    test_pcap_parsing()
    test_summary()
    test_parity_with_agent_parser()
    test_run_end_to_end()
    test_simplified_output()
    test_same_stan_other_vs_and_no_internal_details()
    test_member_health()
    test_simplified_parity_with_agent()
    test_cli()
    test_py27_lint()
    print("\nTODOS OS TESTES ON-BOX PASSARAM")


if __name__ == "__main__":
    main()
