"""Auto-teste rápido (sem F5 real) dos parsers e das camadas de segurança.
Roda dentro do container: docker run --rm --entrypoint python f5-mcp-agent:test -m src._selftest
"""
import shlex
import shutil
import socket
import struct
import subprocess
import time
from types import SimpleNamespace

from . import tcpdump_parser, tmsh_parser, safety, comparator
from .f5_client import CommandResult, F5Client
from .safety import UnsafeInputError
from .inventory import Device, DeviceCredentials

# ---------------------------------------------------------------------------
# Geração de capturas sintéticas no formato do `tcpdump -nn -X`: pacotes IPv4+TCP
# bem-formados (cabeçalhos reais), para exercitar a remoção de cabeçalhos e os
# offsets ISO 8583 do parser de ponta a ponta.
# ---------------------------------------------------------------------------

TCP_SYN, TCP_SYN_ACK, TCP_PSH_ACK, TCP_RST_ACK = 0x02, 0x12, 0x18, 0x14


def _build_ipv4_tcp_packet(src_ip, dst_ip, sport, dport, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, flags, 65535, 0, 0)
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return ip + tcp + payload


def _hexdump_x(packet):
    lines = []
    for off in range(0, len(packet), 16):
        chunk = packet[off:off + 16]
        groups = [chunk[i:i + 2].hex() for i in range(0, len(chunk), 2)]
        hex_part = " ".join(groups).ljust(39)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"\t0x{off:04x}:  {hex_part}  {ascii_part}")
    return "\n".join(lines)


def _entry(time, src, sport, dst, dport, flag_txt, flags, payload=b""):
    pkt = _build_ipv4_tcp_packet(src, dst, sport, dport, flags, payload)
    header = (
        f"{time} IP {src}.{sport} > {dst}.{dport}: "
        f"Flags [{flag_txt}], seq 1000, win 502, length {len(payload)}"
    )
    return header + "\n" + _hexdump_x(pkt) + "\n"


def _iso_payload(mti, bit70, bit11="000123"):
    """Mensagem ISO 8583 sintética: 7 bytes de prefixo (tamanho + header) -> MTI
    (4 ASCII) -> bitmap (32 chars ASCII-hex) -> campos de tamanho fixo. Total 94
    bytes = 188 chars hex, batendo com os offsets do parser (MTI em 14, bit7 em 86...)."""
    prefix = b"\x00\x5a" + b"ISO01"
    bitmap = b"8220000000000000" + b"0400000000000000"
    fields = (
        b"0920140102"          # bit 7
        + bit11.encode()       # bit 11 (STAN)
        + b"123456"            # bit 32
        + b"000000000123"      # bit 37 (RRN/NSU)
        + bit70.encode()       # bit 70 (NMIC)
        + b"12345"             # bit 100
        + b"123456789"         # bit 127
    )
    return prefix + mti.encode() + bitmap + fields


SAMPLE_TCPDUMP = (
    _entry("14:01:02.100000", "10.1.1.5", 51000, "10.1.1.10", 443, "S", TCP_SYN)
    + _entry("14:01:02.100500", "10.1.1.10", 443, "10.1.1.5", 51000, "S.", TCP_SYN_ACK)
    + _entry("14:01:02.101000", "10.1.1.5", 51000, "10.1.1.10", 443, "P.", TCP_PSH_ACK,
             _iso_payload("0800", "301"))
    + _entry("14:01:02.150000", "10.1.1.10", 443, "10.1.1.5", 51000, "P.", TCP_PSH_ACK,
             _iso_payload("0810", "301"))
    + _entry("14:01:02.170000", "10.1.1.5", 51000, "10.1.1.10", 443, "P.", TCP_PSH_ACK,
             _iso_payload("0800", "001", bit11="000124"))
    + _entry("14:01:02.200000", "10.1.1.10", 443, "10.1.1.5", 51000, "R.", TCP_RST_ACK)
)

# Payload TCP que NÃO é ISO 8583 (banner SSH) — não pode gerar MTI/bits/marcadores.
SAMPLE_NON_ISO = _entry(
    "14:02:00.000000", "10.1.1.5", 40000, "10.1.1.10", 22, "P.", TCP_PSH_ACK,
    b"SSH-2.0-OpenSSH_7.4\r\n",
)

# Payload curto demais para ter MTI estruturado, mas com o token "0800" — cai na
# heurística legada (marcador request_0800), só olhando o payload TCP.
SAMPLE_LEGACY = _entry(
    "14:03:00.000000", "10.1.1.5", 40001, "10.1.1.10", 9000, "P.", TCP_PSH_ACK,
    b"xx0800yy",
)

SAMPLE_LIST_VS = """\
ltm virtual vs_web_443 {
    destination 10.1.1.10:443
    ip-protocol tcp
    mask 255.255.255.255
    pool pool_web_443
    profiles {
        tcp { }
    }
}
ltm virtual vs_api_8080 {
    destination 10.1.1.11:8080
    ip-protocol tcp
    mask 255.255.255.255
    pool pool_api_8080
}
"""

SAMPLE_SHOW_POOL_MEMBERS = """\
Ltm::Pool: pool_web_443
Ltm::Pool Member: 10.2.2.11:443
Status
    Availability : available
    State        : enabled
    Reason       : Pool member is available
Ltm::Pool Member: 10.2.2.12:443
Status
    Availability : offline
    State        : disabled
    Reason       : Manually forced offline
"""


# Saídas reais do F5 de teste (encurtadas). Node do pool da VS 3 renomeado para
# "web01" (sem IP no nome) para exercitar a busca do IP real no `list`.
SAMPLE_VS_LIST = """ltm virtual vs_app1_15000 {
    destination 10.100.1.10:hydap
    ip-protocol tcp
    pool pool_app1_15000
}
ltm virtual vs_app2_16000 {
    destination 10.100.1.10:fmsas
    pool pool_app2_16000
}
ltm virtual vs_app3_17000 {
    description "parceiro - Padaria do zezinho"
    destination 10.100.1.10:17000
    pool pool_app3_17000
}
"""

SAMPLE_VS_SHOW = """
Ltm::Virtual Server: vs_app3_17000
Status
  Availability     : available
  Destination      : 10.100.1.10:17000
"""

SAMPLE_POOL_LIST = """ltm pool pool_app1_15000 {
    members {
        node_app_10.100.2.1:hydap {
            address 10.100.2.1
            session monitor-enabled
            state down
        }
        web01:hydap {
            address 192.168.0.9
            session monitor-enabled
            state up
        }
    }
    monitor tcp_half_open
}
ltm pool pool_app2_16000 {
    members {
        node_app_10.100.2.1:fmsas {
            address 10.100.2.1
        }
    }
    monitor tcp_half_open
}
ltm pool pool_app3_17000 {
    members {
        web01:hydap {
            address 192.168.0.9
            session monitor-enabled
            state up
        }
    }
    monitor tcp_half_open
}
"""

SAMPLE_POOL_SHOW = """
Ltm::Pool: pool_app3_17000
  | Ltm::Pool Member: web01:15000
  |   Availability   : available
  |   State          : enabled
"""


def run():
    print("== tcpdump parser (flags + ISO 8583) ==")
    packets = tcpdump_parser.parse_tcpdump_output(SAMPLE_TCPDUMP)
    assert len(packets) == 6, f"esperado 6 pacotes, veio {len(packets)}"
    labels = [p["flags_label"] for p in packets]
    assert labels == ["SYN", "SYN-ACK", "PSH-ACK", "PSH-ACK", "PSH-ACK", "RST-ACK"], labels

    # pacotes sem payload não têm MTI
    assert packets[0]["mti"] is None and packets[5]["mti"] is None

    echo_req, echo_resp, signon = packets[2], packets[3], packets[4]
    assert echo_req["mti"] == "0800" and echo_resp["mti"] == "0810", (echo_req, echo_resp)
    assert echo_req["bit7"] == "0920140102", echo_req
    assert echo_req["bit11"] == "000123", echo_req
    assert echo_req["bit32"] == "123456", echo_req
    assert echo_req["bit37"] == "000000000123", echo_req
    assert echo_req["bit70"] == "301" and echo_req["bit70_desc"] == "Echo Test", echo_req
    assert echo_req["bit100"] == "12345" and echo_req["bit127"] == "123456789", echo_req
    assert echo_req["is_echo_test"] and not echo_req["is_signon"], echo_req
    assert "MTI:0800" in echo_req["markers_found"], echo_req["markers_found"]
    assert "NMIC:301" in echo_req["markers_found"], echo_req["markers_found"]
    assert echo_resp["is_echo_test"], echo_resp
    assert signon["bit70"] == "001" and signon["is_signon"], signon
    assert signon["bit70_desc"] == "Sign-On" and signon["bit11"] == "000124", signon

    summary = tcpdump_parser.summarize(packets)
    assert summary["syn"] == 1 and summary["syn_ack"] == 1 and summary["rst_ack"] == 1
    assert summary["psh_ack"] == 3, summary
    assert summary["mti_counts"] == {"0800": 2, "0810": 1}, summary
    assert summary["network_codes"] == {"301": 2, "001": 1}, summary
    assert summary["echo_tests"] == 2 and summary["signon"] == 1 and summary["signoff"] == 0
    assert summary["request_0800_count"] == 2 and summary["response_0810_count"] == 1
    print("OK:", summary)

    print("== tcpdump parser (payload nao-ISO nao gera falso positivo) ==")
    non_iso = tcpdump_parser.parse_tcpdump_output(SAMPLE_NON_ISO)
    assert len(non_iso) == 1, non_iso
    assert non_iso[0]["mti"] is None and non_iso[0]["bit70"] is None, non_iso[0]
    assert non_iso[0]["markers_found"] == [], non_iso[0]
    print("OK: banner SSH sem MTI/bits/marcadores")

    print("== tcpdump parser (fallback legado 0800 no payload) ==")
    legacy = tcpdump_parser.parse_tcpdump_output(SAMPLE_LEGACY)
    assert len(legacy) == 1 and legacy[0]["mti"] is None, legacy
    assert any("request_0800" in m for m in legacy[0]["markers_found"]), legacy[0]
    legacy_summary = tcpdump_parser.summarize(legacy)
    assert legacy_summary["request_0800_count"] == 1, legacy_summary
    print("OK:", legacy[0]["markers_found"])

    print("== tmsh parser (virtual servers) ==")
    vs_list = tmsh_parser.parse_virtual_servers(SAMPLE_LIST_VS)
    assert len(vs_list) == 2, vs_list
    assert vs_list[0] == {"vs_name": "vs_web_443", "address": "10.1.1.10", "port": 443, "pool_name": "pool_web_443", "description": None}
    print("OK:", vs_list)

    print("== tmsh parser (pool members) ==")
    members = tmsh_parser.parse_pool_members(SAMPLE_SHOW_POOL_MEMBERS)
    assert len(members) == 2, members
    assert members[0]["availability"] == "available"
    assert members[1]["availability"] == "offline"
    print("OK:", members)

    print("== comparator ==")
    baseline = [{"vs_name": "vs_web_443", "pool_name": "pool_web_443", "expected_port": 443,
                 "purpose": "site institucional", "expected_members": [], "partition": "Common"},
                {"vs_name": "vs_missing", "pool_name": "pool_x", "expected_port": 80,
                 "purpose": "legado", "expected_members": [], "partition": "Common"}]
    diff = comparator.compare_vs_to_baseline(vs_list, baseline)
    assert diff["summary"]["ok"] == 1
    assert diff["summary"]["missing_on_device"] == 1
    assert diff["summary"]["unexpected_on_device"] == 1  # vs_api_8080
    print("OK:", diff["summary"])

    print("== safety guardrails ==")
    try:
        safety.assert_safe_tmsh_command("tmsh delete ltm virtual vs_web_443")
        raise AssertionError("deveria ter bloqueado comando de delete")
    except safety.UnsafeInputError:
        print("OK: comando destrutivo bloqueado")

    try:
        safety.require_identifier("vs_web; tmsh delete ltm virtual all", "vs_name")
        raise AssertionError("deveria ter bloqueado identificador malicioso")
    except safety.UnsafeInputError:
        print("OK: identificador malicioso bloqueado")

    assert safety.assert_safe_tmsh_command("tmsh show ltm virtual vs_web_443").startswith("tmsh show")
    print("OK: comando read-only permitido")

    print("== safety: porta TCP 1222 (captura RISe) proibida no tcpdump ==")
    base = "tcpdump -nn -X -i any -c 10"
    blocked_cases = {
        "porta 1222 explicita": f"{base} port 1222",
        "1222 dentro de OR": f"{base} (port 15000 or port 1222)",
        "src/dst port 1222": f"{base} dst port 1222",
        "portrange que inclui 1222": f"{base} portrange 1000-2000",
        "1222 com zeros a esquerda": f"{base} port 01222",
        "1222 junto de host": f"{base} port 1222 and host 10.100.2.1",
    }
    for label, cmd in blocked_cases.items():
        try:
            safety.assert_safe_tcpdump_command(cmd)
            raise AssertionError(f"deveria ter bloqueado: {label}: {cmd}")
        except safety.BlockedPortError as exc:
            assert "1222" in str(exc) and "RISe" in str(exc), (label, str(exc))
            assert "desabilitadas para esta ferramenta" in str(exc), (label, str(exc))
    print(f"OK: {len(blocked_cases)} variações bloqueadas com mensagem RISe")

    ok_cmd = f"{base} port 15000 and host 10.100.2.1"
    assert safety.assert_safe_tcpdump_command(ok_cmd) == ok_cmd
    assert safety.assert_safe_tcpdump_command(base) == base  # sem filtro: não é alterado
    assert safety.require_capturable_port(15000, "node_port") == 15000
    for bad in (1222, "1222", " 1222 ", 1222.0):  # qualquer forma de entrada da porta
        try:
            safety.require_capturable_port(bad, "node_port")
            raise AssertionError(f"deveria ter bloqueado porta {bad!r}")
        except safety.BlockedPortError as exc:
            assert str(exc) == (
                "Capturas na porta TCP 1222 (porta de conexão com a captura RISe) estão "
                "desabilitadas para esta ferramenta."
            ), str(exc)
    print("OK: porta comum passa; 1222 bloqueada em qualquer forma; mensagem exata ao usuário")

    print("== f5_client: tcpdump_capture respeita a proibição (sem rede) ==")
    device = Device(
        name="f5-selftest", host="192.0.2.1", port=22, partition="Common", tags=[],
        credentials=DeviceCredentials(user="u", password="p", key_path=None),
    )
    client = F5Client(device=device, connect_timeout_sec=1, command_timeout_sec=1)
    ssh_calls = []

    def fake_run(cmd):
        ssh_calls.append(cmd)
        return CommandResult(command=cmd, stdout="", stderr="", exit_status=0)

    client._run = fake_run
    client.count_running_tcpdump = lambda: 0
    capture_kwargs = dict(interface="any", count=5, max_count=500, timeout_sec=5, max_timeout_sec=60)

    for kwargs in ({"server_port": 1222, "node_port": None}, {"server_port": None, "node_port": 1222}):
        try:
            client.tcpdump_capture(**capture_kwargs, **kwargs)
            raise AssertionError(f"deveria ter bloqueado {kwargs}")
        except safety.BlockedPortError:
            pass
    assert ssh_calls == [], "porta proibida não pode gerar NENHUM comando no F5"

    client.tcpdump_capture(**capture_kwargs, server_port=None, node_port=15000, host="10.100.2.1")
    assert ssh_calls[-1].endswith("'port 15000 and host 10.100.2.1'"), ssh_calls[-1]
    assert "1222" not in ssh_calls[-1], "o filtro BPF não deve ser alterado pela proibição"

    client.tcpdump_capture(**capture_kwargs, server_port=None, node_port=None)  # sem filtro nenhum
    assert ssh_calls[-1].endswith("-c 5"), ssh_calls[-1]
    print("OK: 1222 recusada na validação, sem tocar no F5; filtro normal intacto:", ssh_calls[-2])

    print("== f5_client: filtro com DUAS portas chega ao shell remoto entre aspas ==")
    # Regressão de um bug real (visto no F5): sem aspas, "(port A or port B)" é erro de
    # sintaxe do shell -> tcpdump nem roda (exit 1, 0 pacotes).
    client.tcpdump_capture(**capture_kwargs, server_port=15000, node_port=16000)
    two_ports = ssh_calls[-1]
    assert two_ports.endswith("'(port 15000 or port 16000)'"), two_ports
    assert shlex.split(two_ports)[-1] == "(port 15000 or port 16000)", shlex.split(two_ports)
    shell = shutil.which("sh")
    if shell:
        buggy = "timeout 5 tcpdump -nn -c 5 (port 15000 or port 16000)"
        assert subprocess.run([shell, "-n", "-c", buggy], capture_output=True).returncode != 0, \
            "o comando sem aspas deveria ser erro de sintaxe do shell"
        fixed = subprocess.run([shell, "-n", "-c", two_ports], capture_output=True)
        assert fixed.returncode == 0, fixed.stderr
        print("OK: sh -n aceita o comando entre aspas; recusa a forma antiga")
    else:
        print("OK (sh indisponível: só a forma do argumento foi conferida)")

    print("== f5_client: com IP e porta confirmados, filtro por conexão (IP E porta) ==")
    client.tcpdump_capture(**capture_kwargs, server_port=17000, node_port=15000,
                           vs_addr="10.100.1.10", client_addr="192.168.170.1",
                           node_addr="192.168.0.9")
    specific = shlex.split(ssh_calls[-1])[-1]
    assert specific == ("((port 17000 and host 10.100.1.10 and host 192.168.170.1) or "
                        "(port 15000 and host 192.168.0.9))"), specific
    client.tcpdump_capture(**capture_kwargs, server_port=17000, node_port=None,
                           vs_addr="10.100.1.10")
    assert shlex.split(ssh_calls[-1])[-1] == "port 17000 and host 10.100.1.10", ssh_calls[-1]
    for bad in ("10.100.1.10 or port 22", "10.100.1.0/24", "zezinho", "10.100.1.10'"):
        try:
            client.tcpdump_capture(**capture_kwargs, server_port=17000, node_port=None, vs_addr=bad)
            raise AssertionError(f"deveria ter recusado vs_addr {bad!r}")
        except UnsafeInputError:
            pass
    print("OK: cada perna vira 'porta AND IPs'; IP inválido recusado:", specific)

    print("== f5_client: uma solicitação = UM processo tcpdump no F5 (sem `timeout`) ==")
    argv = shlex.split(ssh_calls[-1])
    assert argv[:4] == ["perl", "-e", "alarm(shift), exec(@ARGV)", "5"], argv
    assert argv[4] == "tcpdump" and "-l" in argv and "timeout" not in argv, argv

    def killed_by_alarm(cmd):
        return CommandResult(command=cmd, stdout="", stderr="", exit_status=-1)

    client._run = killed_by_alarm
    real_monotonic = time.monotonic
    ticks = iter([100.0, 105.2])  # início / fim: prazo de 5 s vencido
    time.monotonic = lambda: next(ticks)
    try:
        assert client.tcpdump_capture(**capture_kwargs, server_port=17000, node_port=None
                                      ).exit_status == 124
        ticks = iter([100.0, 101.0])  # morto por sinal ANTES do prazo: não é o alarme
        assert client.tcpdump_capture(**capture_kwargs, server_port=17000, node_port=None
                                      ).exit_status == -1
    finally:
        time.monotonic = real_monotonic
        client._run = fake_run
    print("OK: perl alarm + exec do tcpdump; fim pelo prazo -> 124, antes do prazo -> -1")

    print("== server: falha do próprio tcpdump nunca vira status ok ==")
    from . import server

    class FakeClient:
        def __init__(self, exit_status, stderr=""):
            self.exit_status, self.stderr = exit_status, stderr

        def tcpdump_capture(self, **kwargs):
            return CommandResult(command="tcpdump ...", stdout="", stderr=self.stderr,
                                 exit_status=self.exit_status)

    server._get_inventory = lambda: SimpleNamespace(
        limits=SimpleNamespace(tcpdump_max_count=500, tcpdump_max_duration_sec=60))
    server._client_for = lambda device: FakeClient(1, "bash: syntax error near unexpected token `('")
    failed = server.tcpdump_validate_traffic("f5-selftest", node_port=15000)
    assert failed["status"] == "error" and failed["exit_status"] == 1, failed
    assert "syntax error" in failed["message"], failed
    for good in (0, 124):  # 124 = prazo duro, esperado com pouco tráfego
        server._client_for = lambda device, code=good: FakeClient(code)
        assert server.tcpdump_validate_traffic("f5-selftest", node_port=15000)["status"] == "ok"
    print("OK: exit 1 -> status error com stderr; 0 e 124 -> ok")

    print("== server: captura só por porta avisa que é abrangente ==")
    server._client_for = lambda device: FakeClient(0)
    broad = server.tcpdump_validate_traffic("f5-selftest", server_port=17000, node_port=15000)
    assert any("Captura abrangente" in w for w in broad["warnings"]), broad["warnings"]
    narrow = server.tcpdump_validate_traffic(
        "f5-selftest", server_port=17000, vs_addr="10.100.1.10",
        node_port=15000, node_addr="192.168.0.9")
    assert narrow["warnings"] == [], narrow["warnings"]
    print("OK: porta sem IP -> warning; IP+porta nos dois lados -> sem warning")

    print("== tmsh parser: descrição, destino numérico e members do `list` ==")
    vs_all = tmsh_parser.parse_virtual_servers(SAMPLE_VS_LIST)
    assert [v["description"] for v in vs_all] == [None, None, "parceiro - Padaria do zezinho"], vs_all
    assert vs_all[0]["port"] is None  # `list` traz "hydap": porta numérica só pelo `show`
    assert tmsh_parser.parse_vs_destination(SAMPLE_VS_SHOW) == ("10.100.1.10", 17000)
    assert tmsh_parser.parse_vs_destination("nada") == (None, None)
    pool_lists = tmsh_parser.parse_pool_list_members(SAMPLE_POOL_LIST)
    assert pool_lists["pool_app3_17000"] == [
        {"node": "web01", "address": "192.168.0.9", "service": "hydap"}], pool_lists
    assert len(pool_lists["pool_app1_15000"]) == 2, pool_lists
    print("OK:", pool_lists["pool_app3_17000"])

    print("== tmsh parser: conexão pedida pelo usuário -> VS ==")
    match = tmsh_parser.match_virtual_servers
    assert [v["vs_name"] for v in match(vs_all, "Padaria do Zézinho")] == ["vs_app3_17000"]
    assert [v["vs_name"] for v in match(vs_all, "vs_app1_15000")] == ["vs_app1_15000"]
    assert len(match(vs_all, "app")) == 3  # abrangente: casa com várias
    assert match(vs_all, "padaria do joaozinho") == [] and match(vs_all, "  ") == []
    print("OK: nome/descrição sem acento e caixa; 'app' -> 3 candidatas; inexistente -> 0")

    print("== server: tcpdump_capture_connection foca só a conexão pedida ==")

    class ConnClient:
        def __init__(self):
            self.captures = []

        def list_virtual_server_config(self, vs_name=None):
            return CommandResult(command="", stdout=SAMPLE_VS_LIST, stderr="", exit_status=0)

        def show_virtual_servers(self, vs_name=None):
            return CommandResult(command="", stdout=SAMPLE_VS_SHOW, stderr="", exit_status=0)

        def list_pool_config(self, pool_name=None):
            return CommandResult(command="", stdout=SAMPLE_POOL_LIST, stderr="", exit_status=0)

        def show_pool(self, pool_name=None):
            return CommandResult(command="", stdout=SAMPLE_POOL_SHOW, stderr="", exit_status=0)

        def tcpdump_capture(self, **kwargs):
            self.captures.append(kwargs)
            return CommandResult(command="tcpdump ...", stdout="", stderr="", exit_status=124)

    conn_client = ConnClient()
    server._client_for = lambda device: conn_client
    for broad, status in (("app", "ambiguous"), ("padaria do joaozinho", "not_found")):
        out = server.tcpdump_capture_connection("f5-selftest", broad)
        assert out["status"] == status, out
        assert conn_client.captures == [], "pedido abrangente/inexistente NÃO pode capturar"
    assert {c["vs_name"] for c in server.tcpdump_capture_connection(
        "f5-selftest", "app")["candidates"]} == {"vs_app1_15000", "vs_app2_16000", "vs_app3_17000"}

    out = server.tcpdump_capture_connection("f5-selftest", "padaria do zezinho",
                                            client_addr="192.168.170.1")
    assert out["status"] == "ok", out
    sent = conn_client.captures[-1]
    assert (sent["server_port"], sent["vs_addr"], sent["client_addr"]) == \
        (17000, "10.100.1.10", "192.168.170.1"), sent
    assert sent["node_members"] == [("192.168.0.9", 15000)], sent  # IP do node "web01" via `list`
    assert sent["node_port"] is None and sent["node_addr"] is None and sent["host"] is None, sent
    assert out["connection"]["pool_members"] == ["192.168.0.9:15000"], out["connection"]
    assert any("vs_app1_15000" in w and "compartilhado" in w for w in out["warnings"]), out
    # o filtro que o F5Client real monta para esses parâmetros
    client._run = fake_run
    client.tcpdump_capture(**capture_kwargs, server_port=17000, node_port=None,
                           vs_addr="10.100.1.10", node_members=[("192.168.0.9", 15000)])
    assert shlex.split(ssh_calls[-1])[-1] == (
        "((port 17000 and host 10.100.1.10) or (port 15000 and host 192.168.0.9))"), ssh_calls[-1]
    print("OK: 'app' -> ambiguous, sem captura; padaria -> só VS 10.100.1.10:17000 + member "
          "192.168.0.9:15000; aviso de member compartilhado com vs_app1_15000")

    print("\nTODOS OS AUTO-TESTES PASSARAM")


if __name__ == "__main__":
    run()
