#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""f5_tcpdump.py - captura tcpdump segura + parsing ISO 8583 em UM arquivo, feito
para rodar DENTRO do BIG-IP e ser chamado por uma camada de API (ex: iControl LX).

Junta o que hoje esta espalhado pelo agente MCP:
  * captura  : monta o comando como LISTA de argumentos (sem shell), limita
               count/timeout, le o pcap binario do stdout (`-w -`, sem gravar arquivo);
  * safety   : valida identificadores/IP/portas/limites NO EQUIPAMENTO, bloqueia a
               porta TCP 1222 (conexao com a captura RISe), trava de concorrencia
               atomica (flock + contagem de tcpdump em /proc) - nunca interrompe
               capturas existentes;
  * parsing  : pcap -> IPv4/IPv6 -> TCP -> MTI e bits ISO 8583, mesmo formato de
               saida do agente (src/tcpdump_parser.py).

Requisitos: SOMENTE biblioteca padrao e compativel com Python 2.7 e 3.x (o Python do
TMOS pode ser 2.7): sem f-strings, dataclasses, typing nem anotacoes.

Uso:
    echo '{"node_port": 15000, "host": "10.100.2.1", "count": 100, "timeout_sec": 20}' \\
        | python f5_tcpdump.py
    python f5_tcpdump.py --request '{"node_port": 15000}'

Entrada (JSON): interface, server_port, node_port, host, vs_addr, client_addr, node_addr,
count, timeout_sec (e verbose, detalhes, stan).
Saida (JSON): status = ok | busy | blocked | invalid | error, mais os campos abaixo.
Precisa rodar como root (tcpdump).
"""
from __future__ import print_function

import binascii
import errno
import fcntl
import json
import numbers
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

try:
    import syslog
except ImportError:  # pragma: no cover - so em ambientes sem syslog
    syslog = None

# ---------------------------------------------------------------------------
# Configuracao (ajuste aqui; nada disso e lido do ambiente de proposito)
# ---------------------------------------------------------------------------

TCPDUMP_CANDIDATES = ("/usr/sbin/tcpdump", "/sbin/tcpdump", "/usr/bin/tcpdump")

MAX_COUNT = 500
MAX_TIMEOUT_SEC = 180
DEFAULT_COUNT = 100
DEFAULT_TIMEOUT_SEC = 20
SNAPLEN = 512                    # cobre cabecalhos + os 94 bytes de ISO 8583
MAX_PACKETS_RETURNED = 200

MAX_CONCURRENT_TCPDUMP = 2       # teto TOTAL, contando a captura a iniciar
BUSY_RETRY_MINUTES = 5
LOCK_DIR = "/var/run/f5_tcpdump"  # tmpfs no TMOS
GUARD_WAIT_SEC = 5.0

# Portas em que esta ferramenta NUNCA captura. Chave = porta; valor = descricao.
BLOCKED_PORTS = {
    1222: "porta de conexão com a captura RISe",
}

ALLOWED_KEYS = ("interface", "server_port", "node_port", "host", "count", "timeout_sec",
                "vs_addr", "client_addr", "node_addr", "verbose", "detalhes", "stan")
MAX_TRANSACTIONS = 50
ISO_BIT_FIELDS = ("bit7", "bit11", "bit32", "bit37", "bit70", "bit100", "bit127")
EXPECTED_HOPS = 4        # cliente->VS, F5->node, node->F5, VS->cliente
STAN_RE = re.compile(r"^[0-9]{1,12}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")  # sem '-' inicial

TMM_WARNING_MARKER = "tmm tcpdump instances"

# --- ISO 8583 ---------------------------------------------------------------
# Offsets em caracteres HEX relativos ao inicio do PAYLOAD TCP (iRule do cliente:
# `substr $payloadhex 14 8`). ATENCAO: os offsets dos bits (86..188) ainda NAO foram
# confirmados contra uma captura real do cliente - so o MTI vem da iRule.
MTI_OFFSET = 14
MTI_HEX_LEN = 8
ISO_FIELD_SLICES = (
    ("bit7", 86, 106),
    ("bit11", 106, 118),
    ("bit32", 118, 130),
    ("bit37", 130, 154),
    ("bit70", 154, 160),
    ("bit100", 160, 170),
    ("bit127", 170, 188),
)
ISO_MIN_HEX_LEN = 188

MTI_DESCRIPTIONS = {
    "0100": "Pedido de autorização",
    "0110": "Resposta de autorização",
    "0120": "Pedido de advice",
    "0130": "Resposta de advice",
    "0200": "Pedido de saque",
    "0210": "Resposta de saque",
    "0220": "Pedido de advice saque",
    "0230": "Resposta de advice saque",
    "0400": "Pedido de cancelamento",
    "0410": "Resposta de cancelamento",
    "0420": "Pedido de reversão",
    "0430": "Resposta de reversão",
    "0600": "Pedido TSP",
    "0610": "Resposta TSP",
    "0800": "Pedido de Echo-test",
    "0810": "Resposta de Echo-test",
    "0802": "Pedido de sign-on",
    "0812": "Resposta de sign-on",
}
NETWORK_CODE_MAP = {"001": "Sign-On", "002": "Sign-Off", "301": "Echo Test"}

FLAG_LABELS = {
    "S": "SYN", "S.": "SYN-ACK", ".": "ACK", "P.": "PSH-ACK",
    "R": "RST", "R.": "RST-ACK", "F": "FIN", "F.": "FIN-ACK",
    "SEW": "SYN-ECN",
}

LEGACY_MARKERS = (("request_0800", "0800"), ("response_0810", "0810"))


# ---------------------------------------------------------------------------
# Erros e validacao (safety)
# ---------------------------------------------------------------------------

class RequestError(Exception):
    """Pedido recusado na validacao. status = 'invalid' | 'blocked' | 'busy'."""

    def __init__(self, status, message, **extra):
        Exception.__init__(self, message)
        self.status = status
        self.message = message
        self.extra = extra


def blocked_port_message(port):
    return ("Capturas na porta TCP %d (%s) estão desabilitadas para esta "
            "ferramenta." % (port, BLOCKED_PORTS[port]))


def _is_string(value):
    try:
        return isinstance(value, basestring)  # noqa: F821 (python 2)
    except NameError:
        return isinstance(value, str)


def _to_int(value, name, low, high):
    """Aceita int ou string de digitos (com espacos); recusa bool/float/outros."""
    if isinstance(value, bool):
        raise RequestError("invalid", "Valor inválido para '%s': %r" % (name, value))
    if isinstance(value, numbers.Integral):
        number = int(value)
    elif _is_string(value) and value.strip().isdigit():
        number = int(value.strip())
    else:
        raise RequestError("invalid", "Valor inválido para '%s': %r" % (name, value))
    if number < low or number > high:
        raise RequestError(
            "invalid", "'%s' deve estar entre %d e %d (recebido %d)" % (name, low, high, number))
    return number


def _to_port(value, name):
    port = _to_int(value, name, 1, 65535)
    if port in BLOCKED_PORTS:
        raise RequestError("blocked", blocked_port_message(port))
    return port


def _to_ip(value, name):
    """So IPv4/IPv6 literal - sem DNS e sem texto livre indo para o filtro."""
    if _is_string(value):
        try:
            text = str(value)
        except UnicodeError:
            text = None
        if text:
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    socket.inet_pton(family, text)
                    return text
                except (socket.error, ValueError):
                    pass
    raise RequestError("invalid", "'%s' deve ser um endereço IPv4/IPv6 literal: %r" % (name, value))


def validate_request(request):
    """Normaliza e valida o pedido; levanta RequestError se algo estiver fora da
    politica. Retorna um dict com os campos normalizados."""
    if not isinstance(request, dict):
        raise RequestError("invalid", "O pedido deve ser um objeto JSON.")
    unknown = sorted(repr(k) for k in request if k not in ALLOWED_KEYS)
    if unknown:
        raise RequestError("invalid", "Parâmetro(s) não suportado(s): %s" % ", ".join(unknown))

    interface = request.get("interface", "any")
    if not _is_string(interface) or not INTERFACE_RE.match(interface):
        raise RequestError("invalid", "Interface inválida: %r" % (interface,))

    # portas primeiro: um pedido na 1222 e recusado antes de qualquer outra coisa
    server_port = request.get("server_port")
    node_port = request.get("node_port")
    server_port = None if server_port is None else _to_port(server_port, "server_port")
    node_port = None if node_port is None else _to_port(node_port, "node_port")

    host = request.get("host")
    host = None if host is None else _to_ip(host, "host")

    # IP por perna: com server_port, vs_addr (e client_addr) restringem o lado cliente
    # a "port VS and host VS"; com node_port, node_addr restringe o lado servidor. Sem
    # isso, duas VS no mesmo IP ou o mesmo node em varios pools entram na captura.
    vs_addr = request.get("vs_addr")
    vs_addr = None if vs_addr is None else _to_ip(vs_addr, "vs_addr")
    client_addr = request.get("client_addr")
    client_addr = None if client_addr is None else _to_ip(client_addr, "client_addr")
    node_addr = request.get("node_addr")
    node_addr = None if node_addr is None else _to_ip(node_addr, "node_addr")
    if client_addr is not None and server_port is None:
        raise RequestError("invalid", "'client_addr' exige 'server_port' (porta da VS).")
    if node_addr is not None and node_port is None:
        raise RequestError("invalid", "'node_addr' exige 'node_port' (porta do node).")

    verbose = request.get("verbose", False)
    if not isinstance(verbose, bool):
        raise RequestError("invalid", "'verbose' deve ser true ou false: %r" % (verbose,))
    detalhes = request.get("detalhes", False)
    if not isinstance(detalhes, bool):
        raise RequestError("invalid", "'detalhes' deve ser true ou false: %r" % (detalhes,))
    stan = request.get("stan")
    if stan is not None:
        if isinstance(stan, bool) or not (_is_string(stan) or isinstance(stan, numbers.Integral)):
            raise RequestError("invalid", "'stan' deve ser o STAN (1 a 12 digitos): %r" % (stan,))
        stan = str(stan).strip()
        if not STAN_RE.match(stan):
            raise RequestError("invalid", "'stan' deve ter de 1 a 12 digitos: %r" % (stan,))

    count = _to_int(request.get("count", DEFAULT_COUNT), "count", 1, MAX_COUNT)
    timeout_sec = _to_int(request.get("timeout_sec", DEFAULT_TIMEOUT_SEC), "timeout_sec",
                          1, MAX_TIMEOUT_SEC)

    return {
        "interface": str(interface), "server_port": server_port, "node_port": node_port,
        "host": host, "count": count, "timeout_sec": timeout_sec,
        "vs_addr": vs_addr, "client_addr": client_addr, "node_addr": node_addr,
        "verbose": verbose, "detalhes": detalhes, "stan": stan,
    }


def _leg(port, *addrs):
    tokens = ["port", str(port)]
    for addr in addrs:
        if addr is not None:
            tokens.extend(["and", "host", addr])
    return tokens


def build_argv(params, tcpdump_bin):
    """Lista de argumentos do tcpdump - sem shell. Os termos do filtro sao tokens
    separados e vem so de valores ja validados. Cada perna e "porta E IP(s)":
    (port VS and host VS [and host cliente]) or (port node [and host node])."""
    legs = []
    if params["server_port"] is not None:
        legs.append(_leg(params["server_port"], params["vs_addr"], params["client_addr"]))
    if params["node_port"] is not None:
        node_leg = _leg(params["node_port"], params["node_addr"])
        if node_leg not in legs:
            legs.append(node_leg)

    terms = []
    if len(legs) == 1:
        terms.append(legs[0])
    elif len(legs) == 2:
        joined = ["("]
        for index, leg in enumerate(legs):
            if index:
                joined.append("or")
            joined.extend(["("] + leg + [")"] if len(leg) > 2 else leg)
        terms.append(joined + [")"])
    if params["host"] is not None:
        terms.append(["host", params["host"]])

    filter_tokens = []
    for index, term in enumerate(terms):
        if index:
            filter_tokens.append("and")
        filter_tokens.extend(term)

    argv = [tcpdump_bin, "-nn", "-U", "-s", str(SNAPLEN), "-c", str(params["count"]),
            "-i", params["interface"], "-w", "-"]
    if filter_tokens:
        argv.append("--")  # nada depois daqui pode virar opcao do tcpdump
        argv.extend(filter_tokens)
    _assert_argv_safe(argv, params)
    return argv


def _assert_argv_safe(argv, params):
    """Ultima camada: o argv montado nao pode citar porta bloqueada nem ter token
    fora do conjunto esperado depois do `--`."""
    if "--" not in argv:
        return
    keywords = ("(", ")", "port", "or", "and", "host")
    allowed_values = set(str(p) for p in (params["server_port"], params["node_port"]) if p)
    for key in ("host", "vs_addr", "client_addr", "node_addr"):
        if params[key]:
            allowed_values.add(params[key])
    tail = argv[argv.index("--") + 1:]
    for position, token in enumerate(tail):
        if token not in keywords and token not in allowed_values:
            raise RequestError("invalid", "Token inesperado no filtro: %r" % (token,))
        if token == "port" and position + 1 < len(tail):
            value = tail[position + 1]
            if value.isdigit() and int(value) in BLOCKED_PORTS:
                raise RequestError("blocked", blocked_port_message(int(value)))


# ---------------------------------------------------------------------------
# Concorrencia: guarda atomica (flock) + contagem de tcpdump em /proc
# ---------------------------------------------------------------------------

def count_running_tcpdump(proc_dir="/proc"):
    """Conta processos `tcpdump` em execucao (de qualquer origem) lendo /proc.
    Somente leitura - nao altera nem finaliza nenhum processo."""
    count = 0
    for entry in os.listdir(proc_dir):
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc_dir, entry, "comm")) as handle:
                if handle.read().strip() == "tcpdump":
                    count += 1
        except (IOError, OSError):
            continue  # o processo terminou no meio da varredura
    return count


def _open_guard(lock_dir, wait_sec):
    """Trava exclusiva e curta que serializa 'contar + iniciar' entre chamadas
    concorrentes desta ferramenta (elimina a corrida de checar e iniciar)."""
    try:
        os.makedirs(lock_dir, 0o700)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    fd = os.open(os.path.join(lock_dir, "guard.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.time() + wait_sec
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except (IOError, OSError) as exc:
            if exc.errno not in (errno.EAGAIN, errno.EACCES):
                os.close(fd)
                raise
            if time.time() >= deadline:
                os.close(fd)
                return None
            time.sleep(0.05)


def _busy_error(running):
    return RequestError(
        "busy",
        "Já existem %s captura(s) tcpdump em execução em %s — iniciar mais uma "
        "passaria do teto de %d simultâneas. A ferramenta não inicia uma nova captura "
        "nem interrompe as existentes — tente novamente em ~%d minutos."
        % (running, socket.gethostname(), MAX_CONCURRENT_TCPDUMP, BUSY_RETRY_MINUTES),
        retry_after_minutes=BUSY_RETRY_MINUTES,
    )


# ---------------------------------------------------------------------------
# Captura
# ---------------------------------------------------------------------------

def _find_tcpdump():
    for path in TCPDUMP_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _capture(argv):
    """Inicia o tcpdump (lista de argumentos, sem shell) e devolve o Popen.
    `close_fds=True` impede que o filho herde a trava de concorrencia."""
    devnull = open(os.devnull, "rb")
    try:
        proc = subprocess.Popen(argv, stdin=devnull, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True)
    finally:
        devnull.close()
    return proc


def _wait_capture(proc, timeout_sec):
    """Espera o fim da captura com prazo duro. Retorna (stdout, stderr, exit_status,
    timed_out); exit_status = 124 quando o prazo estourou (como o `timeout`)."""
    state = {"timed_out": False}

    def _terminate():
        state["timed_out"] = True
        try:
            proc.terminate()
        except OSError:
            pass

    def _kill():
        try:
            proc.kill()
        except OSError:
            pass

    soft = threading.Timer(timeout_sec, _terminate)
    hard = threading.Timer(timeout_sec + 3, _kill)
    for timer in (soft, hard):
        timer.daemon = True
        timer.start()
    try:
        out, err = proc.communicate()
    finally:
        soft.cancel()
        hard.cancel()
    status = 124 if state["timed_out"] else proc.returncode
    return out, err, status, state["timed_out"]


# ---------------------------------------------------------------------------
# Parsing: pcap -> IP -> TCP -> ISO 8583
# ---------------------------------------------------------------------------

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1000000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1000000000.0),
}
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW = 0, 1, 101
LINKTYPE_RAW_ALT, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2 = 12, 113, 276


def _flags_string(flags):
    """Mesma notacao do tcpdump: F S R P . U E W (ou 'none')."""
    text = ""
    for bit, char in ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                      (0x10, "."), (0x20, "U"), (0x40, "E"), (0x80, "W")):
        if flags & bit:
            text += char
    return text or "none"


def _hexlify(data):
    """bytes -> str hex, igual em Python 2 (str) e 3 (bytes.decode)."""
    text = binascii.hexlify(data)
    return text if isinstance(text, str) else text.decode("ascii")


def _hex_to_ascii(value):
    if not value:
        return None
    try:
        text = binascii.unhexlify(value).decode("ascii", "ignore").strip()
    except (TypeError, ValueError, binascii.Error):
        return None
    return text or None


def _extract_mti(payload_hex):
    end = MTI_OFFSET + MTI_HEX_LEN
    if len(payload_hex) < end:
        return None
    mti = _hex_to_ascii(payload_hex[MTI_OFFSET:end])
    if mti and re.match(r"^\d{4}$", mti):
        return mti
    return None


def _extract_iso_fields(payload_hex):
    result = dict((name, None) for name, _, _ in ISO_FIELD_SLICES)
    result["bit70_desc"] = None
    if len(payload_hex) < ISO_MIN_HEX_LEN:
        return result
    for name, start, end in ISO_FIELD_SLICES:
        result[name] = _hex_to_ascii(payload_hex[start:end])
    if result["bit70"]:
        result["bit70_desc"] = NETWORK_CODE_MAP.get(result["bit70"])
    return result


def _find_markers(mti, bit70, bit70_desc, payload):
    markers = []
    if mti:
        markers.append("MTI:%s" % mti)
        if mti in MTI_DESCRIPTIONS:
            markers.append(MTI_DESCRIPTIONS[mti])
        if bit70:
            markers.append("NMIC:%s" % bit70)
        if bit70_desc:
            markers.append(bit70_desc)
        return markers
    # MTI estruturado nao encontrado: heuristica legada, so no payload TCP
    ascii_payload = payload.decode("ascii", "ignore")
    for label, token in LEGACY_MARKERS:
        if token in ascii_payload:
            markers.append("%s(ascii)" % label)
    return markers


def _l3_offset(frame, linktype):
    """Offset do cabecalho IP dentro do quadro, ou None se nao for IPv4/IPv6."""
    fb = bytearray(frame)
    if linktype == LINKTYPE_ETHERNET:
        if len(fb) < 14:
            return None
        offset, proto = 14, struct.unpack_from(">H", frame, 12)[0]
        while proto in (0x8100, 0x88A8) and len(fb) >= offset + 4:  # VLAN tag(s)
            proto = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4
        return offset if proto in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(fb) < 16:
            return None
        proto = struct.unpack_from(">H", frame, 14)[0]
        return 16 if proto in (0x0800, 0x86DD) else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(fb) < 20:
            return None
        proto = struct.unpack_from(">H", frame, 0)[0]
        return 20 if proto in (0x0800, 0x86DD) else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT):
        return 0 if fb and (fb[0] >> 4) in (4, 6) else None
    if linktype == LINKTYPE_NULL:
        return 4 if len(fb) > 4 and (fb[4] >> 4) in (4, 6) else None
    return None


def _parse_frame(frame, linktype, ts_sec, ts_frac, divisor):
    """Um quadro -> dict no formato do agente, ou None se nao for IP."""
    base = _l3_offset(frame, linktype)
    if base is None:
        return None
    fb = bytearray(frame)
    if len(fb) < base + 20:
        return None

    version = fb[base] >> 4
    if version == 4:
        ihl = (fb[base] & 0x0F) * 4
        proto = fb[base + 9]
        total = struct.unpack_from(">H", frame, base + 2)[0]
        frag = struct.unpack_from(">H", frame, base + 6)[0] & 0x1FFF
        src_ip = socket.inet_ntoa(bytes(frame[base + 12:base + 16]))
        dst_ip = socket.inet_ntoa(bytes(frame[base + 16:base + 20]))
        l4 = base + ihl
        end = min(len(fb), base + total) if total else len(fb)
        usable = ihl >= 20 and frag == 0
    elif version == 6:
        if len(fb) < base + 40:
            return None
        proto = fb[base + 6]
        plen = struct.unpack_from(">H", frame, base + 4)[0]
        src_ip = socket.inet_ntop(socket.AF_INET6, bytes(frame[base + 8:base + 24]))
        dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(frame[base + 24:base + 40]))
        l4 = base + 40
        end = min(len(fb), l4 + plen)
        usable = True
    else:
        return None

    flags_raw, sport, dport, payload = "", None, None, b""
    if proto == 6 and usable and len(fb) >= l4 + 20:
        sport, dport = struct.unpack_from(">HH", frame, l4)
        data_off = (fb[l4 + 12] >> 4) * 4
        flags_raw = _flags_string(fb[l4 + 13])
        if data_off >= 20 and l4 + data_off <= end:
            payload = bytes(frame[l4 + data_off:end])

    def _endpoint(ip, port):
        return "%s.%d" % (ip, port) if port is not None else ip

    if flags_raw in FLAG_LABELS:
        label = FLAG_LABELS[flags_raw]
    else:
        label = flags_raw or "UNKNOWN"

    seconds = time.localtime(ts_sec)
    stamp = "%s.%06d" % (time.strftime("%H:%M:%S", seconds),
                         int(ts_frac * (1000000.0 / divisor)))

    payload_hex = _hexlify(payload)
    mti = _extract_mti(payload_hex)
    iso = _extract_iso_fields(payload_hex) if mti else dict(
        (name, None) for name in ("bit7", "bit11", "bit32", "bit37", "bit70",
                                  "bit70_desc", "bit100", "bit127"))
    preview = "".join(chr(b) if 32 <= b < 127 else "." for b in bytearray(payload[:200]))

    return {
        "time": stamp,
        "src": _endpoint(src_ip, sport),
        "dst": _endpoint(dst_ip, dport),
        "flags": flags_raw,
        "flags_label": label,
        "payload_len": len(payload),
        "mti": mti,
        "bit7": iso["bit7"], "bit11": iso["bit11"], "bit32": iso["bit32"],
        "bit37": iso["bit37"], "bit70": iso["bit70"], "bit70_desc": iso["bit70_desc"],
        "bit100": iso["bit100"], "bit127": iso["bit127"],
        "is_echo_test": iso["bit70"] == "301",
        "is_signon": iso["bit70"] == "001",
        "is_signoff": iso["bit70"] == "002",
        "markers_found": _find_markers(mti, iso["bit70"], iso["bit70_desc"], payload),
        "payload_ascii_preview": preview,
    }


def parse_pcap(data):
    """pcap binario (bytes) -> lista de pacotes. Tolera entrada vazia/truncada."""
    if not data or len(data) < 24:
        return []
    magic = bytes(data[:4])
    if magic not in _PCAP_MAGIC:
        return []
    endian, divisor = _PCAP_MAGIC[magic]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]

    packets = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + incl_len]
        offset += incl_len
        if len(frame) < incl_len:
            break  # registro final truncado
        packet = _parse_frame(frame, linktype, ts_sec, ts_frac, divisor)
        if packet is not None:
            packets.append(packet)
    return packets


def summarize(packets):
    summary = {
        "total_packets": len(packets),
        "syn": 0, "syn_ack": 0, "rst": 0, "rst_ack": 0, "ack_only": 0,
        "psh_ack": 0, "fin": 0, "other": 0,
        "mti_counts": {}, "network_codes": {},
        "echo_tests": 0, "signon": 0, "signoff": 0,
        "request_0800_count": 0, "response_0810_count": 0,
    }
    counters = {"SYN": "syn", "SYN-ACK": "syn_ack", "RST": "rst", "RST-ACK": "rst_ack",
                "ACK": "ack_only", "PSH-ACK": "psh_ack", "FIN": "fin", "FIN-ACK": "fin"}
    for pkt in packets:
        summary[counters.get(pkt["flags_label"], "other")] += 1
        mti = pkt.get("mti")
        if mti:
            summary["mti_counts"][mti] = summary["mti_counts"].get(mti, 0) + 1
        bit70 = pkt.get("bit70")
        if bit70:
            summary["network_codes"][bit70] = summary["network_codes"].get(bit70, 0) + 1
        if pkt.get("is_echo_test"):
            summary["echo_tests"] += 1
        if pkt.get("is_signon"):
            summary["signon"] += 1
        if pkt.get("is_signoff"):
            summary["signoff"] += 1
        markers = pkt.get("markers_found", [])
        if mti == "0800" or any(m.startswith("request_0800") for m in markers):
            summary["request_0800_count"] += 1
        if mti == "0810" or any(m.startswith("response_0810") for m in markers):
            summary["response_0810_count"] += 1
    return summary


# ---------------------------------------------------------------------------
# Visao do usuario: so o trafego da VS pedida + transacoes (resposta enxuta)
# ---------------------------------------------------------------------------
# ATENCAO: copia de src/tcpdump_parser.py (focus_vs_traffic / build_transactions /
# simplified_view); test_f5_tcpdump.py confere a paridade. Altere os dois juntos.

PROBE_LABELS = ("SYN", "SYN-ACK", "RST", "RST-ACK")


def _endpoint_parts(endpoint):
    host, _, port = endpoint.rpartition(".")
    if host and port.isdigit():
        return host, int(port)
    return endpoint, None


def _flow_key(pkt):
    return tuple(sorted((pkt["src"], pkt["dst"])))


def focus_vs_traffic(packets, server_port=None, node_port=None, vs_addr=None):
    """Mantem so o trafego da VS pedida e descarta os fluxos do monitor do pool
    (SYN/SYN-ACK/RST sem dados e sem handshake completo no lado do node). So descarta
    quando o lado da VS e identificavel: vs_addr + server_port, ou server_port diferente
    de node_port. Uma perna do node so fica se for de uma conexao da VS (mesmo STAN ou
    mesma porta efemera do cliente, que o F5 preserva no SNAT); o resto e de outra VS
    que divide o IP da VS ou o node (ex: VS :15000 no mesmo IP, pool com o mesmo
    member) e e descartado. Devolve (pacotes mantidos, info)."""
    info = {"separated": False, "probe_flows": 0, "probe_packets": 0,
            "other_flows": 0, "other_packets": 0}
    if server_port is not None and vs_addr is not None:
        vs_endpoint = "%s.%d" % (vs_addr, server_port)

        def is_vs_endpoint(endpoint):
            return endpoint == vs_endpoint
    elif server_port is not None and node_port is not None and server_port != node_port:
        def is_vs_endpoint(endpoint):
            return _endpoint_parts(endpoint)[1] == server_port
    else:
        return list(packets), info

    info["separated"] = True
    flows = {}
    for pkt in packets:
        flows.setdefault(_flow_key(pkt), []).append(pkt)

    vs_flows = set()
    vs_stans = set()
    client_ports = set()
    for key, pkts in flows.items():
        if any(is_vs_endpoint(e) for e in key):
            vs_flows.add(key)
            vs_stans.update(p["bit11"] for p in pkts if p.get("mti") and p.get("bit11"))
            client_ports.update(_endpoint_parts(e)[1] for e in key if not is_vs_endpoint(e))

    keep = set(vs_flows)
    for key, pkts in flows.items():
        if key in vs_flows:
            continue
        probe = all(p.get("payload_len", 0) == 0 and not p.get("mti")
                    and p["flags_label"] in PROBE_LABELS for p in pkts)
        if probe:
            info["probe_flows"] += 1
            info["probe_packets"] += len(pkts)
        elif (any(p.get("bit11") in vs_stans for p in pkts if p.get("mti") and p.get("bit11"))
              or any(_endpoint_parts(e)[1] in client_ports for e in key)):
            keep.add(key)
        else:
            info["other_flows"] += 1
            info["other_packets"] += len(pkts)
    return [p for p in packets if _flow_key(p) in keep], info


def _is_response_mti(mti):
    return len(mti) == 4 and mti[2] in "13"


def _seconds(stamp):
    """'HH:MM:SS.ffffff' -> segundos desde 00:00 (None se o formato nao bater)."""
    try:
        hh, mm, ss = stamp.split(":")
        return int(hh) * 3600 + int(mm) * 60 + float(ss)
    except (ValueError, AttributeError):
        return None


def build_transactions(packets, detail=False):
    """Agrupa as mensagens ISO 8583 em transacoes (pedido + resposta) pelo STAN (bit
    11). A mesma mensagem aparece em varios saltos (cliente->VS, F5->node...). Com
    `detail`, cada transacao ganha campos (bits ISO), trajeto (saltos em ordem), saltos
    e rtt_ms (do pedido a resposta)."""
    order = []
    groups = {}
    for pkt in packets:
        mti = pkt.get("mti")
        if not mti:
            continue
        stan = pkt.get("bit11")
        if stan:
            key = ("stan", stan)
        else:  # sem STAN: agrupa por conexao + par pedido/resposta
            key = ("flow", _flow_key(pkt), mti[:2] + mti[3:])
        group = groups.get(key)
        if group is None:
            group = {"hora": pkt["time"], "stan": stan, "pedido": None, "resposta": None,
                     "tipo": None, "origem": None}
            if detail:
                group["campos"] = dict((b, pkt.get(b)) for b in ISO_BIT_FIELDS)
                group["trajeto"] = []
                group["_req"] = None
                group["_resp"] = None
            groups[key] = group
            order.append(key)
        response = _is_response_mti(mti)
        if response:
            group["resposta"] = group["resposta"] or mti
        elif group["pedido"] is None:
            group["pedido"] = mti
            group["origem"] = _endpoint_parts(pkt["src"])[0]
            group["hora"] = pkt["time"]
        group["tipo"] = (group["tipo"] or pkt.get("bit70_desc")
                         or MTI_DESCRIPTIONS.get(group["pedido"] or mti))
        if detail:
            group["trajeto"].append(
                {"hora": pkt["time"], "de": pkt["src"], "para": pkt["dst"], "mti": mti})
            moment = _seconds(pkt["time"])
            if moment is not None:
                if response:
                    group["_resp"] = moment      # a ULTIMA resposta (VS->cliente)
                elif group["_req"] is None:
                    group["_req"] = moment       # o PRIMEIRO pedido (cliente->VS)
    out = []
    for key in order:
        group = groups[key]
        group["respondida"] = group["resposta"] is not None
        if detail:
            req = group.pop("_req")
            resp = group.pop("_resp")
            group["saltos"] = len(group["trajeto"])
            if req is not None and resp is not None and resp >= req:
                group["rtt_ms"] = int(round((resp - req) * 1000))
            else:
                group["rtt_ms"] = None
        out.append(group)
    return out


def render_details_markdown(transactions, vs_label):
    """Tabela no padrao pedido (# | Tipo | STAN | Enviada | Resposta | RTT | Rastreio) +
    observacoes, pronta para ser apresentada como esta. Todo valor interpolado passa por
    str(): em Python 2 o decode() devolve unicode e misturar com literal acentuado
    levantaria UnicodeDecodeError."""
    total = len(transactions)
    answered = sum(1 for t in transactions if t["respondida"])
    lines = ["**Transações (%s)** — %d respondida(s) de %d" % (vs_label, answered, total), "",
             "| # | Tipo | STAN | Enviada | Resposta | RTT | Rastreio |",
             "|---|---|---|---|---|---|---|"]
    for number, t in enumerate(transactions, 1):
        if t["resposta"]:
            reply = "%s / %s" % (str(t["resposta"]), str(t["stan"]))
        else:
            reply = "sem resposta"
        rtt = "%d ms" % t["rtt_ms"] if t.get("rtt_ms") is not None else "-"
        lines.append("| %d | %s | %s | %s | %s | %s | %d/%d |" % (
            number, str(t["pedido"] or t["resposta"]), str(t["stan"] or "-"),
            str(t["hora"])[:12], reply, rtt, t["saltos"], EXPECTED_HOPS))
    lines.append("")
    kinds = {}
    for t in transactions:
        if t["pedido"] and t["resposta"]:
            label = "%s→%s" % (str(t["pedido"]), str(t["resposta"]))
        else:
            label = "%s→sem resposta" % str(t["pedido"] or t["resposta"])
        kinds[label] = kinds.get(label, 0) + 1
    mix = ", ".join("%d×%s" % (n, label) for label, n in sorted(kinds.items()))
    lines.append("- **Respondidas:** %d de %d (%s)" % (answered, total, mix))
    rtts = [t["rtt_ms"] for t in transactions if t.get("rtt_ms") is not None]
    if rtts:
        lines.append("- **RTT:** mín %d ms, média %d ms, máx %d ms" % (
            min(rtts), int(round(sum(rtts) / float(len(rtts)))), max(rtts)))
    complete = sum(1 for t in transactions if t["saltos"] >= EXPECTED_HOPS)
    lines.append("- **Rastreio:** %d de %d com os %d saltos (cliente→VS, F5→node, node→F5, "
                 "VS→cliente)" % (complete, total, EXPECTED_HOPS))
    return "\n".join(lines)


def _verdict(kept, summary, transactions, flows):
    if not kept:
        return "Nenhum tráfego da VS na janela capturada."
    if transactions:
        answered = sum(1 for t in transactions if t["respondida"])
        kinds = {}
        for t in transactions:
            # str(): em Python 2 o MTI sai de decode() como unicode, e misturar unicode
            # com o literal acentuado abaixo levantaria UnicodeDecodeError
            label = str(t["pedido"] or t["resposta"])
            kinds[label] = kinds.get(label, 0) + 1
        mix = ", ".join("%d×%s" % (n, mti) for mti, n in sorted(kinds.items()))
        return ("%d transação(ões) ISO 8583 na VS (%s): %d respondida(s), %d sem resposta."
                % (len(transactions), mix, answered, len(transactions) - answered))
    text = ("Tráfego da VS observado (%d pacotes em %d conexão(ões)), sem mensagens "
            "ISO 8583 reconhecidas." % (len(kept), flows))
    if summary["syn"] and not summary["syn_ack"]:
        text += " Houve SYN sem nenhum SYN-ACK: o destino não respondeu à abertura."
    return text


def simplified_view(packets, server_port=None, node_port=None, vs_addr=None,
                    detalhes=False, stan=None):
    """Veredito, contagens e transacoes so do trafego da VS. Com detalhes, cada transacao
    traz campos ISO, trajeto e RTT e a visao inclui tabela_markdown; stan restringe a
    transacoes com esse STAN. Devolve (visao, avisos)."""
    kept, info = focus_vs_traffic(packets, server_port, node_port, vs_addr)
    summary = summarize(kept)
    flows = set(_flow_key(p) for p in kept)
    transactions = build_transactions(kept, detail=detalhes)
    if stan is not None:
        transactions = [t for t in transactions if t["stan"] == stan]
    view = {
        "resultado": _verdict(kept, summary, transactions, len(flows)),
        "trafego": {
            "conexoes": len(flows),
            "pacotes": len(kept),
            "syn": summary["syn"],
            "syn_ack": summary["syn_ack"],
            "rst": summary["rst"] + summary["rst_ack"],
            "fin": summary["fin"],
            "mensagens_iso": sum(summary["mti_counts"].values()),
        },
        "transacoes": transactions[:MAX_TRANSACTIONS],
    }
    if len(transactions) > MAX_TRANSACTIONS:
        view["transacoes_omitidas"] = len(transactions) - MAX_TRANSACTIONS
    if stan is not None and not transactions:
        view["resultado"] = "Nenhuma transação com STAN %s na janela capturada." % stan
    if detalhes and transactions:
        if server_port is not None and vs_addr is not None:
            label = "VS %s:%d" % (vs_addr, server_port)
        elif server_port is not None:
            label = "VS, porta %d" % server_port
        else:
            label = "VS"
        view["tabela_markdown"] = render_details_markdown(view["transacoes"], label)

    notes = []
    if info["probe_flows"]:
        notes.append("%d sonda(s) do monitor do pool (%d pacotes) foram ignoradas: não são "
                     "tráfego da VS." % (info["probe_flows"], info["probe_packets"]))
    if info["other_flows"]:
        notes.append("%d conexão(ões) de outra(s) VS que dividem o IP da VS ou o node (%d "
                     "pacotes) foram ignoradas: não são da VS pedida." % (
                         info["other_flows"], info["other_packets"]))
    if not info["separated"] and kept:
        notes.append("Não foi possível separar o tráfego da VS do restante (informe vs_addr "
                     "junto de server_port, ou use portas de VS e de node diferentes): nada "
                     "foi descartado.")
    return view, notes


# ---------------------------------------------------------------------------
# Orquestracao
# ---------------------------------------------------------------------------

def _audit(request, response):
    if syslog is None:
        return
    try:
        syslog.openlog("f5_tcpdump", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_INFO, "request=%s status=%s" % (
            json.dumps(request, sort_keys=True, default=str), response.get("status")))
    except Exception:  # auditoria nunca pode derrubar a captura
        pass


def run(request, tcpdump_bin=None, lock_dir=None, proc_dir="/proc",
        guard_wait_sec=GUARD_WAIT_SEC, audit=True):
    """Valida, aplica a guarda de concorrencia, captura e devolve o resultado.
    Nunca levanta por causa do pedido: erros de politica viram `status` no dict."""
    try:
        response = _run(request, tcpdump_bin, lock_dir or LOCK_DIR, proc_dir, guard_wait_sec)
    except RequestError as exc:
        response = {"status": exc.status, "message": exc.message}
        response.update(exc.extra)
    except Exception as exc:  # falha inesperada: informa, nao derruba o chamador
        response = {"status": "error", "message": "%s: %s" % (type(exc).__name__, exc)}
    if audit:
        _audit(request, response)
    return response


def _run(request, tcpdump_bin, lock_dir, proc_dir, guard_wait_sec):
    params = validate_request(request)

    binary = tcpdump_bin or _find_tcpdump()
    if not binary:
        raise RequestError("error", "tcpdump não encontrado em: %s" % ", ".join(TCPDUMP_CANDIDATES))
    argv = build_argv(params, binary)

    guard = _open_guard(lock_dir, guard_wait_sec)
    if guard is None:
        raise _busy_error("várias")
    try:
        running = count_running_tcpdump(proc_dir)
        if running >= MAX_CONCURRENT_TCPDUMP:
            raise _busy_error(running)
        proc = _capture(argv)  # a guarda segue ate o tcpdump existir (visivel em /proc)
    finally:
        os.close(guard)

    out, err, status, timed_out = _wait_capture(proc, params["timeout_sec"])
    packets = parse_pcap(out)
    stderr_text = err.decode("utf-8", "replace")

    # 0 = terminou por -c; 124 = prazo duro (esperado com pouco trafego). Qualquer
    # outro codigo e falha do proprio tcpdump (interface inexistente, filtro...) e
    # nao pode virar "ok" com zero pacotes.
    if status not in (0, 124):
        raise RequestError(
            "error",
            "O tcpdump falhou (exit_status=%s): %s" % (
                status, stderr_text.strip()[-500:] or "sem stderr"),
            command=" ".join(argv), exit_status=status)

    warnings = []
    for line in stderr_text.splitlines():
        if TMM_WARNING_MARKER in line:
            warnings.append(
                "O F5 reportou concorrência de tcpdump acima do recomendado durante "
                "esta captura: %r. Considere aguardar ~%d minutos antes de rodar outra."
                % (line.strip(), BUSY_RETRY_MINUTES))

    if not params["verbose"]:
        view, notes = simplified_view(
            packets, server_port=params["server_port"], node_port=params["node_port"],
            vs_addr=params["vs_addr"], detalhes=params["detalhes"], stan=params["stan"])
        simple = {
            "status": "ok",
            "resultado": view["resultado"],
            "janela": {"max_s": params["timeout_sec"],
                       "encerrou_por": "prazo" if timed_out else "limite de pacotes"},
            "trafego": view["trafego"],
            "transacoes": view["transacoes"],
            "avisos": warnings + notes,
        }
        if "transacoes_omitidas" in view:
            simple["transacoes_omitidas"] = view["transacoes_omitidas"]
        if "tabela_markdown" in view:
            simple["tabela_markdown"] = view["tabela_markdown"]
        return simple

    return {
        "status": "ok",
        "command": " ".join(argv),
        "exit_status": status,
        "timed_out": timed_out,
        "summary": summarize(packets),
        "packets": packets[:MAX_PACKETS_RETURNED],
        "packet_count_truncated": len(packets) > MAX_PACKETS_RETURNED,
        "stderr": stderr_text,
        "warnings": warnings,
    }


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    raw = None
    if argv[:1] == ["--request"] and len(argv) >= 2:
        raw = argv[1]
    elif not argv:
        raw = sys.stdin.read()
    else:
        print(json.dumps({"status": "invalid",
                          "message": "Uso: f5_tcpdump.py [--request JSON]  (ou JSON no stdin)"}))
        return 2

    try:
        request = json.loads(raw)
    except ValueError as exc:
        print(json.dumps({"status": "invalid", "message": "JSON inválido: %s" % exc}))
        return 2

    print(json.dumps(run(request), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
