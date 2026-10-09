"""Parser de saída texto do `tcpdump -nn -X` (sem gravar .pcap).

Extrai, por pacote:
  - timestamp, IP/porta de origem e destino
  - classificação de flags TCP (SYN, SYN-ACK, RST, RST-ACK, ACK, PSH-ACK, FIN...)
  - campos ISO 8583 do payload TCP: MTI e os bits 7, 11, 32, 37, 70, 100 e 127,
    além da classificação de Echo-test / Sign-on / Sign-off pelo bit 70 (NMIC)

O dump do `tcpdump -X` começa no cabeçalho IP, mas os offsets ISO 8583 (copiados da
iRule do cliente, `substr $payloadhex 14 8`) são relativos ao payload TCP — por isso os
cabeçalhos IP/TCP são removidos antes de aplicar os offsets (ver _tcp_payload_hex).

Isso é só parsing de texto — nenhuma chamada de rede acontece aqui.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

HEADER_RE = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP6?\s+"
    r"(?P<src>[^\s]+)\s+>\s+(?P<dst>[^\s]+):\s+(?P<rest>.*)$"
)
FLAGS_RE = re.compile(r"Flags\s+\[(?P<flags>[^\]]*)\]")
# Os grupos de hex do tcpdump -X vêm separados por espaço simples ("4500 0034 ..."),
# então o espaço PRECISA fazer parte da classe do grupo `hex`.
HEXLINE_RE = re.compile(
    r"^\s*0x[0-9a-fA-F]+:\s+(?P<hex>[0-9a-fA-F ]+?)\s{2,}(?P<ascii>.*)$"
)

FLAG_LABELS = {
    "S": "SYN",
    "S.": "SYN-ACK",
    ".": "ACK",
    "P.": "PSH-ACK",
    "R": "RST",
    "R.": "RST-ACK",
    "F": "FIN",
    "F.": "FIN-ACK",
    "SEC": "SYN-ECN",
}

# Descrição das mensagens ISO 8583 pelo MTI (4 dígitos ASCII no início da mensagem).
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

# Bit 70 (Network Management Information Code).
NETWORK_CODE_MAP = {
    "001": "Sign-On",
    "002": "Sign-Off",
    "301": "Echo Test",
}

# Offsets em caracteres HEX, relativos ao início do PAYLOAD TCP (não do pacote IP).
# Equivalem ao `substr $payloadhex <offset> <len>` da iRule do cliente:
#   MTI    -> substr $payloadhex 14 8   (4 chars ASCII = 8 hex)
# ATENÇÃO: os offsets dos bits (86..188) ainda NÃO foram validados contra uma captura
# real de ISO 8583 do cliente — confirme com um dump real antes de confiar nos valores.
MTI_OFFSET = 14
MTI_HEX_LEN = 8
ISO_FIELD_SLICES = {
    "bit7": (86, 106),    # data/hora de transmissão MMDDhhmmss (10 chars)
    "bit11": (106, 118),  # STAN (6 chars)
    "bit32": (118, 130),  # institution id (6 chars)
    "bit37": (130, 154),  # RRN / NSU (12 chars)
    "bit70": (154, 160),  # network management code (3 chars)
    "bit100": (160, 170),  # receiving institution id (5 chars)
    "bit127": (170, 188),  # campo privado (9 chars)
}
ISO_MIN_HEX_LEN = 188

# Heurística legada: quando o MTI estruturado não pôde ser extraído, procura os tokens
# "0800"/"0810" no ASCII do payload TCP (nunca nos cabeçalhos IP/TCP).
LEGACY_MARKERS = {
    "request_0800": "0800",
    "response_0810": "0810",
}


@dataclass
class ParsedPacket:
    time: str
    src: str
    dst: str

    flags_raw: str
    flags_label: str

    payload_ascii: str = ""
    payload_hex: str = ""

    mti: str | None = None

    bit7: str | None = None
    bit11: str | None = None
    bit32: str | None = None
    bit37: str | None = None
    bit70: str | None = None
    bit70_desc: str | None = None
    bit100: str | None = None
    bit127: str | None = None

    is_echo_test: bool = False
    is_signon: bool = False
    is_signoff: bool = False

    markers_found: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "time": self.time,
            "src": self.src,
            "dst": self.dst,

            "flags": self.flags_raw,
            "flags_label": self.flags_label,

            "mti": self.mti,

            "bit7": self.bit7,
            "bit11": self.bit11,
            "bit32": self.bit32,
            "bit37": self.bit37,
            "bit70": self.bit70,
            "bit70_desc": self.bit70_desc,
            "bit100": self.bit100,
            "bit127": self.bit127,

            "is_echo_test": self.is_echo_test,
            "is_signon": self.is_signon,
            "is_signoff": self.is_signoff,

            "markers_found": self.markers_found,

            "payload_ascii_preview": self.payload_ascii[:200],
        }


def _classify_flags(flags_raw: str) -> str:
    return FLAG_LABELS.get(flags_raw, flags_raw or "UNKNOWN")


def _compact_hex(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value or "")


def _hex_to_ascii(value: str) -> str | None:
    if not value:
        return None

    try:
        text = bytes.fromhex(value).decode("ascii", errors="ignore").strip()
    except ValueError:
        return None
    return text or None


def _tcp_payload_hex(packet_hex: str) -> str:
    """Remove os cabeçalhos IP e TCP do dump hex do `tcpdump -X` e devolve só o
    payload TCP (em hex, sem espaços). Devolve "" se não for um segmento TCP
    bem-formado/capturado por completo — nesse caso não há o que parsear."""
    h = _compact_hex(packet_hex)
    if len(h) < 2:
        return ""

    version = int(h[0], 16)
    if version == 4:
        ihl = int(h[1], 16) * 4
        if ihl < 20 or len(h) < (ihl + 20) * 2:
            return ""
        if int(h[18:20], 16) != 6:  # byte 9 = protocolo; 6 = TCP
            return ""
        total_len = int(h[4:8], 16)
        if total_len * 2 <= len(h):
            h = h[: total_len * 2]  # descarta padding/trailer de camada 2
        tcp_start = ihl * 2
    elif version == 6:
        if len(h) < (40 + 20) * 2:
            return ""
        if int(h[12:14], 16) != 6:  # byte 6 = next header; 6 = TCP (sem ext. headers)
            return ""
        total_len = 40 + int(h[8:12], 16)
        if total_len * 2 <= len(h):
            h = h[: total_len * 2]
        tcp_start = 40 * 2
    else:
        return ""

    data_offset = int(h[tcp_start + 24], 16) * 4  # nibble alto do byte 12 do TCP
    if data_offset < 20 or len(h) < tcp_start + data_offset * 2:
        return ""
    return h[tcp_start + data_offset * 2:]


def _extract_mti(tcp_payload_hex: str) -> str | None:
    """MTI = 4 dígitos ASCII no offset 14 (8 hex) do payload TCP.

    Parsing equivalente ao da iRule: `set cod [substr $payloadhex 14 8]`."""
    h = _compact_hex(tcp_payload_hex)
    end = MTI_OFFSET + MTI_HEX_LEN
    if len(h) < end:
        return None

    mti = _hex_to_ascii(h[MTI_OFFSET:end])
    if mti and re.fullmatch(r"\d{4}", mti):
        return mti
    return None


def _extract_iso_fields(tcp_payload_hex: str) -> dict:
    h = _compact_hex(tcp_payload_hex)

    result = {name: None for name in ISO_FIELD_SLICES}
    result["bit70_desc"] = None

    if len(h) < ISO_MIN_HEX_LEN:
        return result

    for name, (start, end) in ISO_FIELD_SLICES.items():
        result[name] = _hex_to_ascii(h[start:end])

    if result["bit70"]:
        result["bit70_desc"] = NETWORK_CODE_MAP.get(result["bit70"])

    return result


def _find_markers(
    mti: str | None,
    bit70: str | None,
    bit70_desc: str | None,
    tcp_payload_hex: str = "",
) -> list:
    markers = []

    if mti:
        markers.append(f"MTI:{mti}")
        description = MTI_DESCRIPTIONS.get(mti)
        if description:
            markers.append(description)
        if bit70:
            markers.append(f"NMIC:{bit70}")
        if bit70_desc:
            markers.append(bit70_desc)
        return markers

    # MTI estruturado não encontrado — heurística legada, só no payload TCP.
    ascii_payload = _hex_to_ascii(_compact_hex(tcp_payload_hex)) or ""
    for label, token in LEGACY_MARKERS.items():
        if token in ascii_payload:
            markers.append(f"{label}(ascii)")
    return markers


def parse_tcpdump_output(raw_output: str) -> list[dict]:
    lines = raw_output.splitlines()
    packets: list[dict] = []
    current: ParsedPacket | None = None
    current_ascii_parts: list[str] = []
    current_hex_parts: list[str] = []

    def flush():
        if current is None:
            return

        current.payload_ascii = "".join(current_ascii_parts)
        current.payload_hex = " ".join(current_hex_parts)

        tcp_payload = _tcp_payload_hex(current.payload_hex)
        current.mti = _extract_mti(tcp_payload)

        # Só extrai os bits se o MTI confirmou que é uma mensagem ISO 8583 — senão
        # estaríamos fatiando bytes aleatórios (ex: SSH) em "campos".
        if current.mti:
            iso = _extract_iso_fields(tcp_payload)
            current.bit7 = iso["bit7"]
            current.bit11 = iso["bit11"]
            current.bit32 = iso["bit32"]
            current.bit37 = iso["bit37"]
            current.bit70 = iso["bit70"]
            current.bit70_desc = iso["bit70_desc"]
            current.bit100 = iso["bit100"]
            current.bit127 = iso["bit127"]
            current.is_echo_test = current.bit70 == "301"
            current.is_signon = current.bit70 == "001"
            current.is_signoff = current.bit70 == "002"

        current.markers_found = _find_markers(
            current.mti, current.bit70, current.bit70_desc, tcp_payload
        )
        packets.append(current.to_dict())

    for line in lines:
        header_match = HEADER_RE.match(line)
        if header_match:
            flush()
            current_ascii_parts = []
            current_hex_parts = []

            rest = header_match.group("rest")
            flags_match = FLAGS_RE.search(rest)
            flags_raw = flags_match.group("flags") if flags_match else ""

            current = ParsedPacket(
                time=header_match.group("time"),
                src=header_match.group("src"),
                dst=header_match.group("dst"),
                flags_raw=flags_raw,
                flags_label=_classify_flags(flags_raw),
            )
            continue

        hex_match = HEXLINE_RE.match(line)
        if hex_match and current is not None:
            current_ascii_parts.append(hex_match.group("ascii"))
            current_hex_parts.append(hex_match.group("hex"))

    flush()
    return packets


def summarize(packets: list[dict]) -> dict:
    summary = {
        "total_packets": len(packets),

        "syn": 0,
        "syn_ack": 0,
        "rst": 0,
        "rst_ack": 0,
        "ack_only": 0,
        "psh_ack": 0,
        "fin": 0,
        "other": 0,

        # contagens por MTI / bit 70 (ISO 8583)
        "mti_counts": {},
        "network_codes": {},

        "echo_tests": 0,
        "signon": 0,
        "signoff": 0,

        # compatibilidade com o formato anterior (marcadores 0800/0810)
        "request_0800_count": 0,
        "response_0810_count": 0,
    }
    counters = {
        "SYN": "syn", "SYN-ACK": "syn_ack", "RST": "rst", "RST-ACK": "rst_ack",
        "ACK": "ack_only", "PSH-ACK": "psh_ack", "FIN": "fin", "FIN-ACK": "fin",
    }
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


if __name__ == "__main__":
    # Uso manual: python -m src.tcpdump_parser [arquivo_com_saida_do_tcpdump]
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "tcpdump.txt"
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    parsed = parse_tcpdump_output(raw)

    for pkt in parsed:
        if pkt["mti"]:
            print(
                f"[{pkt['time']}] "
                f"[{pkt['src']}] -> {pkt['dst']} "
                f"MTI={pkt['mti']} "
                f"BIT70={pkt['bit70']} "
                f"({pkt['bit70_desc']}) "
                f"STAN={pkt['bit11']} "
                f"NSU={pkt['bit37']}"
            )

    print()
    print(summarize(parsed))
