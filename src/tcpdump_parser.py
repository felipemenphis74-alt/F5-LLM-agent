"""Parser de saída texto do `tcpdump -nn -X` (sem gravar .pcap).

Extrai, por pacote:
  - timestamp, IP/porta de origem e destino
  - classificação de flags TCP (SYN, SYN-ACK, RST, RST-ACK, ACK, PSH-ACK, FIN...)
  - se o payload contém os marcadores textuais "0800" (request) / "0810" (resposta)
    — heurística para handshakes tipo ISO8583; ajuste FLAG_MARKERS se o protocolo do
    cliente usar outra convenção.

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

# Marcadores procurados no payload (texto ASCII decodificado da captura).
# Ajuste aqui se o protocolo monitorado usar outro esquema de request/response.
PAYLOAD_MARKERS = {
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
    markers_found: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "time": self.time,
            "src": self.src,
            "dst": self.dst,
            "flags": self.flags_raw,
            "flags_label": self.flags_label,
            "markers_found": self.markers_found,
            "payload_ascii_preview": self.payload_ascii[:200],
        }


def _classify_flags(flags_raw: str) -> str:
    return FLAG_LABELS.get(flags_raw, flags_raw or "UNKNOWN")


def _find_markers(ascii_payload: str, hex_payload: str) -> list:
    found = []
    hex_compact = hex_payload.replace(" ", "").lower()
    for label, marker in PAYLOAD_MARKERS.items():
        if marker in ascii_payload:
            found.append(f"{label}(ascii)")
        elif marker.lower() in hex_compact:
            found.append(f"{label}(hex-bytes)")
    return found


def parse_tcpdump_output(raw_output: str) -> list[dict]:
    lines = raw_output.splitlines()
    packets: list[ParsedPacket] = []
    current: ParsedPacket | None = None
    current_ascii_parts: list[str] = []
    current_hex_parts: list[str] = []

    def flush():
        if current is not None:
            current.payload_ascii = "".join(current_ascii_parts)
            current.payload_hex = " ".join(current_hex_parts)
            current.markers_found = _find_markers(current.payload_ascii, current.payload_hex)
            packets.append(current)

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
    return [p.to_dict() for p in packets]


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
        "request_0800_count": 0,
        "response_0810_count": 0,
    }
    counters = {
        "SYN": "syn", "SYN-ACK": "syn_ack", "RST": "rst", "RST-ACK": "rst_ack",
        "ACK": "ack_only", "PSH-ACK": "psh_ack", "FIN": "fin", "FIN-ACK": "fin",
    }
    for pkt in packets:
        key = counters.get(pkt["flags_label"], "other")
        summary[key] += 1
        for marker in pkt["markers_found"]:
            if marker.startswith("request_0800"):
                summary["request_0800_count"] += 1
            elif marker.startswith("response_0810"):
                summary["response_0810_count"] += 1
    return summary
