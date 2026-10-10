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
    payload_len: int = 0     # bytes de payload TCP (0 = segmento sem dados)

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
            "payload_len": self.payload_len,

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
        current.payload_len = len(tcp_payload) // 2
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


# ---------------------------------------------------------------------------
# Visão do usuário: só o tráfego da VS pedida + transações (resposta enxuta)
# ---------------------------------------------------------------------------
# ATENÇÃO: onbox/f5_tcpdump.py tem uma cópia desta lógica (o script no BIG-IP é um
# arquivo único, só stdlib, compatível com Python 2.7); onbox/test_f5_tcpdump.py
# confere a paridade das duas. Altere os dois juntos.

MAX_TRANSACTIONS = 50
# Fluxo do monitor do pool (tcp_half_open): só SYN / SYN-ACK / RST, sem handshake
# completo, sem dados.
_PROBE_LABELS = frozenset(("SYN", "SYN-ACK", "RST", "RST-ACK"))


def _endpoint_parts(endpoint: str) -> tuple[str, int | None]:
    host, _, port = endpoint.rpartition(".")
    if host and port.isdigit():
        return host, int(port)
    return endpoint, None


def _flow_key(pkt: dict) -> tuple:
    return tuple(sorted((pkt["src"], pkt["dst"])))


def focus_vs_traffic(
    packets: list[dict],
    server_port: int | None = None,
    node_port: int | None = None,
    vs_addr: str | None = None,
) -> tuple[list[dict], dict]:
    """Mantém só o tráfego da VS pedida (o lado cliente e as pernas do node das
    conexões dela) e descarta os fluxos do monitor do pool — SYN/SYN-ACK/RST sem dados
    e sem handshake completo no lado do node, que não são conexões da aplicação.

    Só descarta quando o lado da VS é identificável: `vs_addr` + `server_port`, ou
    `server_port` diferente de `node_port`. Sem isso (ex: só a porta do node) nada é
    descartado. Devolve (pacotes mantidos, info)."""
    info = {"separated": False, "probe_flows": 0, "probe_packets": 0}
    if server_port is not None and vs_addr is not None:
        vs_endpoint = f"{vs_addr}.{server_port}"

        def is_vs_side(pkt: dict) -> bool:
            return vs_endpoint in (pkt["src"], pkt["dst"])
    elif server_port is not None and node_port is not None and server_port != node_port:
        def is_vs_side(pkt: dict) -> bool:
            return server_port in (_endpoint_parts(pkt["src"])[1],
                                   _endpoint_parts(pkt["dst"])[1])
    else:
        return list(packets), info

    info["separated"] = True
    flows: dict[tuple, list[dict]] = {}
    for pkt in packets:
        flows.setdefault(_flow_key(pkt), []).append(pkt)

    keep = set()
    for key, pkts in flows.items():
        probe = (
            not any(is_vs_side(p) for p in pkts)
            and all(p.get("payload_len", 0) == 0 and not p.get("mti")
                    and p["flags_label"] in _PROBE_LABELS for p in pkts)
        )
        if probe:
            info["probe_flows"] += 1
            info["probe_packets"] += len(pkts)
        else:
            keep.add(key)
    return [p for p in packets if _flow_key(p) in keep], info


def _is_response_mti(mti: str) -> bool:
    return len(mti) == 4 and mti[2] in "13"


ISO_BIT_FIELDS = ("bit7", "bit11", "bit32", "bit37", "bit70", "bit100", "bit127")
EXPECTED_HOPS = 4   # cliente→VS, F5→node, node→F5, VS→cliente


def _seconds(stamp: str) -> float | None:
    """'HH:MM:SS.ffffff' -> segundos desde 00:00 (None se o formato não bater)."""
    try:
        hh, mm, ss = stamp.split(":")
        return int(hh) * 3600 + int(mm) * 60 + float(ss)
    except (ValueError, AttributeError):
        return None


def build_transactions(packets: list[dict], detail: bool = False) -> list[dict]:
    """Agrupa as mensagens ISO 8583 em transações (pedido + resposta), pelo STAN
    (bit 11). A mesma mensagem aparece em vários saltos (cliente→VS, F5→node...): conta
    uma vez. Com `detail`, cada transação ganha `campos` (bits ISO), `trajeto` (os
    saltos, em ordem), `saltos` (quantos) e `rtt_ms` (do pedido à resposta)."""
    order: list[tuple] = []
    groups: dict[tuple, dict] = {}
    for pkt in packets:
        mti = pkt.get("mti")
        if not mti:
            continue
        stan = pkt.get("bit11")
        if stan:
            key = ("stan", stan)
        else:  # sem STAN: agrupa por conexão + par pedido/resposta
            key = ("flow", _flow_key(pkt), mti[:2] + mti[3:])
        group = groups.get(key)
        if group is None:
            group = {"hora": pkt["time"], "stan": stan, "pedido": None, "resposta": None,
                     "tipo": None, "origem": None}
            if detail:
                group.update(campos={b: pkt.get(b) for b in ISO_BIT_FIELDS}, trajeto=[],
                             _req=None, _resp=None)
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
                    group["_resp"] = moment      # a ÚLTIMA resposta (VS→cliente)
                elif group["_req"] is None:
                    group["_req"] = moment       # o PRIMEIRO pedido (cliente→VS)
    out = []
    for key in order:
        group = groups[key]
        group["respondida"] = group["resposta"] is not None
        if detail:
            req, resp = group.pop("_req"), group.pop("_resp")
            group["saltos"] = len(group["trajeto"])
            group["rtt_ms"] = (round((resp - req) * 1000)
                               if req is not None and resp is not None and resp >= req
                               else None)
        out.append(group)
    return out


def render_details_markdown(transactions: list[dict], vs_label: str) -> str:
    """Tabela no padrão pedido pelo usuário (# | Tipo | STAN | Enviada | Resposta | RTT |
    Rastreio) + observações — pronta para ser apresentada como está."""
    total = len(transactions)
    answered = sum(1 for t in transactions if t["respondida"])
    lines = [f"**Transações ({vs_label})** — {answered} respondida(s) de {total}", "",
             "| # | Tipo | STAN | Enviada | Resposta | RTT | Rastreio |",
             "|---|---|---|---|---|---|---|"]
    for number, t in enumerate(transactions, 1):
        reply = f"{t['resposta']} / {t['stan']}" if t["resposta"] else "sem resposta"
        rtt = f"{t['rtt_ms']:.0f} ms" if t.get("rtt_ms") is not None else "-"
        lines.append("| %d | %s | %s | %s | %s | %s | %d/%d |" % (
            number, t["pedido"] or t["resposta"], t["stan"] or "-", t["hora"][:12], reply,
            rtt, t["saltos"], EXPECTED_HOPS))
    lines.append("")
    kinds: dict[str, int] = {}
    for t in transactions:
        label = (f"{t['pedido']}→{t['resposta']}" if t["pedido"] and t["resposta"]
                 else f"{t['pedido'] or t['resposta']}→sem resposta")
        kinds[label] = kinds.get(label, 0) + 1
    mix = ", ".join(f"{n}×{label}" for label, n in sorted(kinds.items()))
    lines.append(f"- **Respondidas:** {answered} de {total} ({mix})")
    rtts = [t["rtt_ms"] for t in transactions if t.get("rtt_ms") is not None]
    if rtts:
        lines.append(f"- **RTT:** mín {min(rtts):.0f} ms, média "
                     f"{sum(rtts) / len(rtts):.0f} ms, máx {max(rtts):.0f} ms")
    complete = sum(1 for t in transactions if t["saltos"] >= EXPECTED_HOPS)
    lines.append(f"- **Rastreio:** {complete} de {total} com os {EXPECTED_HOPS} saltos "
                 "(cliente→VS, F5→node, node→F5, VS→cliente)")
    return "\n".join(lines)


def _verdict(kept: list[dict], summary: dict, transactions: list[dict], flows: int) -> str:
    if not kept:
        return "Nenhum tráfego da VS na janela capturada."
    if transactions:
        answered = sum(1 for t in transactions if t["respondida"])
        kinds: dict[str, int] = {}
        for t in transactions:
            label = t["pedido"] or t["resposta"]
            kinds[label] = kinds.get(label, 0) + 1
        mix = ", ".join(f"{n}×{mti}" for mti, n in sorted(kinds.items()))
        return (f"{len(transactions)} transação(ões) ISO 8583 na VS ({mix}): "
                f"{answered} respondida(s), {len(transactions) - answered} sem resposta.")
    text = (f"Tráfego da VS observado ({len(kept)} pacotes em {flows} conexão(ões)), "
            "sem mensagens ISO 8583 reconhecidas.")
    if summary["syn"] and not summary["syn_ack"]:
        text += " Houve SYN sem nenhum SYN-ACK: o destino não respondeu à abertura."
    return text


def simplified_view(
    packets: list[dict],
    server_port: int | None = None,
    node_port: int | None = None,
    vs_addr: str | None = None,
    detalhes: bool = False,
    stan: str | None = None,
) -> tuple[dict, list[str]]:
    """Resposta enxuta para o usuário: veredito, contagens e transações — só do tráfego
    da VS pedida. Com `detalhes`, cada transação traz campos ISO, trajeto e RTT e a
    visão inclui `tabela_markdown`; `stan` restringe às transações com esse STAN.
    Devolve (visão, avisos sobre o foco aplicado)."""
    kept, info = focus_vs_traffic(packets, server_port, node_port, vs_addr)
    summary = summarize(kept)
    flows = {_flow_key(p) for p in kept}
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
        view["resultado"] = f"Nenhuma transação com STAN {stan} na janela capturada."
    if detalhes and transactions:
        if server_port is not None and vs_addr is not None:
            label = f"VS {vs_addr}:{server_port}"
        elif server_port is not None:
            label = f"VS, porta {server_port}"
        else:
            label = "VS"
        view["tabela_markdown"] = render_details_markdown(view["transacoes"], label)

    notes = []
    if info["probe_flows"]:
        notes.append(
            f"{info['probe_flows']} sonda(s) do monitor do pool "
            f"({info['probe_packets']} pacotes) foram ignoradas: não são tráfego da VS.")
    if not info["separated"] and kept:
        notes.append(
            "Não foi possível separar o tráfego da VS do restante (informe vs_addr junto "
            "de server_port, ou use portas de VS e de node diferentes): nada foi "
            "descartado.")
    return view, notes


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
