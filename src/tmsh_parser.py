"""Parsing best-effort da saída texto do tmsh (`list`/`show`).

A formatação exata do tmsh varia um pouco por versão de TMOS. Estas funções cobrem os
formatos mais comuns, mas sempre devolvem também o texto bruto (`raw`) para conferência
manual — trate os campos estruturados como "melhor esforço", não como garantia.
"""
from __future__ import annotations

import re
import unicodedata

VS_BLOCK_RE = re.compile(
    r"ltm virtual (?P<name>\S+)\s*\{(?P<body>.*?)\n\}", re.DOTALL
)
DESTINATION_RE = re.compile(r"destination\s+(?:/\S+/)?(?P<addr>\S+)")
POOL_RE = re.compile(r"^\s*pool\s+(?P<pool>\S+)", re.MULTILINE)
DESCRIPTION_RE = re.compile(r'^\s*description\s+(?:"(?P<quoted>[^"]*)"|(?P<word>\S+))', re.MULTILINE)
# `tmsh show ltm virtual <vs>` traz o destino com a porta NUMÉRICA ("10.100.1.10:15000");
# o `list` pode trazer o nome do serviço ("10.100.1.10:hydap"), sem porta utilizável.
SHOW_DESTINATION_RE = re.compile(r"Destination\s*:\s*(?:/\S+/)?(?P<addr>\S+)")
POOL_LIST_BLOCK_RE = re.compile(r"ltm pool (?P<name>\S+)\s*\{(?P<body>.*?)\n\}", re.DOTALL)
POOL_LIST_MEMBER_RE = re.compile(
    r"(?P<key>\S+):(?P<service>[\w-]+)\s*\{\s*address\s+(?P<addr>[\d.a-fA-F:]+)"
)
STATUS_LINE_RE = re.compile(r"Availability\s*:\s*(?P<avail>\S+)")

POOL_MEMBER_RE = re.compile(
    r"Ltm::Pool Member:\s*(?P<member>\S+):(?P<port>\d+)"
    r"(?P<body>.*?)(?=Ltm::Pool Member:|\Z)",
    re.DOTALL,
)
# Extrai o IPv4 de dentro do identificador do member — que pode ser um IP puro
# ("10.2.2.11") ou um node NOMEADO ("node_app_10.100.2.1"), formato comum quando
# o BIG-IP usa nodes com nome em vez de nodes anônimos por IP.
MEMBER_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
MEMBER_AVAIL_RE = re.compile(r"Availability\s*:\s*(?P<avail>[\w-]+)")
MEMBER_STATE_RE = re.compile(r"State\s*:\s*(?P<state>[\w-]+)")
MEMBER_REASON_RE = re.compile(r"Reason\s*:\s*(?P<reason>.+)")

# Propriedades da VS no `list` (só o que descreve a VS; nada do dispositivo).
IP_PROTOCOL_RE = re.compile(r"^\s*ip-protocol\s+(?P<proto>\S+)", re.MULTILINE)
DISABLED_RE = re.compile(r"^\s*disabled\s*$", re.MULTILINE)
SNAT_RE = re.compile(
    r"source-address-translation\s*\{(?P<body>.*?)\}", re.DOTALL)
SNAT_TYPE_RE = re.compile(r"\btype\s+(?P<type>\S+)")
SNAT_POOL_RE = re.compile(r"\bpool\s+(?P<pool>\S+)")
# sub-blocos de primeiro nivel da VS (indentados com 4 espacos no `list`)
def _sub_block(body: str, name: str) -> str:
    match = re.search(rf"^ {{4}}{name} \{{\n(?P<inner>.*?)^ {{4}}\}}", body,
                      re.DOTALL | re.MULTILINE)
    return match.group("inner") if match else ""


def _strip_partition(name: str) -> str:
    return name[len("/Common/"):] if name.startswith("/Common/") else name


def parse_virtual_servers(list_output: str) -> list[dict]:
    """Parseia a saída de `tmsh list ltm virtual [...]`."""
    results = []
    for match in VS_BLOCK_RE.finditer(list_output):
        name = match.group("name")
        body = match.group("body")
        dest_match = DESTINATION_RE.search(body)
        pool_match = POOL_RE.search(body)
        desc_match = DESCRIPTION_RE.search(body)

        addr, port = None, None
        if dest_match:
            addr_full = dest_match.group("addr")
            if ":" in addr_full:
                addr, _, port = addr_full.rpartition(":")
            else:
                addr = addr_full

        proto_match = IP_PROTOCOL_RE.search(body)
        snat_match = SNAT_RE.search(body)
        snat = None
        if snat_match:
            type_match = SNAT_TYPE_RE.search(snat_match.group("body"))
            pool_snat = SNAT_POOL_RE.search(snat_match.group("body"))
            snat = {"type": type_match.group("type") if type_match else None}
            if pool_snat:
                snat["pool"] = _strip_partition(pool_snat.group("pool"))
        profiles = [_strip_partition(m.group(1)) for m in
                    re.finditer(r"^\s{8}(\S+)\s*\{", _sub_block(body, "profiles"), re.MULTILINE)]
        persistence = [_strip_partition(m.group(1)) for m in
                       re.finditer(r"^\s{8}(\S+)\s*\{", _sub_block(body, "persist"), re.MULTILINE)]
        rules = [_strip_partition(line.strip()) for line in
                 _sub_block(body, "rules").splitlines() if line.strip()]

        results.append({
            "vs_name": name,
            "address": addr,
            "port": int(port) if port and port.isdigit() else None,
            # destino com nome de serviço ("hydap"): sem porta numérica no `list`
            "service": port if port and not port.isdigit() else None,
            "pool_name": pool_match.group("pool") if pool_match else None,
            "description": (desc_match.group("quoted") if desc_match.group("quoted") is not None
                            else desc_match.group("word")) if desc_match else None,
            "ip_protocol": proto_match.group("proto") if proto_match else None,
            "enabled": not DISABLED_RE.search(body),
            "profiles": profiles,
            "persistence": persistence,
            "snat": snat,
            "rules": rules,
        })

    if not results:
        # fallback: nenhum bloco reconhecido — devolve vazio, chamador deve olhar o raw
        return []
    return results


def parse_pool_members(show_output: str) -> list[dict]:
    """Parseia a saída de `tmsh show ltm pool <name> members detail`."""
    members = []
    for match in POOL_MEMBER_RE.finditer(show_output):
        body = match.group("body")
        member_raw = match.group("member")
        ip_match = MEMBER_IP_RE.search(member_raw)
        avail_match = MEMBER_AVAIL_RE.search(body)
        state_match = MEMBER_STATE_RE.search(body)
        members.append({
            "address": ip_match.group(0) if ip_match else member_raw,
            "node_name": member_raw,
            "port": int(match.group("port")),
            "availability": avail_match.group("avail") if avail_match else None,
            "state": state_match.group("state") if state_match else None,
        })
    return members


VS_STATUS_SPLIT_RE = re.compile(r"^Ltm::Virtual Server:\s*(\S+)\s*$", re.MULTILINE)
POOL_STATUS_SPLIT_RE = re.compile(r"Ltm::Pool Member:")


def _first(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None


def _number(value: str | None):
    """"12" -> 12; "8.8K" fica texto (formato do tmsh)."""
    return int(value) if value is not None and value.isdigit() else value


def parse_vs_status(show_output: str) -> list[dict]:
    """Status de cada VS em `tmsh show ltm virtual [<vs>]`: disponibilidade, estado,
    motivo, destino e contadores. Só campos da própria VS — o resto da saída (CMP, PVA,
    contadores internos...) é descartado de propósito."""
    parts = VS_STATUS_SPLIT_RE.split(show_output)
    results = []
    for name, body in zip(parts[1::2], parts[2::2]):
        addr, port = parse_vs_destination(body)
        results.append({
            "vs_name": name,
            "availability": _first(r"Availability\s*:\s*(\S+)", body),
            "state": _first(r"State\s*:\s*(\S+)", body),
            "reason": _first(r"Reason\s*:\s*(.+)", body),
            "destination": f"{addr}:{port}" if addr and port else None,
            "connections": {
                "current": _number(_first(r"Current Connections\s+(\S+)", body)),
                "max": _number(_first(r"Maximum Connections\s+(\S+)", body)),
                "total": _number(_first(r"Total Connections\s+(\S+)", body)),
            },
            "traffic": {
                "bits_in": _first(r"Bits In\s+(\S+)", body),
                "bits_out": _first(r"Bits Out\s+(\S+)", body),
                "packets_in": _first(r"Packets In\s+(\S+)", body),
                "packets_out": _first(r"Packets Out\s+(\S+)", body),
            },
        })
    return results


def parse_pool_status(show_output: str) -> dict:
    """Status do pool e de cada member em `tmsh show ltm pool <p> members detail`:
    disponibilidade/estado/motivo — sem nomes internos de objetos nem contadores."""
    head = POOL_STATUS_SPLIT_RE.split(show_output, maxsplit=1)[0]
    members = []
    for match in POOL_MEMBER_RE.finditer(show_output):
        body = match.group("body")
        member_raw = match.group("member")
        ip_match = MEMBER_IP_RE.search(member_raw)
        reason = MEMBER_REASON_RE.search(body)
        avail = MEMBER_AVAIL_RE.search(body)
        state = MEMBER_STATE_RE.search(body)
        members.append({
            "address": ip_match.group(0) if ip_match else member_raw,
            "port": int(match.group("port")),
            "availability": avail.group("avail") if avail else None,
            "state": state.group("state") if state else None,
            "reason": reason.group("reason").strip() if reason else None,
        })
    return {
        "availability": _first(r"Availability\s*:\s*(\S+)", head),
        "state": _first(r"State\s*:\s*(\S+)", head),
        "reason": _first(r"Reason\s*:\s*(.+)", head),
        "members": members,
    }


SYS_CONNECTION_RE = re.compile(
    r"^(?P<client>\S+:\S+)\s+(?P<vs>\S+:\S+)\s+(?P<snat>\S+:\S+)\s+(?P<node>\S+:\S+)\s+"
    r"(?P<proto>\w+)\s+(?P<idle>\d+)\b", re.MULTILINE)


def parse_sys_connections(show_output: str) -> list[dict]:
    """Linhas de `tmsh show sys connection`: cliente, VS, endereço do F5 no lado do
    node (SNAT), node, protocolo e ociosidade. Campos internos (TMM, flags) ficam de
    fora."""
    return [
        {"client": m.group("client"), "virtual_server": m.group("vs"),
         "snat": m.group("snat"), "node": m.group("node"),
         "protocol": m.group("proto"), "idle_s": int(m.group("idle"))}
        for m in SYS_CONNECTION_RE.finditer(show_output)
    ]


def parse_vs_destination(show_output: str) -> tuple[str | None, int | None]:
    """Endereço e porta NUMÉRICA do destino de uma VS, a partir de
    `tmsh show ltm virtual <vs>` (o `list` pode trazer nome de serviço no lugar
    da porta). Devolve (None, None) se não reconhecer."""
    match = SHOW_DESTINATION_RE.search(show_output)
    if not match:
        return None, None
    addr, sep, port = match.group("addr").rpartition(":")
    if not sep or not port.isdigit():
        return None, None
    return addr, int(port)


def parse_pool_list_members(list_output: str) -> dict[str, list[dict]]:
    """Parseia `tmsh list ltm pool` (todos os pools) em
    {pool: [{"node", "address", "service"}]}.

    `address` é o IP real do node (o `show` só traz o nome, que pode não conter IP).
    `service` é a porta como o `list` escreve — número ou nome ("hydap"): serve para
    comparar members ENTRE pools da mesma saída (mesma notação nos dois lados), não
    para obter a porta numérica."""
    pools = {}
    for block in POOL_LIST_BLOCK_RE.finditer(list_output):
        pools[block.group("name")] = [
            {"node": m.group("key").rsplit("/", 1)[-1], "address": m.group("addr"),
             "service": m.group("service")}
            for m in POOL_LIST_MEMBER_RE.finditer(block.group("body"))
        ]
    return pools


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).casefold()
    return re.sub(r"[\s_\-./\"']+", " ", text).strip()


def match_virtual_servers(virtual_servers: list[dict], connection: str) -> list[dict]:
    """VS que correspondem ao nome de conexão pedido pelo usuário.

    Um nome de VS idêntico ao pedido ganha sozinho. Senão, a VS corresponde se TODAS
    as palavras do pedido aparecem no nome, na descrição ou no pool dela (sem
    diferenciar maiúsculas/acentos/separadores) — "padaria do zezinho" acha a VS de
    descrição "parceiro - Padaria do zezinho". Pedido vazio não corresponde a nada."""
    wanted = _normalize(connection)
    if not wanted:
        return []
    exact = [vs for vs in virtual_servers if _normalize(vs["vs_name"]) == wanted]
    if exact:
        return exact
    tokens = wanted.split()
    matches = []
    for vs in virtual_servers:
        haystack = " ".join(_normalize(vs.get(k) or "") for k in ("vs_name", "description", "pool_name"))
        if all(token in haystack for token in tokens):
            matches.append(vs)
    return matches
