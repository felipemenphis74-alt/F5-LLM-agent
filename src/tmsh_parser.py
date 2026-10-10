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
DESTINATION_RE = re.compile(r"destination\s+(?:/\S+/)?(?P<addr>[\d.:a-fA-F]+)")
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

        results.append({
            "vs_name": name,
            "address": addr,
            "port": int(port) if port and port.isdigit() else None,
            "pool_name": pool_match.group("pool") if pool_match else None,
            "description": (desc_match.group("quoted") if desc_match.group("quoted") is not None
                            else desc_match.group("word")) if desc_match else None,
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
