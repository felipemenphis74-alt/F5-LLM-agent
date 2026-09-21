"""Parsing best-effort da saída texto do tmsh (`list`/`show`).

A formatação exata do tmsh varia um pouco por versão de TMOS. Estas funções cobrem os
formatos mais comuns, mas sempre devolvem também o texto bruto (`raw`) para conferência
manual — trate os campos estruturados como "melhor esforço", não como garantia.
"""
from __future__ import annotations

import re

VS_BLOCK_RE = re.compile(
    r"ltm virtual (?P<name>\S+)\s*\{(?P<body>.*?)\n\}", re.DOTALL
)
DESTINATION_RE = re.compile(r"destination\s+(?:/\S+/)?(?P<addr>[\d.:a-fA-F]+)")
POOL_RE = re.compile(r"^\s*pool\s+(?P<pool>\S+)", re.MULTILINE)
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
