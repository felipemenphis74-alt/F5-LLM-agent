"""Agente MCP de monitoramento F5 BIG-IP — somente leitura.

Todas as ferramentas expostas aqui são estritamente read-only: consultam status de
Virtual Servers e Pools, conexões ativas (`show sys connection`), comparam com
baselines de propósito (Excel/Google Sheets) e validam padrões de tráfego via tcpdump
nativo do TMOS. Nenhuma ferramenta cria, modifica, salva ou reinicia configuração —
isso é garantido em múltiplas camadas por src/safety.py (allowlist de comandos +
validação de identificadores), independentemente do que for pedido pelo modelo.
"""
from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from . import baseline_excel, baseline_sheets, comparator, tmsh_parser, tcpdump_parser
from .f5_client import (
    F5Client,
    F5ConnectionError,
    TCPDUMP_BUSY_RETRY_MINUTES,
    TcpdumpBusyError,
    describe_tcpdump_warnings,
)
from .inventory import Inventory, InventoryError
from .safety import BlockedPortError, UnsafeInputError

mcp = FastMCP(
    "f5-bigip-monitor",
    instructions=(
        "Agente somente-leitura para monitoramento de F5 BIG-IP: status de "
        "Virtual Servers/Pools, sys connections, comparação com baseline de "
        "propósito (Excel/Sheets) e validação de padrões de tráfego via tcpdump. "
        "Nunca realiza alterações de configuração. "
        "Capturas tcpdump devem ser focadas na conexão que o usuário pediu: se ele "
        "citar uma conexão pelo nome, use tcpdump_capture_connection (resolve VS e pool "
        "members e captura só aquele IP:porta). Se o pedido for abrangente (casa com "
        "várias conexões ou não cita nenhuma), não faça uma captura ampla — quebre em "
        "conexões específicas e valide uma por vez, ou pergunte ao usuário qual."
    ),
)

_inventory: Optional[Inventory] = None


def _get_inventory() -> Inventory:
    global _inventory
    if _inventory is None:
        _inventory = Inventory.load()
    return _inventory


def _client_for(device_name: str) -> F5Client:
    inv = _get_inventory()
    device = inv.get(device_name)
    return F5Client(
        device=device,
        connect_timeout_sec=inv.limits.ssh_connect_timeout_sec,
        command_timeout_sec=inv.limits.command_timeout_sec,
    )


# ---------------------------------------------------------------------------
# Inventário
# ---------------------------------------------------------------------------

@mcp.tool()
def list_devices() -> list[dict]:
    """Lista os devices F5 BIG-IP configurados no inventário (nome, host, partição,
    tags). Não expõe credenciais."""
    inv = _get_inventory()
    return [
        {"name": d.name, "host": d.host, "port": d.port, "partition": d.partition, "tags": d.tags}
        for d in inv.list_devices()
    ]


# ---------------------------------------------------------------------------
# Virtual Servers
# ---------------------------------------------------------------------------

@mcp.tool()
def get_virtual_server_status(device: str, vs_name: Optional[str] = None) -> dict:
    """Consulta status/estatísticas de Virtual Server(s) via `tmsh show ltm virtual`
    (somente leitura). Se vs_name for omitido, lista todas as VS do device."""
    client = _client_for(device)
    result = client.show_virtual_servers(vs_name)
    return {"command": result.command, "exit_status": result.exit_status,
            "stdout": result.stdout, "stderr": result.stderr}


@mcp.tool()
def get_virtual_server_config(device: str, vs_name: Optional[str] = None) -> dict:
    """Consulta a configuração declarada de Virtual Server(s) via
    `tmsh list ltm virtual` (destino, porta, pool associado) — usado como base para
    comparação com o baseline de propósito do cliente. Somente leitura."""
    client = _client_for(device)
    result = client.list_virtual_server_config(vs_name)
    parsed = tmsh_parser.parse_virtual_servers(result.stdout)
    return {"command": result.command, "exit_status": result.exit_status,
            "parsed": parsed, "raw": result.stdout}


# ---------------------------------------------------------------------------
# Pools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_pool_status(device: str, pool_name: Optional[str] = None) -> dict:
    """Consulta status detalhado de um Pool e seus members via
    `tmsh show ltm pool <nome> members detail` (disponibilidade, estado). Se
    pool_name for omitido, lista todos os pools do device. Somente leitura."""
    client = _client_for(device)
    result = client.show_pool(pool_name)
    parsed_members = tmsh_parser.parse_pool_members(result.stdout) if pool_name else []
    return {"command": result.command, "exit_status": result.exit_status,
            "parsed_members": parsed_members, "raw": result.stdout}


# ---------------------------------------------------------------------------
# Conexões ativas
# ---------------------------------------------------------------------------

@mcp.tool()
def get_sys_connections(
    device: str,
    client_addr: Optional[str] = None,
    server_addr: Optional[str] = None,
    server_port: Optional[int] = None,
    client_port: Optional[int] = None,
) -> dict:
    """Executa `tmsh show sys connection` (somente leitura) com filtros opcionais de
    endereço/porta de cliente e servidor, para verificar conexões ativas e confirmar
    se os padrões esperados de tráfego estão presentes."""
    client = _client_for(device)
    result = client.show_sys_connections(client_addr, server_addr, server_port, client_port)
    return {"command": result.command, "exit_status": result.exit_status,
            "stdout": result.stdout, "stderr": result.stderr}


# ---------------------------------------------------------------------------
# Baseline (Excel / Google Sheets)
# ---------------------------------------------------------------------------

@mcp.tool()
def get_baseline_from_excel(filename: str, sheet_name: Optional[str] = None) -> list[dict]:
    """Lê o baseline de propósito de cada Virtual Server a partir de um arquivo Excel
    (.xlsx) localizado no diretório de dados montado no container (F5_MCP_DATA_DIR).
    `filename` é relativo a esse diretório (ex: 'clienteA_baseline.xlsx')."""
    return baseline_excel.load_baseline(filename, sheet_name)


@mcp.tool()
def get_baseline_from_sheets(spreadsheet_id: str, sheet_range: str = "A1:F1000") -> list[dict]:
    """Lê o baseline de propósito de cada Virtual Server a partir de uma planilha
    Google Sheets (somente leitura). Requer GOOGLE_SHEETS_CREDENTIALS_PATH configurado
    com uma service account que tenha acesso de leitor à planilha."""
    return baseline_sheets.load_baseline_from_sheet(spreadsheet_id, sheet_range)


@mcp.tool()
def compare_vs_with_excel_baseline(
    device: str, filename: str, sheet_name: Optional[str] = None
) -> dict:
    """Compara TODAS as Virtual Servers do device com o baseline de propósito de um
    Excel local: identifica VS divergentes (pool/porta diferente do esperado), VS que
    existem no baseline mas não no device, e VS que existem no device mas não estão
    documentadas no baseline. Somente leitura."""
    baseline = baseline_excel.load_baseline(filename, sheet_name)
    client = _client_for(device)
    result = client.list_virtual_server_config()
    live_vs = tmsh_parser.parse_virtual_servers(result.stdout)
    return comparator.compare_vs_to_baseline(live_vs, baseline)


@mcp.tool()
def compare_vs_with_sheets_baseline(
    device: str, spreadsheet_id: str, sheet_range: str = "A1:F1000"
) -> dict:
    """Igual a compare_vs_with_excel_baseline, mas lendo o baseline de um Google
    Sheets. Somente leitura."""
    baseline = baseline_sheets.load_baseline_from_sheet(spreadsheet_id, sheet_range)
    client = _client_for(device)
    result = client.list_virtual_server_config()
    live_vs = tmsh_parser.parse_virtual_servers(result.stdout)
    return comparator.compare_vs_to_baseline(live_vs, baseline)


@mcp.tool()
def compare_pool_members_with_baseline(
    device: str, pool_name: str, expected_members: list[str]
) -> dict:
    """Compara os members reais de um Pool (via tmsh show ltm pool ... members detail)
    com uma lista esperada de members no formato 'ip:porta' (normalmente vinda do
    baseline do cliente). Reporta members faltando, inesperados e fora do ar. Somente
    leitura."""
    client = _client_for(device)
    result = client.show_pool(pool_name)
    live_members = tmsh_parser.parse_pool_members(result.stdout)
    return comparator.compare_pool_members_to_baseline(pool_name, live_members, expected_members)


# ---------------------------------------------------------------------------
# Tcpdump — validação de padrões de tráfego
# ---------------------------------------------------------------------------

@mcp.tool()
def tcpdump_validate_traffic(
    device: str,
    interface: str = "any",
    server_port: Optional[int] = None,
    node_port: Optional[int] = None,
    host: Optional[str] = None,
    count: int = 100,
    timeout_sec: int = 20,
    client_addr: Optional[str] = None,
    vs_addr: Optional[str] = None,
    node_addr: Optional[str] = None,
    verbose: bool = False,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Executa uma captura tcpdump somente-leitura no BIG-IP (via SSH, sem gravar
    .pcap) filtrando por porta de servidor (VS), porta de node/pool member e pelos
    IPs de cada lado da conexão.

    RETORNO SIMPLES (padrão): `resultado` (veredito em uma frase), `trafego` (contagens
    só da VS pedida), `transacoes` (ISO 8583 agrupadas por STAN: pedido/resposta),
    `janela` e `avisos`. Sondas do monitor do pool e conexões que não são da VS
    pedida NÃO entram — só é descartado quando o lado da VS é identificável (`vs_addr`
    + `server_port`, ou portas de VS e node diferentes). `verbose=True` devolve o
    retorno completo (comando, summary, até 200 pacotes brutos, stderr) — use só para
    depurar a ferramenta, não para responder ao usuário.

    DETALHES DAS TRANSAÇÕES: quando o usuário pedir os detalhes das transações
    capturadas, chame com `detalhes=True` (e `stan="<STAN>"` para uma só). Cada
    transação passa a trazer `campos` (bits ISO 8583), `trajeto` (os saltos), `saltos`
    e `rtt_ms`, e a resposta inclui `tabela_markdown`: apresente-a COMO ESTÁ (tabela
    "# | Tipo | STAN | Enviada | Resposta | RTT | Rastreio" + observações), sem
    reformatar e sem acrescentar pacotes brutos.

    SEJA ESPECÍFICO: quando o IP e a porta da conexão a validar já estiverem
    confirmados (ex: lidos da config da VS/pool), passe-os — `vs_addr` (+
    `client_addr`, se conhecido) junto de `server_port`, e `node_addr` junto de
    `node_port`. Cada lado vira um filtro "IP E porta" (ex: `(port 17000 and host
    10.100.1.10 and host 192.168.170.1) or (port 15000 and host 192.168.0.9)`), e a
    captura pega só aquela conexão — não o monitor de outros pools nem outra VS na
    mesma porta. Captura só por porta, sem IP, é abrangente e o retorno avisa isso em
    'warnings'. `host` (legado) faz AND com o filtro inteiro.

    A captura roda como UM único processo tcpdump no F5 (o prazo duro é um alarme no
    próprio processo, sem wrapper `timeout` ao lado). A
    análise identifica SYN, SYN+ACK, RST/RST+ACK, ACK, origem de cada pacote, e procura
    os marcadores de payload '0800' (request) / '0810' (resposta) — ajuste se o
    protocolo do cliente usar outra convenção. A captura é limitada por --count e por
    timeout duro (definidos no inventory.yaml) para nunca impactar o equipamento.

    Antes de iniciar, o agente confere quantas capturas tcpdump já estão rodando no
    host; se isso já estiver no limite (padrão: 2 — contando a que seria iniciada
    agora), ele RECUSA iniciar uma nova — nunca interrompe ou altera capturas em
    andamento — e retorna status 'busy' pedindo para tentar de novo em alguns
    minutos. Mesmo quando a captura roda, o campo 'warnings' do retorno reporta
    qualquer aviso do próprio TMOS sobre concorrência de tcpdump (ex: limite de
    instâncias tmm excedido) que apareça no stderr — cobre o caso raro de outra
    captura começar bem entre o check e o início desta.

    Se o próprio tcpdump falhar (exit_status diferente de 0 e 124), o retorno é
    status 'error' com o stderr — nunca 'ok' com zero pacotes.

    Portas proibidas: capturas na porta TCP 1222 (porta de conexão com a captura
    RISe) estão desabilitadas para esta ferramenta — um pedido envolvendo essa porta
    é recusado na validação dos parâmetros e retorna status 'blocked', sem sequer
    conectar no F5.

    Requer que a conta SSH tenha 'Advanced shell (bash)' habilitado no BIG-IP (tcpdump
    não roda dentro do prompt tmsh)."""
    return _run_capture(
        _client_for(device), interface=interface, count=count, timeout_sec=timeout_sec,
        server_port=server_port, node_port=node_port, host=host,
        client_addr=client_addr, vs_addr=vs_addr, node_addr=node_addr, verbose=verbose,
        detalhes=detalhes, stan=stan,
    )


def _run_capture(
    client: F5Client,
    interface: str,
    count: int,
    timeout_sec: int,
    server_port: Optional[int] = None,
    node_port: Optional[int] = None,
    host: Optional[str] = None,
    client_addr: Optional[str] = None,
    vs_addr: Optional[str] = None,
    node_addr: Optional[str] = None,
    node_members: Optional[list[tuple[str, int]]] = None,
    verbose: bool = False,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Executa a captura e monta o retorno estruturado (comum às ferramentas de
    tcpdump). Padrão: retorno simples só com o tráfego da VS; `verbose` = completo."""
    inv = _get_inventory()
    try:
        result = client.tcpdump_capture(
            interface=interface,
            server_port=server_port,
            node_port=node_port,
            host=host,
            client_addr=client_addr,
            vs_addr=vs_addr,
            node_addr=node_addr,
            node_members=node_members,
            count=count,
            max_count=inv.limits.tcpdump_max_count,
            timeout_sec=timeout_sec,
            max_timeout_sec=inv.limits.tcpdump_max_duration_sec,
        )
    except BlockedPortError as exc:
        # Porta proibida para esta ferramenta (ex: 1222, conexão com a captura RISe).
        # Retorno estruturado — não é erro de uso, é política: não adianta retentar.
        return {
            "status": "blocked",
            "message": str(exc),
        }
    except TcpdumpBusyError as exc:
        return {
            "status": "busy",
            "message": str(exc),
            "retry_after_minutes": TCPDUMP_BUSY_RETRY_MINUTES,
        }

    # 0 = terminou por -c; 124 = prazo duro do `timeout` (esperado com pouco tráfego).
    # Qualquer outro código é falha do próprio tcpdump/shell — não pode virar "ok".
    if result.exit_status not in (0, 124):
        return {
            "status": "error",
            "message": "O tcpdump falhou (exit_status=%s): %s" % (
                result.exit_status, (result.stderr or "sem stderr").strip()[-500:]),
            "command": result.command,
            "exit_status": result.exit_status,
        }

    packets = tcpdump_parser.parse_tcpdump_output(result.stdout)
    summary = tcpdump_parser.summarize(packets)
    warnings = describe_tcpdump_warnings(result.stderr)
    broad_sides = []
    if server_port is not None and vs_addr is None and client_addr is None and host is None:
        broad_sides.append(f"server_port {server_port} sem vs_addr/client_addr")
    if node_port is not None and node_addr is None and host is None:
        broad_sides.append(f"node_port {node_port} sem node_addr")
    if broad_sides:
        warnings.append(
            "Captura abrangente (" + "; ".join(broad_sides) + "): pega qualquer tráfego "
            "nessas portas, inclusive de outras conexões. Com IP e porta confirmados, "
            "repita com vs_addr/client_addr/node_addr para capturar só a conexão validada."
        )
    if not verbose:
        view, notes = tcpdump_parser.simplified_view(
            packets, server_port=server_port, node_port=node_port, vs_addr=vs_addr,
            detalhes=detalhes, stan=stan)
        window = min(timeout_sec, inv.limits.tcpdump_max_duration_sec)
        simple = {
            "status": "ok",
            "resultado": view["resultado"],
            "janela": {"max_s": window,
                       "encerrou_por": "prazo" if result.exit_status == 124
                       else "limite de pacotes"},
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
        "command": result.command,
        "exit_status": result.exit_status,
        "summary": summary,
        "packets": packets[:200],
        "packet_count_truncated": len(packets) > 200,
        "stderr": result.stderr,
        # Avisos do próprio TMOS sobre concorrência de tcpdump detectados no stderr
        # desta execução (ex: limite de instâncias tmm excedido) — destacados aqui em
        # vez de ficarem enterrados no stderr bruto acima.
        "warnings": warnings,
    }


def _connection_summary(vs: dict) -> dict:
    return {"vs_name": vs["vs_name"], "description": vs.get("description"),
            "pool_name": vs.get("pool_name")}


@mcp.tool()
def tcpdump_capture_connection(
    device: str,
    connection: str,
    client_addr: Optional[str] = None,
    interface: str = "0.0",
    count: int = 100,
    timeout_sec: int = 20,
    verbose: bool = False,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Captura (tcpdump, somente leitura) SÓ o tráfego da conexão que o usuário
    pediu — use esta ferramenta sempre que o pedido citar uma conexão pelo nome
    (ex: "a conexão da Padaria do Zezinho"), em vez de montar filtros por porta.

    RETORNO SIMPLES (padrão): `conexao` (VS, IP:porta, pool, members), `resultado`
    (veredito em uma frase), `trafego`, `transacoes` (ISO 8583 por STAN) e `avisos` —
    só do tráfego da VS pedida; sondas do monitor do pool não aparecem. `verbose=True`
    devolve o retorno completo (comando, summary, pacotes brutos, stderr), só para
    depurar a ferramenta.

    DETALHES DAS TRANSAÇÕES: se o usuário pedir os detalhes, chame com `detalhes=True`
    (e `stan="<STAN>"` para uma só): cada transação traz `campos` ISO 8583, `trajeto`,
    `saltos` e `rtt_ms`, e a resposta inclui `tabela_markdown` — apresente-a como está
    (tabela "# | Tipo | STAN | Enviada | Resposta | RTT | Rastreio" + observações).

    `connection` = o nome da conexão como o usuário disse (ex: "padaria do zezinho"),
    sem palavras de contexto como "conexão"/"captura". Ele é procurado no nome, na
    descrição e no pool das Virtual Servers (sem diferenciar maiúsculas/acentos). Para
    a ÚNICA VS encontrada o agente lê, no próprio F5, o IP:porta numérico da VS e de
    cada pool member, e captura apenas:
        (porta da VS E IP da VS [E client_addr]) OU (porta E IP de cada member)
    `client_addr` (opcional): IP do cliente, se o usuário souber — restringe ainda mais
    o lado cliente.

    Pedido abrangente — NÃO captura nada e devolve o que validar no lugar:
      - status 'ambiguous': o nome bate em mais de uma VS. 'candidates' lista cada
        conexão específica; confirme com o usuário qual validar ou valide UMA POR VEZ,
        chamando de novo com o vs_name exato de cada candidata — nunca uma captura
        única cobrindo todas.
      - status 'not_found': nenhuma VS corresponde; 'available_connections' lista as
        existentes para o usuário escolher.

    Se um pool member também é usado por outra VS, o lado servidor não tem como ser
    separado por IP/porta (mesmo destino, mesmo SNAT) — o retorno avisa em 'warnings'
    quais VS compartilham o member.

    Mesmos limites, guardas e retorno de tcpdump_validate_traffic (um único processo
    tcpdump no F5, prazo duro, porta 1222 bloqueada, recusa se o F5 já tiver capturas
    demais rodando)."""
    client = _client_for(device)
    vs_all = tmsh_parser.parse_virtual_servers(client.list_virtual_server_config().stdout)
    matches = tmsh_parser.match_virtual_servers(vs_all, connection)
    if not matches:
        return {
            "status": "not_found",
            "message": f"Nenhuma Virtual Server corresponde a {connection!r}. Nada foi "
                       "capturado — confirme com o usuário qual destas conexões validar.",
            "available_connections": [_connection_summary(vs) for vs in vs_all],
        }
    if len(matches) > 1:
        return {
            "status": "ambiguous",
            "message": f"{connection!r} corresponde a {len(matches)} conexões — pedido "
                       "abrangente demais para uma captura focada. Nada foi capturado: "
                       "valide uma conexão específica por vez (chame de novo com o "
                       "vs_name exato) ou confirme com o usuário qual delas.",
            "candidates": [_connection_summary(vs) for vs in matches],
        }

    vs = matches[0]
    connection_info = _connection_summary(vs)
    if not vs.get("pool_name"):
        return {"status": "error", "connection": connection_info,
                "message": f"A VS {vs['vs_name']} não tem pool associado — não há lado "
                           "servidor definido para focar a captura."}

    vs_addr, vs_port = tmsh_parser.parse_vs_destination(
        client.show_virtual_servers(vs["vs_name"]).stdout)
    pool_lists = tmsh_parser.parse_pool_list_members(client.list_pool_config().stdout)
    own_list = pool_lists.get(vs["pool_name"], [])
    # Porta numérica vem do `show`; o IP real do node vem do `list` (casados pelo nome
    # do node) — um node nomeado sem IP no nome ("web01") não vira filtro inválido.
    node_ip = {m["node"]: m["address"] for m in own_list}
    node_members = []
    for m in tmsh_parser.parse_pool_members(client.show_pool(vs["pool_name"]).stdout):
        node = m["node_name"].rsplit("/", 1)[-1]
        node_members.append((node_ip.get(node, m["address"]), m["port"]))
    if vs_addr is None or vs_port is None or not node_members:
        return {"status": "error", "connection": connection_info,
                "message": "Não consegui ler o IP:porta da VS e/ou dos pool members no "
                           "F5 — sem eles a captura não pode ser focada nesta conexão, "
                           "então nada foi capturado."}
    connection_info.update(vs_addr=vs_addr, vs_port=vs_port, client_addr=client_addr,
                           pool_members=[f"{a}:{p}" for a, p in node_members])

    # Members compartilhados com pools de OUTRAS VS: comparados na notação do `list`
    # (porta numérica ou nome de serviço, a mesma nos dois lados).
    own = {(m["address"], m["service"]) for m in own_list}
    shared = []
    for other in vs_all:
        other_pool = other.get("pool_name")
        if other["vs_name"] == vs["vs_name"] or not other_pool or other_pool == vs["pool_name"]:
            continue
        common = own & {(m["address"], m["service"]) for m in pool_lists.get(other_pool, [])}
        if common:
            shared.append(f"{other['vs_name']} (pool {other_pool}: "
                          + ", ".join(sorted(f"{a}:{s}" for a, s in common)) + ")")

    try:
        result = _run_capture(
            client, interface=interface, count=count, timeout_sec=timeout_sec,
            server_port=vs_port, vs_addr=vs_addr, client_addr=client_addr,
            node_members=node_members, verbose=verbose, detalhes=detalhes, stan=stan,
        )
    except UnsafeInputError as exc:
        # IP/porta lidos do F5 que não passam na validação (ex: member em IPv6 com
        # rota-domínio "%1") — não captura no escuro, devolve o motivo.
        return {"status": "error", "connection": connection_info, "message": str(exc)}
    if verbose:
        result["connection"] = connection_info
    else:
        compact = {
            "vs": connection_info["vs_name"],
            "descricao": connection_info.get("description"),
            "vs_ip_porta": f"{vs_addr}:{vs_port}",
            "pool": connection_info.get("pool_name"),
            "membros": connection_info["pool_members"],
            "cliente": client_addr,
        }
        result = {"conexao": {k: v for k, v in compact.items() if v}, **result}
    if shared and result.get("status") == "ok":
        if verbose:
            result["warnings"].append(
                "Pool member compartilhado com outra(s) VS: " + "; ".join(shared) + ". No "
                "lado servidor o tráfego dessas VS tem o mesmo IP/porta/SNAT e pode aparecer "
                "na captura — o lado cliente (IP:porta da VS) é exclusivo desta conexão."
            )
        else:
            # resposta simples: sem nomear outras VS/pools — só o limite que afeta a leitura
            result["avisos"].append(
                "O pool member é compartilhado com outra VS: no lado do node podem aparecer "
                "conexões dela (mesmo IP/porta/SNAT); o lado cliente é exclusivo desta VS."
            )
    return result


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
