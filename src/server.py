"""Agente MCP de monitoramento F5 BIG-IP — somente leitura.

SUPERFÍCIE EXPOSTA AO CLIENTE (política de segurança):
  * só status e configuração de Virtual Servers (e do pool/members/conexões dessas
    VS) — nada da configuração do dispositivo (NTP, ARP, VLANs, autenticação, rede,
    sistema...). A allowlist de comandos em src/safety.py não contém nada disso;
  * as respostas NÃO trazem comando executado, saída bruta, stderr, código de saída,
    host/porta/credenciais do dispositivo nem qualquer detalhe de COMO o agente se
    conecta ou funciona; as descrições das ferramentas (visíveis ao modelo cliente)
    seguem a mesma regra;
  * erros chegam ao cliente como mensagens genéricas; o detalhe técnico vai só para
    o log do servidor (stderr do processo).
Ao alterar/adicionar uma ferramenta, mantenha isso — src/_selftest.py varre as respostas
por termos que não podem aparecer.
"""
from __future__ import annotations

import functools
import logging
import sys
from typing import Optional

import paramiko
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
from .safety import BlockedPortError, CommandNotAllowedError, UnsafeInputError

logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("f5-mcp")

mcp = FastMCP(
    "f5-bigip-monitor",
    instructions=(
        "Consulta somente-leitura de Virtual Servers de F5 BIG-IP: status e configuração "
        "das VS, status do pool e dos membros, conexões ativas da VS, comparação com o "
        "baseline de propósito (Excel/Sheets) e validação de tráfego de uma VS. Não "
        "altera nada e não expõe configuração do dispositivo. Capturas de tráfego devem "
        "ser focadas na conexão que o usuário pediu: se ele citar uma conexão pelo nome, "
        "use tcpdump_capture_connection. Se o pedido for abrangente (casa com várias "
        "conexões ou não cita nenhuma), não faça uma captura ampla — quebre em conexões "
        "específicas e valide uma por vez, ou pergunte ao usuário qual."
    ),
)

# Mensagens que chegam ao cliente. Nenhuma cita método de conexão, comando, caminho,
# variável de ambiente ou texto vindo do dispositivo.
MSG_UNAVAILABLE = "Não foi possível consultar o dispositivo no momento. Tente novamente em instantes."
MSG_INTERNAL = ("Não foi possível concluir a consulta. Tente novamente; se persistir, "
                "acione o administrador do serviço.")
MSG_NOT_ALLOWED = "Operação não permitida por esta ferramenta."
MSG_DEVICE = "Dispositivo não encontrado. Use list_devices para ver os disponíveis."
MSG_BASELINE = "Não foi possível ler o baseline informado. Confira o nome do arquivo/planilha."
MSG_BUSY = ("Não foi possível iniciar a captura agora: há outras capturas em andamento. "
            f"Tente novamente em ~{TCPDUMP_BUSY_RETRY_MINUTES} minutos.")
MSG_CAPTURE_FAILED = "A captura não pôde ser concluída. Tente novamente em alguns minutos."
MSG_CONNECTION_UNKNOWN = ("Não foi possível determinar o IP:porta da VS e dos membros do "
                          "pool; nada foi capturado.")
MSG_CONCURRENT = ("Outra captura rodou ao mesmo tempo no dispositivo; o resultado pode "
                  "estar incompleto.")

# Interfaces fixas: a escolha da interface/VLAN não é um parâmetro do cliente.
CAPTURE_INTERFACE_ANY = "any"
CAPTURE_INTERFACE_CONNECTION = "0.0"

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


def _safe_tool(func):
    """Troca qualquer exceção por uma mensagem genérica (o detalhe vai para o log).
    Passam como estão só as mensagens NOSSAS e seguras: erro de parâmetro e a política
    de porta proibida."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BlockedPortError:
            raise                      # política: mensagem definida pelo produto
        except CommandNotAllowedError as exc:
            log.warning("%s: comando fora da allowlist: %s", func.__name__, exc)
            raise RuntimeError(MSG_NOT_ALLOWED) from None
        except UnsafeInputError:
            raise                      # parâmetro inválido: mensagem nossa, sem internals
        except InventoryError as exc:
            log.warning("%s: inventário: %s", func.__name__, exc)
            raise RuntimeError(MSG_DEVICE) from None
        except baseline_excel.BaselineError as exc:
            log.warning("%s: baseline: %s", func.__name__, exc)
            raise RuntimeError(MSG_BASELINE) from None
        except (F5ConnectionError, paramiko.SSHException, OSError, EOFError) as exc:
            log.warning("%s: dispositivo indisponível: %s", func.__name__, exc)
            raise RuntimeError(MSG_UNAVAILABLE) from None
        except Exception:
            log.exception("%s: erro inesperado", func.__name__)
            raise RuntimeError(MSG_INTERNAL) from None
    return wrapper


# ---------------------------------------------------------------------------
# Dispositivos
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def list_devices() -> list[dict]:
    """Lista os nomes dos dispositivos F5 disponíveis para consulta (use o nome nas
    demais ferramentas)."""
    return [{"name": d.name} for d in _get_inventory().list_devices()]


# ---------------------------------------------------------------------------
# Virtual Servers
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def get_virtual_server_status(device: str, vs_name: Optional[str] = None) -> dict:
    """Status de Virtual Server(s): disponibilidade, estado, motivo, destino
    (IP:porta), conexões (atuais/máximas/totais) e tráfego (bits/pacotes). Sem
    `vs_name`, lista todas as VS do dispositivo."""
    client = _client_for(device)
    return {"virtual_servers": tmsh_parser.parse_vs_status(
        client.show_virtual_servers(vs_name).stdout)}


@mcp.tool()
@_safe_tool
def get_virtual_server_config(device: str, vs_name: Optional[str] = None) -> dict:
    """Configuração de Virtual Server(s): destino (IP/porta), protocolo, pool
    associado, descrição, habilitada ou não, perfis, persistência, tradução de
    origem (SNAT) e regras — usada como base para comparar com o baseline de
    propósito. Sem `vs_name`, lista todas."""
    client = _client_for(device)
    return {"virtual_servers": tmsh_parser.parse_virtual_servers(
        client.list_virtual_server_config(vs_name).stdout)}


# ---------------------------------------------------------------------------
# Pools das VS
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def get_pool_status(
    device: str,
    pool_name: Optional[str] = None,
    vs_name: Optional[str] = None,
) -> dict:
    """Status do pool de uma VS e de cada membro (endereço, porta, disponibilidade,
    estado e motivo). Informe `pool_name` ou `vs_name` (o pool da VS é resolvido
    automaticamente)."""
    if pool_name is None and vs_name is None:
        raise UnsafeInputError("Informe pool_name ou vs_name.")
    client = _client_for(device)
    if pool_name is None:
        found = tmsh_parser.parse_virtual_servers(
            client.list_virtual_server_config(vs_name).stdout)
        pool_name = found[0].get("pool_name") if found else None
        if not pool_name:
            raise UnsafeInputError(f"A VS {vs_name!r} não foi encontrada ou não tem pool.")
    status = tmsh_parser.parse_pool_status(client.show_pool(pool_name).stdout)
    return {"pool": pool_name, **status}


# ---------------------------------------------------------------------------
# Conexões ativas da VS
# ---------------------------------------------------------------------------

MAX_CONNECTION_ROWS = 100


@mcp.tool()
@_safe_tool
def get_sys_connections(
    device: str,
    client_addr: Optional[str] = None,
    server_addr: Optional[str] = None,
    server_port: Optional[int] = None,
    client_port: Optional[int] = None,
) -> dict:
    """Conexões ativas filtradas por cliente e/ou por VS (IP:porta de destino), para
    confirmar se o tráfego esperado está presente. Exige ao menos um filtro."""
    if all(value is None for value in (client_addr, server_addr, server_port, client_port)):
        raise UnsafeInputError(
            "Informe ao menos um filtro: server_addr, server_port, client_addr ou client_port.")
    client = _client_for(device)
    rows = tmsh_parser.parse_sys_connections(
        client.show_sys_connections(client_addr, server_addr, server_port, client_port).stdout)
    out = {"total": len(rows), "connections": rows[:MAX_CONNECTION_ROWS]}
    if len(rows) > MAX_CONNECTION_ROWS:
        out["omitted"] = len(rows) - MAX_CONNECTION_ROWS
    return out


# ---------------------------------------------------------------------------
# Baseline (Excel / Google Sheets)
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def get_baseline_from_excel(filename: str, sheet_name: Optional[str] = None) -> list[dict]:
    """Lê o baseline de propósito de cada Virtual Server a partir de um arquivo Excel
    (.xlsx) do diretório de baselines. `filename` é o nome do arquivo (ex:
    'clienteA_baseline.xlsx')."""
    return baseline_excel.load_baseline(filename, sheet_name)


@mcp.tool()
@_safe_tool
def get_baseline_from_sheets(spreadsheet_id: str, sheet_range: str = "A1:F1000") -> list[dict]:
    """Lê o baseline de propósito de cada Virtual Server a partir de uma planilha
    Google Sheets (somente leitura)."""
    return baseline_sheets.load_baseline_from_sheet(spreadsheet_id, sheet_range)


@mcp.tool()
@_safe_tool
def compare_vs_with_excel_baseline(
    device: str, filename: str, sheet_name: Optional[str] = None
) -> dict:
    """Compara TODAS as Virtual Servers do dispositivo com o baseline de propósito de
    um Excel: identifica VS divergentes (pool/porta diferente do esperado), VS que
    existem no baseline mas não no dispositivo, e VS que existem no dispositivo mas
    não estão documentadas no baseline."""
    baseline = baseline_excel.load_baseline(filename, sheet_name)
    client = _client_for(device)
    live_vs = tmsh_parser.parse_virtual_servers(client.list_virtual_server_config().stdout)
    return comparator.compare_vs_to_baseline(live_vs, baseline)


@mcp.tool()
@_safe_tool
def compare_vs_with_sheets_baseline(
    device: str, spreadsheet_id: str, sheet_range: str = "A1:F1000"
) -> dict:
    """Igual a compare_vs_with_excel_baseline, mas lendo o baseline de um Google
    Sheets."""
    baseline = baseline_sheets.load_baseline_from_sheet(spreadsheet_id, sheet_range)
    client = _client_for(device)
    live_vs = tmsh_parser.parse_virtual_servers(client.list_virtual_server_config().stdout)
    return comparator.compare_vs_to_baseline(live_vs, baseline)


@mcp.tool()
@_safe_tool
def compare_pool_members_with_baseline(
    device: str, pool_name: str, expected_members: list[str]
) -> dict:
    """Compara os membros reais de um pool com uma lista esperada no formato
    'ip:porta' (normalmente vinda do baseline do cliente). Reporta membros faltando,
    inesperados e fora do ar."""
    client = _client_for(device)
    live_members = tmsh_parser.parse_pool_members(client.show_pool(pool_name).stdout)
    return comparator.compare_pool_members_to_baseline(pool_name, live_members, expected_members)


# ---------------------------------------------------------------------------
# Validação de tráfego de uma VS
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def tcpdump_validate_traffic(
    device: str,
    server_port: Optional[int] = None,
    node_port: Optional[int] = None,
    host: Optional[str] = None,
    count: int = 100,
    timeout_sec: int = 20,
    client_addr: Optional[str] = None,
    vs_addr: Optional[str] = None,
    node_addr: Optional[str] = None,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Captura e analisa o tráfego de uma VS por uma janela curta: porta da VS
    (`server_port`), porta do membro (`node_port`) e os IPs de cada lado.

    SEJA ESPECÍFICO: com o IP e a porta já confirmados (lidos da config da VS/pool),
    passe `vs_addr` (+ `client_addr`, se conhecido) junto de `server_port`, e
    `node_addr` junto de `node_port` — a captura pega só aquela conexão. Só por porta,
    sem IP, é abrangente e o retorno avisa isso. `host` faz AND com o filtro todo.

    Retorno (status 'ok'): `resultado` (veredito em uma frase), `trafego` (contagens
    só da VS pedida), `transacoes` (ISO 8583 agrupadas por STAN: pedido/resposta),
    `membros` (como cada membro do pool da VS respondeu ao SYN: "responde", "não
    responde (sem SYN-ACK)" ou "recusa (RST)" — a análise de membro fora do ar, que
    aparece também no `resultado`), `janela` e `avisos`. Tráfego que não é da VS
    pedida não entra no retorno.

    DETALHES: se o usuário pedir os detalhes das transações, chame com
    `detalhes=True` (e `stan="<STAN>"` para uma só). Cada transação traz `campos` (bits
    ISO 8583), `trajeto`, `saltos` e `rtt_ms`, e a resposta inclui `tabela_markdown`:
    apresente-a COMO ESTÁ (tabela "# | Tipo | STAN | Enviada | Resposta | RTT |
    Rastreio" + observações), sem reformatar.

    Outros status: 'busy' (há capturas demais em andamento — tente novamente no
    prazo indicado), 'blocked' (porta com captura desabilitada: capturas na porta TCP
    1222 não são permitidas) e 'error'."""
    return _run_capture(
        _client_for(device), interface=CAPTURE_INTERFACE_ANY, count=count,
        timeout_sec=timeout_sec, server_port=server_port, node_port=node_port, host=host,
        client_addr=client_addr, vs_addr=vs_addr, node_addr=node_addr,
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
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Executa a captura e monta a resposta enxuta, só com o tráfego da VS pedida."""
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
        # Porta proibida para esta ferramenta (ex: 1222). Retorno estruturado — é
        # política, não adianta retentar.
        return {"status": "blocked", "message": str(exc)}
    except TcpdumpBusyError as exc:
        log.info("captura recusada (busy): %s", exc)
        return {"status": "busy", "message": MSG_BUSY,
                "retry_after_minutes": TCPDUMP_BUSY_RETRY_MINUTES}

    # 0 = terminou por -c; 124 = prazo duro (esperado com pouco tráfego). Qualquer
    # outro código é falha da captura — não pode virar "ok". O detalhe fica no log.
    if result.exit_status not in (0, 124):
        log.warning("captura falhou: exit=%s stderr=%s", result.exit_status,
                    (result.stderr or "").strip()[-500:])
        return {"status": "error", "message": MSG_CAPTURE_FAILED}

    packets = tcpdump_parser.parse_tcpdump_output(result.stdout)
    warnings = []
    if describe_tcpdump_warnings(result.stderr):
        log.info("aviso de concorrência na captura: %s", (result.stderr or "").strip()[-300:])
        warnings.append(MSG_CONCURRENT)
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

    # Membros do pool da VS pedida cuja resposta ao SYN é analisada (node fora do ar etc.).
    # Com a mesma porta nos dois lados e sem o IP do node não dá para separar os SYN do
    # cliente dos SYN do F5 ao node: sem análise por membro.
    if node_members:
        members = list(node_members)
    elif node_port is not None and (node_addr or host):
        members = [(node_addr or host, node_port)]
    elif node_port is not None and node_port != server_port:
        members = [(None, node_port)]
    else:
        members = None
    view, notes = tcpdump_parser.simplified_view(
        packets, server_port=server_port, node_port=node_port, vs_addr=vs_addr,
        detalhes=detalhes, stan=stan, members=members)
    simple = {
        "status": "ok",
        "resultado": view["resultado"],
        "janela": {"max_s": min(timeout_sec, inv.limits.tcpdump_max_duration_sec),
                   "encerrou_por": "prazo" if result.exit_status == 124
                   else "limite de pacotes"},
        "trafego": view["trafego"],
        "transacoes": view["transacoes"],
        "avisos": warnings + notes,
    }
    if "transacoes_omitidas" in view:
        simple["transacoes_omitidas"] = view["transacoes_omitidas"]
    if "membros" in view:
        simple["membros"] = view["membros"]
    if "tabela_markdown" in view:
        simple["tabela_markdown"] = view["tabela_markdown"]
    return simple


def _connection_summary(vs: dict) -> dict:
    return {"vs_name": vs["vs_name"], "description": vs.get("description"),
            "pool_name": vs.get("pool_name")}   # só da VS pedida (não é usado para listar outras)


@mcp.tool()
@_safe_tool
def tcpdump_capture_connection(
    device: str,
    connection: str,
    client_addr: Optional[str] = None,
    count: int = 100,
    timeout_sec: int = 20,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Captura SÓ o tráfego da conexão que o usuário pediu — use esta ferramenta
    sempre que o pedido citar uma conexão pelo nome (ex: "a conexão da Padaria do
    Zezinho"), em vez de montar filtros por porta.

    `connection` = o nome da conexão como o usuário disse (ex: "padaria do zezinho"),
    sem palavras de contexto como "conexão"/"captura". Ele é procurado no nome, na
    descrição e no pool das Virtual Servers (sem diferenciar maiúsculas/acentos). Para
    a ÚNICA VS encontrada, a captura cobre apenas o tráfego da VS e dos membros do
    pool dela. `client_addr` (opcional): IP do cliente, se o usuário souber.

    Retorno (status 'ok'): `conexao` (VS, IP:porta, pool, membros), `resultado`
    (veredito em uma frase), `trafego`, `transacoes` (ISO 8583 por STAN), `membros`
    (como cada membro do pool respondeu ao SYN — informa membro fora do ar, sem
    SYN-ACK), `janela` e `avisos` — só do tráfego da VS pedida.

    DETALHES: se o usuário pedir os detalhes das transações, chame com `detalhes=True`
    (e `stan="<STAN>"` para uma só): cada transação traz `campos` ISO 8583, `trajeto`,
    `saltos` e `rtt_ms`, e a resposta inclui `tabela_markdown` — apresente-a como está
    (tabela "# | Tipo | STAN | Enviada | Resposta | RTT | Rastreio" + observações).

    Pedido abrangente — NÃO captura nada e devolve o que validar no lugar:
      - status 'ambiguous': o nome bate em mais de uma VS. 'candidates' lista só as
        que casam com o que o usuário disse; confirme com ele qual validar ou valide UMA
        POR VEZ, chamando de novo com o vs_name exato de cada candidata.
      - status 'not_found': nenhuma VS corresponde; peça o nome exato.

    A resposta traz SOMENTE a VS pedida: nenhuma informação de outras VS, pools ou
    conexões.

    Mesmos status e limites de tcpdump_validate_traffic ('busy', 'blocked', 'error';
    capturas na porta TCP 1222 não são permitidas)."""
    client = _client_for(device)
    vs_all = tmsh_parser.parse_virtual_servers(client.list_virtual_server_config().stdout)
    matches = tmsh_parser.match_virtual_servers(vs_all, connection)
    # Só a VS pedida: nada de listar as demais. Sem correspondência, o usuário
    # confirma o nome (get_virtual_server_config lista as VS quando ELE pede a lista).
    if not matches:
        return {
            "status": "not_found",
            "message": f"Nenhuma Virtual Server corresponde a {connection!r}. Nada foi "
                       "capturado — peça ao usuário o nome exato da VS (ou use "
                       "get_virtual_server_config para listar as VS).",
        }
    if len(matches) > 1:
        return {
            "status": "ambiguous",
            "message": f"{connection!r} corresponde a {len(matches)} conexões — pedido "
                       "abrangente demais para uma captura focada. Nada foi capturado: "
                       "valide uma conexão específica por vez (chame de novo com o "
                       "vs_name exato) ou confirme com o usuário qual delas.",
            "candidates": [{"vs_name": vs["vs_name"], "description": vs.get("description")}
                           for vs in matches],
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
                "message": MSG_CONNECTION_UNKNOWN}
    connection_info.update(vs_addr=vs_addr, vs_port=vs_port, client_addr=client_addr,
                           pool_members=[f"{a}:{p}" for a, p in node_members])

    try:
        result = _run_capture(
            client, interface=CAPTURE_INTERFACE_CONNECTION, count=count,
            timeout_sec=timeout_sec, server_port=vs_port, vs_addr=vs_addr,
            client_addr=client_addr, node_members=node_members, detalhes=detalhes, stan=stan,
        )
    except BlockedPortError:
        raise
    except UnsafeInputError as exc:
        # IP/porta lidos do dispositivo que não passam na validação (ex: IPv6 com
        # rota-domínio "%1") — não captura no escuro.
        log.warning("valores lidos do dispositivo recusados: %s", exc)
        return {"status": "error", "connection": connection_info,
                "message": MSG_CONNECTION_UNKNOWN}

    compact = {
        "vs": connection_info["vs_name"],
        "descricao": connection_info.get("description"),
        "vs_ip_porta": f"{vs_addr}:{vs_port}",
        "pool": connection_info.get("pool_name"),
        "membros": connection_info["pool_members"],
        "cliente": client_addr,
    }
    return {"conexao": {k: v for k, v in compact.items() if v}, **result}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
