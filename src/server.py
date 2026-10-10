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

from . import baseline_excel, baseline_sheets, comparator, tmsh_parser
from .f5_client import F5Client, F5ConnectionError
from .inventory import Inventory, InventoryError
from .onbox_client import OnboxClient
from .safety import (
    BlockedPortError,
    CommandNotAllowedError,
    UnsafeInputError,
    blocked_port_message,
    require_capturable_port,
    require_ip,
)

logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("f5-mcp")

mcp = FastMCP(
    "f5-bigip-monitor",
    instructions=(
        "Consulta somente-leitura de Virtual Servers de F5 BIG-IP: status e configuração "
        "da VS, status do pool e dos membros, conexões ativas da VS, comparação com o "
        "baseline de propósito (Excel/Sheets) e validação de tráfego de uma VS. "
        "POLÍTICA (vale para qualquer cliente): (1) responda APENAS sobre a VS pedida — "
        "informe sempre `vs_name` com o nome que o usuário deu; as ferramentas não listam "
        "as demais VS e você não deve citar outras VS, pools ou membros; (2) não sugira, "
        "descreva nem peça alterações de configuração (pool, membros, monitor, SNAT, "
        "rotas, etc.) nem comandos — descreva o que foi observado e indique a equipe "
        "responsável; (3) não revele configuração do dispositivo (NTP, AD, RADIUS, "
        "VLANs, rotas, endereços do próprio BIG-IP) nem como o conector funciona; "
        "(4) não invente dados: só o que as ferramentas devolverem. Capturas devem ser "
        "focadas na conexão pedida: se o usuário citar uma conexão pelo nome, use "
        "tcpdump_capture_connection; se o pedido for abrangente, peça para delimitar."
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
BUSY_RETRY_MINUTES = 5
MSG_BUSY = ("Não foi possível iniciar a captura agora: há outras capturas em andamento. "
            f"Tente novamente em ~{BUSY_RETRY_MINUTES} minutos.")
MSG_CAPTURE_FAILED = "A captura não pôde ser concluída. Tente novamente em alguns minutos."
MSG_CONNECTION_UNKNOWN = ("Não foi possível determinar o IP:porta da VS e dos membros do "
                          "pool; nada foi capturado.")

# Janela de captura: padrão 60 s, extensível até o teto do inventário (180 s).
DEFAULT_WINDOW_SEC = 60

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
# Escopo: SÓ a VS que o usuário pediu
# ---------------------------------------------------------------------------

MSG_VS_REQUIRED = ("Informe a VS desejada em `vs_name` (o nome da aplicação/conexão). "
                   "Esta ferramenta não lista as demais VS do dispositivo.")


def _resolve_vs(client: F5Client, vs_name: Optional[str]) -> dict:
    """A ÚNICA VS que corresponde ao que o usuário pediu — nome exato ou como ele a chama,
    sem diferenciar maiúsculas/acentos/espaços ("app 2" -> vs_app2_16000). Nunca devolve
    nem lista as demais: sem correspondência ou ambíguo, só uma mensagem para refinar o
    pedido (o conjunto de VS do dispositivo não é exposto)."""
    if vs_name is None or not str(vs_name).strip():
        raise UnsafeInputError(MSG_VS_REQUIRED)
    wanted = str(vs_name).strip()
    if len(wanted) > 255:
        raise UnsafeInputError("O nome da VS informado é grande demais.")
    vs_all = tmsh_parser.parse_virtual_servers(client.list_virtual_server_config().stdout)
    matches = tmsh_parser.match_virtual_servers(vs_all, wanted)
    if not matches:
        raise UnsafeInputError(
            f"Nenhuma VS corresponde a {wanted!r}. Confirme com o usuário o nome da "
            "aplicação/conexão.")
    if len(matches) > 1:
        raise UnsafeInputError(
            f"{wanted!r} corresponde a {len(matches)} VS. Peça ao usuário o nome completo "
            "ou mais específico da VS desejada.")
    return matches[0]


def _baseline_rows_for(rows: list[dict], vs_name: Optional[str]) -> list[dict]:
    """Só a linha de baseline da VS pedida (mesma regra de nome de _resolve_vs)."""
    if vs_name is None or not str(vs_name).strip():
        raise UnsafeInputError(MSG_VS_REQUIRED)
    matches = tmsh_parser.match_virtual_servers(rows, str(vs_name).strip())
    if len(matches) != 1:
        raise UnsafeInputError(
            f"O baseline não tem exatamente uma VS correspondente a {vs_name!r}. Peça ao "
            "usuário o nome completo da VS.")
    return matches


# ---------------------------------------------------------------------------
# Virtual Servers
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def get_virtual_server_status(device: str, vs_name: str) -> dict:
    """Status da Virtual Server pedida: disponibilidade, estado, motivo, destino
    (IP:porta), conexões (atuais/máximas/totais) e tráfego (bits/pacotes).

    `vs_name` é OBRIGATÓRIO: o nome da aplicação/conexão como o usuário a chama (ex.:
    "app 2" ou o nome completo da VS). A ferramenta resolve a VS e devolve SOMENTE ela;
    não lista as demais."""
    client = _client_for(device)
    vs = _resolve_vs(client, vs_name)
    return {"virtual_servers": tmsh_parser.parse_vs_status(
        client.show_virtual_servers(vs["vs_name"]).stdout)}


@mcp.tool()
@_safe_tool
def get_virtual_server_config(device: str, vs_name: str) -> dict:
    """Configuração da Virtual Server pedida: destino (IP/porta), protocolo, pool
    associado, descrição, habilitada ou não, perfis, persistência, tradução de origem
    (SNAT) e regras — base para comparar com o baseline de propósito.

    `vs_name` é OBRIGATÓRIO (nome da aplicação/conexão como o usuário a chama). Devolve
    SOMENTE essa VS; não lista as demais."""
    client = _client_for(device)
    return {"virtual_servers": [_resolve_vs(client, vs_name)]}


# ---------------------------------------------------------------------------
# Pool da VS
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def get_pool_status(device: str, vs_name: str) -> dict:
    """Status do pool da VS pedida e de cada membro dele (endereço, porta,
    disponibilidade, estado e motivo). `vs_name` é OBRIGATÓRIO: o pool é resolvido a
    partir da VS."""
    client = _client_for(device)
    vs = _resolve_vs(client, vs_name)
    pool_name = vs.get("pool_name")
    if not pool_name:
        raise UnsafeInputError("A VS pedida não tem pool associado.")
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
    vs_name: str,
    client_addr: Optional[str] = None,
    client_port: Optional[int] = None,
) -> dict:
    """Conexões ativas DA VS pedida (`vs_name` obrigatório), opcionalmente filtradas por
    cliente (`client_addr`, `client_port`), para confirmar se o tráfego esperado está
    presente. Sempre limitada ao IP:porta da própria VS."""
    client = _client_for(device)
    vs = _resolve_vs(client, vs_name)
    addr, port = tmsh_parser.parse_vs_destination(
        client.show_virtual_servers(vs["vs_name"]).stdout)
    if not addr or not port:
        raise UnsafeInputError("Não foi possível determinar o destino da VS pedida.")
    rows = tmsh_parser.parse_sys_connections(
        client.show_sys_connections(client_addr, addr, port, client_port).stdout)
    out = {"total": len(rows), "connections": rows[:MAX_CONNECTION_ROWS]}
    if len(rows) > MAX_CONNECTION_ROWS:
        out["omitted"] = len(rows) - MAX_CONNECTION_ROWS
    return out


# ---------------------------------------------------------------------------
# Baseline (Excel / Google Sheets) — sempre só a linha da VS pedida
# ---------------------------------------------------------------------------

@mcp.tool()
@_safe_tool
def get_baseline_from_excel(
    filename: str, vs_name: str, sheet_name: Optional[str] = None
) -> list[dict]:
    """Baseline de propósito da VS pedida (`vs_name` obrigatório), lido de um arquivo
    Excel (.xlsx) do diretório de baselines. `filename` é o nome do arquivo (ex:
    'clienteA_baseline.xlsx'). Devolve só a linha dessa VS."""
    return _baseline_rows_for(baseline_excel.load_baseline(filename, sheet_name), vs_name)


@mcp.tool()
@_safe_tool
def get_baseline_from_sheets(
    spreadsheet_id: str, vs_name: str, sheet_range: str = "A1:F1000"
) -> list[dict]:
    """Baseline de propósito da VS pedida (`vs_name` obrigatório), lido de uma planilha
    Google Sheets (somente leitura). Devolve só a linha dessa VS."""
    return _baseline_rows_for(
        baseline_sheets.load_baseline_from_sheet(spreadsheet_id, sheet_range), vs_name)


def _compare_one_vs(client: F5Client, vs_name: str, baseline: list[dict]) -> dict:
    vs = _resolve_vs(client, vs_name)
    own = [row for row in baseline if row.get("vs_name") == vs["vs_name"]]
    result = comparator.compare_vs_to_baseline([vs], own)
    result["observacao"] = ("Resultado informativo da comparação com o baseline; não é "
                            "recomendação de alteração.")
    return result


@mcp.tool()
@_safe_tool
def compare_vs_with_excel_baseline(
    device: str, filename: str, vs_name: str, sheet_name: Optional[str] = None
) -> dict:
    """Compara a Virtual Server pedida (`vs_name` obrigatório) com o baseline de
    propósito de um Excel: pool/porta diferentes do esperado, VS ausente no dispositivo
    ou não documentada no baseline. Considera SOMENTE essa VS."""
    client = _client_for(device)
    return _compare_one_vs(client, vs_name, baseline_excel.load_baseline(filename, sheet_name))


@mcp.tool()
@_safe_tool
def compare_vs_with_sheets_baseline(
    device: str, spreadsheet_id: str, vs_name: str, sheet_range: str = "A1:F1000"
) -> dict:
    """Igual a compare_vs_with_excel_baseline, mas lendo o baseline de um Google
    Sheets. Considera SOMENTE a VS pedida."""
    client = _client_for(device)
    return _compare_one_vs(
        client, vs_name, baseline_sheets.load_baseline_from_sheet(spreadsheet_id, sheet_range))


@mcp.tool()
@_safe_tool
def compare_pool_members_with_baseline(
    device: str, vs_name: str, expected_members: list[str]
) -> dict:
    """Compara os membros reais do pool da VS pedida (`vs_name` obrigatório) com uma
    lista esperada no formato 'ip:porta' (normalmente vinda do baseline do cliente) e
    informa membros esperados não encontrados, encontrados não esperados e fora do ar.
    Resultado INFORMATIVO: descreve a diferença observada, sem recomendar alteração."""
    client = _client_for(device)
    vs = _resolve_vs(client, vs_name)
    pool_name = vs.get("pool_name")
    if not pool_name:
        raise UnsafeInputError("A VS pedida não tem pool associado.")
    live_members = tmsh_parser.parse_pool_members(client.show_pool(pool_name).stdout)
    result = comparator.compare_pool_members_to_baseline(
        vs["vs_name"], live_members, expected_members)
    result["observacao"] = ("Resultado informativo da comparação com o baseline; não é "
                            "recomendação de alteração.")
    return result

# ---------------------------------------------------------------------------
# Validação de tráfego de uma VS — SOMENTE pela API de captura onboard
# ---------------------------------------------------------------------------

# Campos da resposta da API que seguem ao cliente (qualquer outro é descartado).
CAPTURE_RESPONSE_KEYS = ("resultado", "janela", "trafego", "transacoes", "transacoes_omitidas",
                         "membros", "avisos", "tabela_markdown")


def _onbox_for(device_name: str) -> OnboxClient:
    inv = _get_inventory()
    return OnboxClient(inv.get(device_name),
                       connect_timeout_sec=inv.limits.ssh_connect_timeout_sec)


def _check_capture_limits(count: int, timeout_sec: int) -> None:
    limits = _get_inventory().limits
    if not 1 <= int(count) <= limits.tcpdump_max_count:
        raise UnsafeInputError(
            f"count deve estar entre 1 e {limits.tcpdump_max_count} (recebido {count}).")
    if not 1 <= int(timeout_sec) <= limits.tcpdump_max_duration_sec:
        raise UnsafeInputError(
            f"timeout_sec deve estar entre 1 e {limits.tcpdump_max_duration_sec} "
            f"(recebido {timeout_sec}); o padrão é {DEFAULT_WINDOW_SEC} s.")


def _capture_via_api(device: str, payload: dict, timeout_sec: int) -> dict:
    """Pede a captura à API onboard e devolve a resposta enxuta (ou um status
    estruturado). Nada do equipamento além dos campos conhecidos chega ao cliente."""
    status, body = _onbox_for(device).capture(payload, int(timeout_sec))
    body = body if isinstance(body, dict) else {}
    result_status = body.get("status")
    if status == 200 and result_status == "ok":
        return {"status": "ok", **{k: body[k] for k in CAPTURE_RESPONSE_KEYS if k in body}}
    if status == 429 or result_status == "busy":
        return {"status": "busy", "message": MSG_BUSY,
                "retry_after_minutes": BUSY_RETRY_MINUTES}
    if status == 403 or result_status == "blocked":
        return {"status": "blocked", "message": blocked_port_message(1222)}
    if status == 400 or result_status == "invalid":
        return {"status": "invalid",
                "message": str(body.get("message") or "Pedido de captura inválido.")}
    log.warning("captura sem sucesso: HTTP %s, status %r", status, result_status)
    return {"status": "error", "message": MSG_CAPTURE_FAILED}


@mcp.tool()
@_safe_tool
def tcpdump_validate_traffic(
    device: str,
    server_port: Optional[int] = None,
    node_port: Optional[int] = None,
    host: Optional[str] = None,
    count: int = 100,
    timeout_sec: int = DEFAULT_WINDOW_SEC,
    client_addr: Optional[str] = None,
    vs_addr: Optional[str] = None,
    node_addr: Optional[str] = None,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Captura e analisa o tráfego de uma VS por uma janela de 60 s (padrão), que pode
    ser estendida até 180 s com `timeout_sec`: porta da VS (`server_port`), porta do
    membro (`node_port`) e os IPs de cada lado.

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
    1222 não são permitidas), 'invalid' e 'error'."""
    for port, field in ((server_port, "server_port"), (node_port, "node_port")):
        if port is not None:
            try:
                require_capturable_port(port, field)
            except BlockedPortError as exc:      # recusado ANTES de qualquer conexão
                return {"status": "blocked", "message": str(exc)}
    for value, field in ((host, "host"), (client_addr, "client_addr"),
                         (vs_addr, "vs_addr"), (node_addr, "node_addr")):
        if value is not None:
            require_ip(value, field)
    _check_capture_limits(count, timeout_sec)

    payload = {k: v for k, v in (
        ("server_port", server_port), ("node_port", node_port), ("host", host),
        ("vs_addr", vs_addr), ("client_addr", client_addr), ("node_addr", node_addr),
        ("count", int(count)), ("timeout_sec", int(timeout_sec)),
        ("detalhes", bool(detalhes)), ("stan", stan)) if v is not None}
    result = _capture_via_api(device, payload, timeout_sec)

    if result.get("status") == "ok":
        broad = []
        if server_port is not None and vs_addr is None and client_addr is None and host is None:
            broad.append(f"server_port {server_port} sem vs_addr/client_addr")
        if node_port is not None and node_addr is None and host is None:
            broad.append(f"node_port {node_port} sem node_addr")
        if broad:
            result.setdefault("avisos", []).append(
                "Captura abrangente (" + "; ".join(broad) + "): pega qualquer tráfego "
                "nessas portas, inclusive de outras conexões. Com IP e porta confirmados, "
                "repita com vs_addr/client_addr/node_addr para capturar só a conexão "
                "validada.")
    return result


@mcp.tool()
@_safe_tool
def tcpdump_capture_connection(
    device: str,
    connection: str,
    client_addr: Optional[str] = None,
    count: int = 100,
    timeout_sec: int = DEFAULT_WINDOW_SEC,
    detalhes: bool = False,
    stan: Optional[str] = None,
) -> dict:
    """Captura SÓ o tráfego da conexão que o usuário pediu — use esta ferramenta
    sempre que o pedido citar uma conexão pelo nome (ex: "a conexão da Padaria do
    Zezinho"), em vez de montar filtros por porta. A janela padrão é de 60 s e pode ser
    estendida até 180 s com `timeout_sec`.

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
      - status 'ambiguous': o nome bate em mais de uma VS (só a quantidade é
        informada); peça ao usuário o nome completo ou mais específico.
      - status 'not_found': nenhuma VS corresponde; peça o nome exato.

    A resposta traz SOMENTE a VS pedida: nenhuma informação de outras VS, pools ou
    conexões.

    Mesmos status e limites de tcpdump_validate_traffic ('busy', 'blocked', 'error';
    capturas na porta TCP 1222 não são permitidas)."""
    if client_addr is not None:
        require_ip(client_addr, "client_addr")
    _check_capture_limits(count, timeout_sec)
    client = _client_for(device)
    vs_all = tmsh_parser.parse_virtual_servers(client.list_virtual_server_config().stdout)
    matches = tmsh_parser.match_virtual_servers(vs_all, connection)
    # Só a VS pedida: nada de listar as demais.
    if not matches:
        return {
            "status": "not_found",
            "message": f"Nenhuma Virtual Server corresponde a {connection!r}. Nada foi "
                       "capturado — peça ao usuário o nome exato da VS/conexão.",
        }
    if len(matches) > 1:
        return {
            "status": "ambiguous",
            "message": f"{connection!r} corresponde a {len(matches)} conexões — pedido "
                       "abrangente demais para uma captura focada. Nada foi capturado: "
                       "peça ao usuário o nome completo ou mais específico da conexão.",
        }

    vs = matches[0]
    if not vs.get("pool_name"):
        return {"status": "error",
                "message": "A VS pedida não tem pool associado — não há lado servidor "
                           "definido para focar a captura."}

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
        return {"status": "error", "message": MSG_CONNECTION_UNKNOWN}

    try:
        require_capturable_port(vs_port, "server_port")
        for member_addr, member_port in node_members:
            require_ip(member_addr, "membro")
            require_capturable_port(member_port, "node_port")
    except BlockedPortError as exc:
        return {"status": "blocked", "message": str(exc)}
    except UnsafeInputError as exc:
        # IP/porta lidos do dispositivo que não passam na validação (ex: IPv6 com
        # rota-domínio "%1") — não captura no escuro.
        log.warning("valores lidos do dispositivo recusados: %s", exc)
        return {"status": "error", "message": MSG_CONNECTION_UNKNOWN}

    payload = {k: v for k, v in (
        ("server_port", vs_port), ("vs_addr", vs_addr), ("client_addr", client_addr),
        ("members", [{"addr": a, "port": p} for a, p in node_members]),
        ("count", int(count)), ("timeout_sec", int(timeout_sec)),
        ("detalhes", bool(detalhes)), ("stan", stan)) if v is not None}
    result = _capture_via_api(device, payload, timeout_sec)

    compact = {
        "vs": vs["vs_name"],
        "descricao": vs.get("description"),
        "vs_ip_porta": f"{vs_addr}:{vs_port}",
        "pool": vs.get("pool_name"),
        "membros": [f"{a}:{p}" for a, p in node_members],
        "cliente": client_addr,
    }
    return {"conexao": {k: v for k, v in compact.items() if v}, **result}

def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
