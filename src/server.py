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
        "Nunca realiza alterações de configuração."
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
) -> dict:
    """Executa uma captura tcpdump somente-leitura no BIG-IP (via SSH, sem gravar
    .pcap) filtrando por porta de servidor (VS), porta de node/pool member e,
    opcionalmente, por `host` (IP do pool member/node — afunila a captura a um device
    específico em vez de qualquer tráfego na(s) porta(s), útil ao validar um pool). A
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

    Portas proibidas: capturas na porta TCP 1222 (porta de conexão com a captura
    RISe) estão desabilitadas para esta ferramenta — um pedido envolvendo essa porta
    é recusado na validação dos parâmetros e retorna status 'blocked', sem sequer
    conectar no F5.

    Requer que a conta SSH tenha 'Advanced shell (bash)' habilitado no BIG-IP (tcpdump
    não roda dentro do prompt tmsh)."""
    inv = _get_inventory()
    client = _client_for(device)
    try:
        result = client.tcpdump_capture(
            interface=interface,
            server_port=server_port,
            node_port=node_port,
            host=host,
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

    packets = tcpdump_parser.parse_tcpdump_output(result.stdout)
    summary = tcpdump_parser.summarize(packets)
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
        "warnings": describe_tcpdump_warnings(result.stderr),
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
