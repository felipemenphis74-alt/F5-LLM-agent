"""
Camada de segurança do agente.

Regra de ouro: este agente NUNCA monta um comando tmsh/shell livre a partir de texto
vindo do modelo. Toda ferramenta MCP chama uma função Python parametrizada aqui dentro,
que:
  1. valida cada identificador (nome de VS, pool, partição, interface, device...)
     contra uma allowlist de caracteres;
  2. monta o comando tmsh a partir de um TEMPLATE fixo (nunca concatenação livre);
  3. antes de enviar, re-valida o comando final contra uma allowlist de prefixos
     read-only e uma blocklist de palavras perigosas (defesa em profundidade).

Isso garante que mesmo que um valor malicioso tente "escapar" (ex: nome de VS contendo
`; tmsh delete ltm virtual all`), a validação de identificador já rejeita antes de
chegar perto de montar o comando.
"""
import ipaddress
import re

# Identificadores (nomes de VS, pool, partição, device, interface...) só podem conter
# isso. Suficiente para convenções de nomenclatura F5 (letras, números, _ - . /).
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_\-./]{1,255}$")

# Portas: inteiro 1-65535
def is_valid_port(value) -> bool:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= p <= 65535


def is_valid_identifier(value: str) -> bool:
    return isinstance(value, str) and bool(IDENTIFIER_RE.match(value))


class UnsafeInputError(ValueError):
    """Levantado quando um parâmetro de entrada falha na validação de segurança."""


class CommandNotAllowedError(UnsafeInputError):
    """Levantado quando um comando JÁ MONTADO fica fora da allowlist (bug interno ou
    tentativa de bypass). Diferente de UnsafeInputError "de entrada": a mensagem cita o
    comando e NUNCA deve chegar ao cliente da ferramenta — o servidor MCP a troca por
    uma resposta genérica."""


def require_identifier(value: str, field_name: str) -> str:
    if not is_valid_identifier(value):
        raise UnsafeInputError(
            f"Valor inválido para '{field_name}': {value!r}. "
            "Apenas letras, números, '_', '-', '.', '/' são permitidos."
        )
    return value


def require_ip(value: str, field_name: str) -> str:
    """Endereço IPv4/IPv6 literal (sem máscara nem nome) — usado nos filtros de
    captura por IP, onde um nome ou texto livre não faz sentido."""
    try:
        ipaddress.ip_address(value)
    except (TypeError, ValueError):
        raise UnsafeInputError(f"Endereço IP inválido para '{field_name}': {value!r}")
    return value


def require_port(value, field_name: str) -> int:
    if not is_valid_port(value):
        raise UnsafeInputError(f"Porta inválida para '{field_name}': {value!r}")
    return int(value)


# Prefixos de comando tmsh explicitamente permitidos (somente leitura). Só o que
# descreve Virtual Servers, seus pools e as conexões delas — nada da configuração do
# dispositivo (NTP, ARP, VLANs, autenticação, rede, sistema...). Qualquer comando final
# tem que ser exatamente um destes ou começar com um deles seguido de espaço (então
# "list ltm virtual-address" NÃO casa com "list ltm virtual").
ALLOWED_TMSH_PREFIXES = (
    "show ltm virtual",
    "show ltm pool",
    "list ltm virtual",
    "list ltm pool",
    "show sys connection",
)

# Palavras que NUNCA podem aparecer em um comando enviado ao F5, mesmo dentro
# dos prefixos permitidos acima (defesa em profundidade contra bypass).
FORBIDDEN_TOKENS = (
    "modify", "create", "delete", "save", "load", "reboot", "reset",
    "restart", "install", "upgrade", "bigstart", "tmsh -c", "rm ", "mv ",
    "cp ", ">", ">>", "|", ";", "&&", "$(", "`", "reset-stats",
    "shutdown", "config", "edit", "run util", "run /util",
)


def assert_safe_tmsh_command(command: str) -> str:
    """Valida um comando tmsh já montado a partir de templates fixos.

    Levanta UnsafeInputError se o comando não for reconhecidamente read-only.
    """
    normalized = command.strip()
    lowered = normalized.lower()

    if not normalized.startswith("tmsh "):
        raise CommandNotAllowedError(f"Comando deve começar com 'tmsh ': {normalized!r}")

    body = normalized[len("tmsh "):].strip()

    if not any(body == prefix or body.startswith(prefix + " ")
               for prefix in ALLOWED_TMSH_PREFIXES):
        raise CommandNotAllowedError(
            f"Comando tmsh fora da allowlist read-only: {normalized!r}"
        )

    for token in FORBIDDEN_TOKENS:
        if token in lowered:
            raise CommandNotAllowedError(
                f"Comando contém token proibido {token!r}: {normalized!r}"
            )

    return normalized


# Portas TCP em que esta ferramenta NUNCA executa captura (tcpdump), mesmo que o
# chamador peça explicitamente. Chave = porta; valor = o que ela é (usado na mensagem
# mostrada ao usuário). Para bloquear outra porta, basta incluí-la aqui.
BLOCKED_TCPDUMP_PORTS = {
    1222: "porta de conexão com a captura RISe",
}


class BlockedPortError(UnsafeInputError):
    """Levantado quando uma captura tcpdump envolveria uma porta proibida para esta
    ferramenta (BLOCKED_TCPDUMP_PORTS). Subclasse de UnsafeInputError."""


def blocked_port_message(port: int) -> str:
    return (
        f"Capturas na porta TCP {port} ({BLOCKED_TCPDUMP_PORTS[port]}) estão "
        "desabilitadas para esta ferramenta."
    )


def require_capturable_port(value, field_name: str) -> int:
    """Como require_port, mas também recusa portas em BLOCKED_TCPDUMP_PORTS."""
    port = require_port(value, field_name)
    if port in BLOCKED_TCPDUMP_PORTS:
        raise BlockedPortError(blocked_port_message(port))
    return port


_PORT_TOKEN_RE = re.compile(r"\bport\s+(\S+)")
_PORTRANGE_RE = re.compile(r"\bportrange\s+(\d+)\s*-\s*(\d+)")


def _assert_no_blocked_ports(normalized: str, lowered: str) -> None:
    """Defesa em profundidade na validação do comando JÁ MONTADO, independente de
    quem o montou: nenhuma porta bloqueada pode aparecer no filtro (`port N`,
    `src/dst port N`, `portrange A-B`). A validação principal acontece antes, nos
    parâmetros de entrada (require_capturable_port) — o filtro BPF em si não é
    alterado."""
    for match in _PORT_TOKEN_RE.finditer(lowered):
        # o filtro chega entre aspas e pode ter parenteses colados: "'port 15000)'"
        token = match.group(1).strip("()'\"")
        if not token.isdigit():
            # só geramos portas decimais; qualquer outra forma (nome de serviço,
            # hex...) não dá para comparar com a lista de bloqueio -> recusa.
            raise CommandNotAllowedError(
                f"Porta em formato não suportado no filtro tcpdump {token!r}: {normalized!r}"
            )
        if int(token) in BLOCKED_TCPDUMP_PORTS:
            raise BlockedPortError(blocked_port_message(int(token)))

    for match in _PORTRANGE_RE.finditer(lowered):
        low, high = int(match.group(1)), int(match.group(2))
        for port in BLOCKED_TCPDUMP_PORTS:
            if low <= port <= high:
                raise BlockedPortError(blocked_port_message(port))


def assert_safe_tcpdump_command(command: str) -> str:
    """Valida um comando tcpdump já montado a partir de template fixo."""
    normalized = command.strip()
    if not normalized.startswith("tcpdump "):
        raise CommandNotAllowedError(f"Comando deve começar com 'tcpdump ': {normalized!r}")

    lowered = normalized.lower()
    # tcpdump é somente captura/leitura por natureza; ainda assim bloqueamos
    # tentativas de encadear comandos via shell.
    for token in (";", "&&", "|", "`", "$(", ">", ">>"):
        if token in lowered:
            raise CommandNotAllowedError(
                f"Comando tcpdump contém token proibido {token!r}: {normalized!r}"
            )

    _assert_no_blocked_ports(normalized, lowered)
    return normalized


# Comando fixo usado só para CONTAR processos tcpdump já em execução no host, como
# guarda de concorrência antes de iniciar uma nova captura (nunca para checar mais
# nada além disso, e nunca para matar/alterar processos existentes). Allowlist
# fechada — sem interpolação de entrada externa, nunca aceita variação.
ALLOWED_PS_COMMANDS = (
    "ps -eo pid,comm",
)


def assert_safe_ps_command(command: str) -> str:
    """Valida o comando fixo de listagem de processos usado para checar quantas
    capturas tcpdump já estão rodando antes de iniciar uma nova."""
    normalized = command.strip()
    if normalized not in ALLOWED_PS_COMMANDS:
        raise CommandNotAllowedError(f"Comando ps fora do esperado: {normalized!r}")
    return normalized
