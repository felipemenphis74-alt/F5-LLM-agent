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


def require_identifier(value: str, field_name: str) -> str:
    if not is_valid_identifier(value):
        raise UnsafeInputError(
            f"Valor inválido para '{field_name}': {value!r}. "
            "Apenas letras, números, '_', '-', '.', '/' são permitidos."
        )
    return value


def require_port(value, field_name: str) -> int:
    if not is_valid_port(value):
        raise UnsafeInputError(f"Porta inválida para '{field_name}': {value!r}")
    return int(value)


# Prefixos de comando tmsh explicitamente permitidos (somente leitura).
# Qualquer comando final tem que começar com um destes.
ALLOWED_TMSH_PREFIXES = (
    "show ltm virtual",
    "show ltm pool",
    "list ltm virtual",
    "list ltm pool",
    "show sys connection",
    "show ltm virtual-address",
    "show net vlan",
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
        raise UnsafeInputError(f"Comando deve começar com 'tmsh ': {normalized!r}")

    body = normalized[len("tmsh "):].strip()

    if not any(body.startswith(prefix) for prefix in ALLOWED_TMSH_PREFIXES):
        raise UnsafeInputError(
            f"Comando tmsh fora da allowlist read-only: {normalized!r}"
        )

    for token in FORBIDDEN_TOKENS:
        if token in lowered:
            raise UnsafeInputError(
                f"Comando contém token proibido {token!r}: {normalized!r}"
            )

    return normalized


def assert_safe_tcpdump_command(command: str) -> str:
    """Valida um comando tcpdump já montado a partir de template fixo."""
    normalized = command.strip()
    if not normalized.startswith("tcpdump "):
        raise UnsafeInputError(f"Comando deve começar com 'tcpdump ': {normalized!r}")

    lowered = normalized.lower()
    # tcpdump é somente captura/leitura por natureza; ainda assim bloqueamos
    # tentativas de encadear comandos via shell.
    for token in (";", "&&", "|", "`", "$(", ">", ">>"):
        if token in lowered:
            raise UnsafeInputError(
                f"Comando tcpdump contém token proibido {token!r}: {normalized!r}"
            )
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
        raise UnsafeInputError(f"Comando ps fora do esperado: {normalized!r}")
    return normalized
