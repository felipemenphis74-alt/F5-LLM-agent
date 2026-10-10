"""Cliente SSH read-only para BIG-IP (TMOS).

Toda execução passa por safety.assert_safe_tmsh_command / assert_safe_tcpdump_command /
assert_safe_ps_command antes de ir para o wire. Nenhuma função aqui aceita comando
livre vindo do chamador de fora deste módulo — os métodos públicos são parametrizados
(nomes de VS, pool, etc.) e montam o comando internamente a partir de templates fixos.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Optional

import paramiko

from .inventory import Device
from .safety import (
    UnsafeInputError,
    assert_safe_ps_command,
    assert_safe_tcpdump_command,
    assert_safe_tmsh_command,
    require_capturable_port,
    require_identifier,
    require_port,
)

# Teto de capturas tcpdump TOTAL simultâneas no F5, contando a que o agente está
# prestes a iniciar. Ou seja: se já houver >= MAX_CONCURRENT_TCPDUMP rodando, o
# agente recusa iniciar mais uma (senão o total passaria do teto). O agente NUNCA
# interrompe ou altera capturas já em execução — só decide não empilhar mais uma.
MAX_CONCURRENT_TCPDUMP = 2

# Retry sugerido ao usuário quando a captura é recusada por excesso de concorrência.
TCPDUMP_BUSY_RETRY_MINUTES = 5

# Trecho que o próprio TMOS imprime no stderr do tcpdump quando o número de capturas
# tmm concorrentes passa do recomendado. Pode aparecer mesmo com o nosso check antes
# (corrida entre o check e o tcpdump começar de fato — o TMM pode contar de forma
# diferente de processos tcpdump em userland/`ps`). Quando aparece, é reportado como
# warning explícito pro chamador, mesmo que a captura em si tenha rodado.
TMM_TCPDUMP_WARNING_MARKER = "tmm tcpdump instances"


def describe_tcpdump_warnings(stderr: str) -> list[str]:
    """Varre o stderr de uma captura já executada por avisos conhecidos do próprio
    TMOS sobre concorrência de tcpdump, para reportar explicitamente ao chamador em
    vez de deixar enterrado no stderr bruto."""
    warnings = []
    if TMM_TCPDUMP_WARNING_MARKER in stderr:
        for line in stderr.splitlines():
            if TMM_TCPDUMP_WARNING_MARKER in line:
                warnings.append(
                    f"O F5 reportou concorrência de tcpdump acima do recomendado "
                    f"durante esta captura: {line.strip()!r}. Considere aguardar "
                    f"~{TCPDUMP_BUSY_RETRY_MINUTES} minutos antes de rodar outra."
                )
    return warnings


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int


class F5ConnectionError(RuntimeError):
    pass


class TcpdumpBusyError(RuntimeError):
    """Levantado quando já existem capturas tcpdump demais em execução no host.

    O agente nunca mata/altera capturas existentes — isso é só um freio para não
    empilhar mais uma captura em cima de outras que já podem estar rodando (de
    outro operador, outro chamado deste mesmo agente, etc.)."""


class F5Client:
    """Uma conexão SSH sob demanda por chamada (sem estado persistente entre
    chamadas de ferramenta MCP) — simples e evita conexões penduradas."""

    def __init__(self, device: Device, connect_timeout_sec: int, command_timeout_sec: int):
        self.device = device
        self.connect_timeout_sec = connect_timeout_sec
        self.command_timeout_sec = command_timeout_sec

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        # RejectPolicy exige known_hosts previamente populado (monte um known_hosts
        # somente-leitura no container). Isso evita MITM silencioso na rede interna.
        try:
            client.load_system_host_keys()
        except Exception:
            pass
        creds = self.device.credentials
        try:
            client.connect(
                hostname=self.device.host,
                port=self.device.port,
                username=creds.user,
                password=creds.password,
                key_filename=creds.key_path,
                timeout=self.connect_timeout_sec,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.ssh_exception.SSHException as exc:
            raise F5ConnectionError(
                f"Falha ao conectar em {self.device.name} ({self.device.host}): {exc}. "
                "Se o erro mencionar host key, popule known_hosts com a chave do F5 "
                "(ssh-keyscan) antes de usar RejectPolicy em produção."
            ) from exc
        return client

    def _run(self, command: str) -> CommandResult:
        client = self._connect()
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=self.command_timeout_sec)
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            status = stdout.channel.recv_exit_status()
            return CommandResult(command=command, stdout=out, stderr=err, exit_status=status)
        finally:
            client.close()

    # ---- tmsh: leitura de Virtual Servers -------------------------------------

    def show_virtual_servers(self, vs_name: Optional[str] = None) -> CommandResult:
        if vs_name is not None:
            require_identifier(vs_name, "vs_name")
            cmd = f"tmsh show ltm virtual {shlex.quote(vs_name)}"
        else:
            cmd = "tmsh show ltm virtual"
        return self._run(assert_safe_tmsh_command(cmd))

    def list_virtual_server_config(self, vs_name: Optional[str] = None) -> CommandResult:
        """`list` (não `show`) traz a config declarada: pool associado, portas,
        perfis — útil para comparar 'propósito' com o baseline do Excel."""
        if vs_name is not None:
            require_identifier(vs_name, "vs_name")
            cmd = f"tmsh list ltm virtual {shlex.quote(vs_name)}"
        else:
            cmd = "tmsh list ltm virtual"
        return self._run(assert_safe_tmsh_command(cmd))

    # ---- tmsh: leitura de Pools -------------------------------------------------

    def show_pool(self, pool_name: Optional[str] = None) -> CommandResult:
        if pool_name is not None:
            require_identifier(pool_name, "pool_name")
            cmd = f"tmsh show ltm pool {shlex.quote(pool_name)} members detail"
        else:
            cmd = "tmsh show ltm pool"
        return self._run(assert_safe_tmsh_command(cmd))

    def list_pool_config(self, pool_name: Optional[str] = None) -> CommandResult:
        if pool_name is not None:
            require_identifier(pool_name, "pool_name")
            cmd = f"tmsh list ltm pool {shlex.quote(pool_name)} members"
        else:
            cmd = "tmsh list ltm pool"
        return self._run(assert_safe_tmsh_command(cmd))

    # ---- tmsh: sys connection ---------------------------------------------------

    def show_sys_connections(
        self,
        client_addr: Optional[str] = None,
        server_addr: Optional[str] = None,
        server_port: Optional[int] = None,
        client_port: Optional[int] = None,
    ) -> CommandResult:
        parts = ["tmsh show sys connection"]
        if client_addr is not None:
            require_identifier(client_addr, "client_addr")
            parts += ["cs-client-addr", shlex.quote(client_addr)]
        if server_addr is not None:
            require_identifier(server_addr, "server_addr")
            parts += ["cs-server-addr", shlex.quote(server_addr)]
        if server_port is not None:
            require_port(server_port, "server_port")
            parts += ["cs-server-port", str(int(server_port))]
        if client_port is not None:
            require_port(client_port, "client_port")
            parts += ["cs-client-port", str(int(client_port))]
        cmd = " ".join(parts)
        return self._run(assert_safe_tmsh_command(cmd))

    # ---- tcpdump (nativo do TMOS, somente captura/leitura) -----------------------

    def count_running_tcpdump(self) -> int:
        """Conta quantos processos `tcpdump` já estão rodando no host — sem alterar
        ou finalizar nenhum deles. Usado como guarda de concorrência antes de iniciar
        uma nova captura."""
        result = self._run(assert_safe_ps_command("ps -eo pid,comm"))
        count = 0
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # formato de "ps -eo pid,comm": "<pid> <comm>" — comm pode vir com path
            # (ex: "/usr/sbin/tcpdump") dependendo da distro/versão do ps.
            _, _, comm = line.partition(" ")
            if "tcpdump" in comm.strip():
                count += 1
        return count

    def tcpdump_capture(
        self,
        interface: str,
        server_port: Optional[int],
        node_port: Optional[int],
        count: int,
        max_count: int,
        timeout_sec: int,
        max_timeout_sec: int,
        host: Optional[str] = None,
    ) -> CommandResult:
        require_identifier(interface, "interface")
        if count < 1 or count > max_count:
            raise UnsafeInputError(f"count deve estar entre 1 e {max_count} (recebido {count})")
        if timeout_sec < 1 or timeout_sec > max_timeout_sec:
            raise UnsafeInputError(
                f"timeout_sec deve estar entre 1 e {max_timeout_sec} (recebido {timeout_sec})"
            )
        if host is not None:
            require_identifier(host, "host")

        # Portas proibidas (safety.BLOCKED_TCPDUMP_PORTS, ex: 1222 = conexão com a
        # captura RISe): recusadas AQUI, antes de qualquer conexão SSH — uma captura
        # pedida explicitamente nessas portas nunca chega nem a consultar o F5.
        port_filters = []
        if server_port is not None:
            require_capturable_port(server_port, "server_port")
            port_filters.append(f"port {int(server_port)}")
        if node_port is not None:
            require_capturable_port(node_port, "node_port")
            port_filters.append(f"port {int(node_port)}")

        # Guarda de concorrência: nunca deixa o TOTAL de capturas simultâneas (as que
        # já existem + esta que estamos prestes a iniciar) passar de
        # MAX_CONCURRENT_TCPDUMP. Ou seja, recusa já a partir de
        # `running >= MAX_CONCURRENT_TCPDUMP` — não espera passar do teto pra agir.
        # Não interrompe/altera nada que já esteja em execução — só recusa iniciar.
        running = self.count_running_tcpdump()
        if running >= MAX_CONCURRENT_TCPDUMP:
            raise TcpdumpBusyError(
                f"Já existem {running} captura(s) tcpdump em execução em "
                f"{self.device.name} — iniciar mais uma passaria do teto de "
                f"{MAX_CONCURRENT_TCPDUMP} simultâneas. O agente não inicia uma nova "
                "captura nem interrompe as existentes — tente novamente em "
                f"~{TCPDUMP_BUSY_RETRY_MINUTES} minutos."
            )

        # Filtros de porta se combinam por OR entre si; o filtro de host (quando
        # informado) sempre AND com o resto, para afunilar a captura a um device
        # específico em vez de qualquer tráfego que passe pela(s) porta(s).
        filter_terms = []
        if port_filters:
            filter_terms.append(
                "(" + " or ".join(port_filters) + ")" if len(port_filters) > 1 else port_filters[0]
            )
        if host is not None:
            filter_terms.append(f"host {shlex.quote(host)}")
        filter_expr = " and ".join(filter_terms)

        # -nn: sem resolução de nomes/portas (mais rápido, sem depender de DNS)
        # -X: hex+ascii do payload, necessário para localizar marcadores 0800/0810
        # -c: limite duro de pacotes (proteção contra captura sem fim)
        # timeout do lado do cliente SSH (self.command_timeout_sec) + `timeout`
        # remoto garantem que a captura não fica presa mesmo sem atingir -c.
        cmd_parts = ["tcpdump", "-nn", "-X", "-i", shlex.quote(interface), "-c", str(int(count))]
        if filter_expr:
            # O filtro BPF vai como UM argumento, entre aspas: sem isso o shell remoto
            # recusa os parenteses de "(port A or port B)" (erro de sintaxe, exit 1).
            cmd_parts.append(shlex.quote(filter_expr))
        tcpdump_cmd = " ".join(cmd_parts)
        assert_safe_tcpdump_command(tcpdump_cmd)

        # `timeout N <cmd>` é um utilitário padrão do shell (coreutils), não do tmsh;
        # está disponível no bash do TMOS. Isso garante que a captura nunca ultrapassa
        # o limite mesmo se -c não for atingido (ex: pouco tráfego).
        full_cmd = f"timeout {int(timeout_sec)} {tcpdump_cmd}"

        prev_timeout = self.command_timeout_sec
        try:
            # margem de alguns segundos além do timeout do próprio tcpdump remoto
            self.command_timeout_sec = timeout_sec + 10
            return self._run(full_cmd)
        finally:
            self.command_timeout_sec = prev_timeout
