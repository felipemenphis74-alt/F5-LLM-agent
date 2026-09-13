"""Cliente SSH read-only para BIG-IP (TMOS).

Toda execução passa por safety.assert_safe_tmsh_command / assert_safe_tcpdump_command
antes de ir para o wire. Nenhuma função aqui aceita comando livre vindo do chamador de
fora deste módulo — os métodos públicos são parametrizados (nomes de VS, pool, etc.)
e montam o comando internamente a partir de templates fixos.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Optional

import paramiko

from .inventory import Device
from .safety import (
    UnsafeInputError,
    assert_safe_tcpdump_command,
    assert_safe_tmsh_command,
    require_identifier,
    require_port,
)


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int


class F5ConnectionError(RuntimeError):
    pass


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

    def tcpdump_capture(
        self,
        interface: str,
        server_port: Optional[int],
        node_port: Optional[int],
        count: int,
        max_count: int,
        timeout_sec: int,
        max_timeout_sec: int,
    ) -> CommandResult:
        require_identifier(interface, "interface")
        if count < 1 or count > max_count:
            raise UnsafeInputError(f"count deve estar entre 1 e {max_count} (recebido {count})")
        if timeout_sec < 1 or timeout_sec > max_timeout_sec:
            raise UnsafeInputError(
                f"timeout_sec deve estar entre 1 e {max_timeout_sec} (recebido {timeout_sec})"
            )

        port_filters = []
        if server_port is not None:
            require_port(server_port, "server_port")
            port_filters.append(f"port {int(server_port)}")
        if node_port is not None:
            require_port(node_port, "node_port")
            port_filters.append(f"port {int(node_port)}")

        filter_expr = " or ".join(port_filters) if port_filters else ""

        # -nn: sem resolução de nomes/portas (mais rápido, sem depender de DNS)
        # -X: hex+ascii do payload, necessário para localizar marcadores 0800/0810
        # -c: limite duro de pacotes (proteção contra captura sem fim)
        # timeout do lado do cliente SSH (self.command_timeout_sec) + `timeout`
        # remoto garantem que a captura não fica presa mesmo sem atingir -c.
        cmd_parts = ["tcpdump", "-nn", "-X", "-i", shlex.quote(interface), "-c", str(int(count))]
        if filter_expr:
            cmd_parts.append(filter_expr)
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
