"""Carrega o inventário de devices F5 (inventory.yaml) e resolve credenciais
a partir de variáveis de ambiente — nunca de texto puro no YAML."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from .safety import is_valid_identifier

DEFAULT_SSH_CONNECT_TIMEOUT = 10
DEFAULT_COMMAND_TIMEOUT = 20
DEFAULT_TCPDUMP_MAX_COUNT = 500
DEFAULT_TCPDUMP_MAX_DURATION = 180


@dataclass
class DeviceCredentials:
    user: str
    password: Optional[str]
    key_path: Optional[str]


@dataclass
class Device:
    name: str
    host: str
    port: int
    partition: str
    tags: list
    credentials: DeviceCredentials


@dataclass
class Limits:
    ssh_connect_timeout_sec: int
    command_timeout_sec: int
    tcpdump_max_count: int
    tcpdump_max_duration_sec: int


class InventoryError(ValueError):
    pass


class Inventory:
    def __init__(self, devices: dict[str, Device], limits: Limits):
        self._devices = devices
        self.limits = limits

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Inventory":
        path = path or os.environ.get("F5_MCP_INVENTORY_PATH", "/app/inventory.yaml")
        p = Path(path)
        if not p.exists():
            raise InventoryError(
                f"Arquivo de inventário não encontrado em {path}. "
                "Copie inventory.example.yaml para inventory.yaml e monte no container."
            )
        with p.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        defaults = raw.get("defaults", {}) or {}
        limits = Limits(
            ssh_connect_timeout_sec=int(os.environ.get(
                "F5_MCP_SSH_CONNECT_TIMEOUT_SEC",
                defaults.get("ssh_connect_timeout_sec", DEFAULT_SSH_CONNECT_TIMEOUT),
            )),
            command_timeout_sec=int(os.environ.get(
                "F5_MCP_COMMAND_TIMEOUT_SEC",
                defaults.get("command_timeout_sec", DEFAULT_COMMAND_TIMEOUT),
            )),
            tcpdump_max_count=int(os.environ.get(
                "F5_MCP_TCPDUMP_MAX_COUNT",
                defaults.get("tcpdump_max_count", DEFAULT_TCPDUMP_MAX_COUNT),
            )),
            tcpdump_max_duration_sec=int(os.environ.get(
                "F5_MCP_TCPDUMP_MAX_DURATION_SEC",
                defaults.get("tcpdump_max_duration_sec", DEFAULT_TCPDUMP_MAX_DURATION),
            )),
        )

        devices: dict[str, Device] = {}
        for entry in raw.get("devices", []) or []:
            name = entry["name"]
            if not is_valid_identifier(name):
                raise InventoryError(f"Nome de device inválido: {name!r}")

            auth_env = entry.get("auth_env", {}) or {}
            user_env = auth_env.get("user")
            password_env = auth_env.get("password")
            key_env = auth_env.get("key_env")

            user = os.environ.get(user_env) if user_env else None
            password = os.environ.get(password_env) if password_env else None
            key_path = os.environ.get(key_env) if key_env else None

            if not user:
                raise InventoryError(
                    f"Device {name!r}: variável de ambiente de usuário "
                    f"({user_env!r}) não definida. Verifique seu .env."
                )
            if not password and not key_path:
                raise InventoryError(
                    f"Device {name!r}: nem senha nem chave SSH definidas via "
                    "variáveis de ambiente. Verifique seu .env."
                )

            devices[name] = Device(
                name=name,
                host=entry["host"],
                port=int(entry.get("port", 22)),
                partition=entry.get("partition", "Common"),
                tags=entry.get("tags", []) or [],
                credentials=DeviceCredentials(user=user, password=password, key_path=key_path),
            )

        if not devices:
            raise InventoryError("Nenhum device definido em inventory.yaml.")

        return cls(devices, limits)

    def list_devices(self) -> list[Device]:
        return list(self._devices.values())

    def get(self, name: str) -> Device:
        if not is_valid_identifier(name):
            raise InventoryError(f"Nome de device inválido: {name!r}")
        device = self._devices.get(name)
        if device is None:
            available = ", ".join(sorted(self._devices)) or "(nenhum)"
            raise InventoryError(f"Device {name!r} não encontrado. Disponíveis: {available}")
        return device
