"""Cliente da API de captura ONBOARD (extensão iControl LX `/mgmt/shared/f5_tcpdump`).

A captura de tráfego roda SOMENTE pela API onboard: o MCP não executa tcpdump por SSH.
Este módulo só faz o transporte (login, POST, consulta do job); a validação e a safety
(porta 1222, limites, concorrência) são do script no equipamento, que é a autoridade.

Nada aqui devolve ao chamador detalhes de rede/credenciais: falhas de transporte viram
`F5ConnectionError` (o servidor MCP troca por mensagem genérica; o detalhe vai ao log).
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional

from .f5_client import F5ConnectionError
from .inventory import Device

log = logging.getLogger("f5-mcp.onbox")

CAPTURE_PATH = "/mgmt/shared/f5_tcpdump"
LOGIN_PATH = "/mgmt/shared/authn/login"
POLL_INTERVAL_SEC = 3.0
# folga além da janela pedida: início do script, parse e fila do worker
EXTRA_WAIT_SEC = 45


class OnboxClient:
    """Uma sessão (login → captura) por chamada de ferramenta, sem estado persistente."""

    def __init__(
        self,
        device: Device,
        host: Optional[str] = None,
        port: Optional[int] = None,
        verify_tls: Optional[bool] = None,
        ca_bundle: Optional[str] = None,
        connect_timeout_sec: int = 15,
    ):
        self.device = device
        self.host = host or os.environ.get("F5_MCP_REST_HOST") or device.host
        self.port = int(port or os.environ.get("F5_MCP_REST_PORT") or 443)
        if verify_tls is None:
            verify_tls = os.environ.get("F5_MCP_REST_VERIFY_TLS", "false").strip().lower() in (
                "1", "true", "yes", "sim")
        self.ca_bundle = ca_bundle or os.environ.get("F5_MCP_REST_CA_BUNDLE") or None
        self.verify_tls = bool(verify_tls or self.ca_bundle)
        self.connect_timeout_sec = connect_timeout_sec

    # ---- transporte ---------------------------------------------------------------

    def _context(self) -> ssl.SSLContext:
        if self.verify_tls:
            return ssl.create_default_context(cafile=self.ca_bundle)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # certificado autoassinado do equipamento (lab)
        return ctx

    def _http(self, method: str, path: str, body: Optional[dict] = None,
              token: Optional[str] = None, timeout: Optional[float] = None) -> tuple[int, dict]:
        """(status HTTP, corpo JSON). Falha de rede/TLS -> F5ConnectionError."""
        url = f"https://{self.host}:{self.port}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("X-F5-Auth-Token", token)
        try:
            with urllib.request.urlopen(request, context=self._context(),
                                        timeout=timeout or self.connect_timeout_sec) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            raise F5ConnectionError(f"REST indisponível em {self.host}: {exc}") from exc
        try:
            return status, json.loads(raw.decode("utf-8", "replace") or "{}")
        except ValueError:
            return status, {}

    def _login(self) -> str:
        creds = self.device.credentials
        if not creds.password:
            raise F5ConnectionError("autenticação REST exige senha configurada")
        status, body = self._http("POST", LOGIN_PATH, {
            "username": creds.user, "password": creds.password, "loginProviderName": "tmos"})
        token = (body.get("token") or {}).get("token") if isinstance(body, dict) else None
        if status != 200 or not token:
            raise F5ConnectionError(f"login REST recusado (HTTP {status})")
        return token

    # ---- captura ------------------------------------------------------------------

    def capture(self, payload: dict, window_sec: int) -> tuple[int, dict]:
        """Pede a captura e devolve (HTTP, corpo final). Respostas rápidas (invalid/
        blocked/busy/captura curta) voltam direto; 202 = captura em andamento, e o
        resultado é consultado por `job_id` até o fim da janela + folga."""
        token = self._login()
        status, body = self._http("POST", CAPTURE_PATH, payload, token=token, timeout=30)
        job = body.get("job_id") if isinstance(body, dict) else None
        deadline = time.monotonic() + window_sec + EXTRA_WAIT_SEC
        while status == 202 and job:
            if time.monotonic() >= deadline:
                log.warning("captura %s sem resposta dentro do prazo", job)
                return 504, {"status": "error"}
            time.sleep(POLL_INTERVAL_SEC)
            status, body = self._http("GET", f"{CAPTURE_PATH}?job_id={job}", token=token,
                                      timeout=30)
        return status, body
