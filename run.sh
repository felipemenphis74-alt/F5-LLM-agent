#!/usr/bin/env bash
# Sobe o servidor MCP f5-bigip-monitor via stdio, sem Docker (ex.: Ubuntu no WSL2).
# Uso: veja docs/wsl.md. O cliente MCP (Claude Desktop/Code) executa este script
# diretamente ou via `wsl.exe -e /caminho/para/run.sh`.
#
# IMPORTANTE: este script NÃO pode escrever nada em stdout — o stdout é o canal do
# protocolo MCP. Avisos vão para stderr (aparecem no log do cliente MCP).
set -euo pipefail

APP_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$APP_DIR"

warn() { printf 'f5-mcp run.sh: %s\n' "$*" >&2; }

# Carrega o .env (equivalente ao `docker run --env-file`). Lido linha a linha e
# exportado literalmente: sem expansão de $, crases ou espaços — senhas com
# caracteres especiais funcionam. Tolera finais de linha CRLF (arquivo editado no Windows).
ENV_FILE="${F5_MCP_ENV_FILE:-$APP_DIR/.env}"
if [[ -f "$ENV_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    line="${line#export }"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { warn "linha ignorada no .env (nome inválido)"; continue; }
    # remove aspas envolventes, se houver
    if [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi
    export "$key=$value"
  done < "$ENV_FILE"
else
  warn "arquivo .env não encontrado em $ENV_FILE (copie de .env.example)"
fi

# Caminhos que no container ficam em /app/... (padrão do código) — aqui, na pasta do projeto.
# Podem ser sobrescritos no próprio .env.
export PYTHONUNBUFFERED=1
export F5_MCP_INVENTORY_PATH="${F5_MCP_INVENTORY_PATH:-$APP_DIR/inventory.yaml}"
export F5_MCP_DATA_DIR="${F5_MCP_DATA_DIR:-$APP_DIR/data}"
if [[ "${GOOGLE_SHEETS_CREDENTIALS_PATH:-}" == /app/* ]]; then
  # valor herdado do .env.example (caminho do container): traduz para a pasta local
  export GOOGLE_SHEETS_CREDENTIALS_PATH="$APP_DIR/${GOOGLE_SHEETS_CREDENTIALS_PATH#/app/}"
fi

[[ -f "$F5_MCP_INVENTORY_PATH" ]] || warn "inventory não encontrado em $F5_MCP_INVENTORY_PATH (copie de inventory.example.yaml)"
# O cliente SSH usa RejectPolicy e lê ~/.ssh/known_hosts do usuário que roda este script.
[[ -s "$HOME/.ssh/known_hosts" ]] || warn "~/.ssh/known_hosts vazio ou inexistente: as conexões ao F5 serão recusadas (rode ssh-keyscan, veja docs/wsl.md)"

PYTHON="${F5_MCP_PYTHON:-$APP_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  warn "Python do venv não encontrado em $PYTHON (crie com: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"
  exit 1
fi

exec "$PYTHON" -m src.server
