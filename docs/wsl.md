# Rodando no Windows com WSL (sem Docker Desktop)

O agente é Python puro e fala MCP por stdio, então não precisa de container: no WSL2 ele
roda num venv, iniciado pelo [`run.sh`](../run.sh). O cliente MCP no Windows chama o
`wsl.exe`, que executa o script dentro do Ubuntu; stdin/stdout atravessam a fronteira
Windows/WSL sem configuração extra. O código do servidor é o mesmo do container.

Se preferir manter a imagem Docker, veja [Alternativa: Docker Engine dentro do WSL](#alternativa-docker-engine-dentro-do-wsl).

## 1. Preparar o WSL

No PowerShell (admin), se o WSL ainda não existir:

```powershell
wsl --install -d Ubuntu-24.04
wsl -l -v          # a distro precisa estar na VERSION 2
```

No Ubuntu:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git openssh-client netcat-openbsd
```

Ubuntu 24.04 traz Python 3.12; a imagem Docker usa 3.11. Ambos funcionam.

## 2. Instalar o agente

Instale na home do Linux (ext4), **não** em `/mnt/c` ou `/mnt/f`: é mais rápido e
permite restringir permissões dos arquivos de credencial.

```bash
git clone https://github.com/felipemenphis74-alt/F5-LLM-agent ~/f5-mcp-agent
cd ~/f5-mcp-agent
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m src._selftest      # deve terminar com "TODOS OS AUTO-TESTES PASSARAM"
```

## 3. Configuração

Mesmos arquivos do cenário Docker, na pasta do projeto:

| Item | No Docker | No WSL |
|---|---|---|
| `.env` | `--env-file` | `~/f5-mcp-agent/.env` (`chmod 600 .env`), carregado pelo `run.sh` |
| `inventory.yaml` | montado em `/app/inventory.yaml` | `~/f5-mcp-agent/inventory.yaml` |
| Baseline `.xlsx` | montado em `/app/data` | `~/f5-mcp-agent/data/` |
| `known_hosts` | montado em `/root/.ssh/known_hosts` | `~/.ssh/known_hosts` do usuário WSL |
| Chave SSH (`key_env`) | arquivo montado no container | caminho Linux, ex. `~/.ssh/f5_monitor` (`chmod 600`) |
| `google-creds.json` (opcional) | montado em `/app/google-creds.json` | `~/f5-mcp-agent/google-creds.json` |

Se a configuração atual está no Windows (ex.: `F:\Felipe\Claude\f5-mcp-agent`), ela
aparece no WSL como `/mnt/f/Felipe/Claude/f5-mcp-agent`:

```bash
cp /mnt/f/Felipe/Claude/f5-mcp-agent/{.env,inventory.yaml} ~/f5-mcp-agent/
cp /mnt/f/Felipe/Claude/f5-mcp-agent/data/*.xlsx ~/f5-mcp-agent/data/
chmod 600 ~/f5-mcp-agent/.env
```

O `run.sh`:

- carrega o `.env` linha a linha, sem expansão de shell (senhas com `$`, espaços ou
  crases funcionam) e tolerando CRLF de arquivos editados no Windows;
- define `F5_MCP_INVENTORY_PATH` e `F5_MCP_DATA_DIR` para a pasta do projeto (o padrão
  do código é `/app/...`, que só existe no container); ambos podem ser sobrescritos no `.env`;
- traduz `GOOGLE_SHEETS_CREDENTIALS_PATH=/app/...` para a pasta do projeto;
- não escreve nada em stdout (canal do MCP); avisos vão para stderr.

Outro `.env`: `F5_MCP_ENV_FILE=/caminho/.env`. Outro Python: `F5_MCP_PYTHON=/caminho/python`.

### known_hosts

O cliente SSH usa `RejectPolicy` e lê `~/.ssh/known_hosts` **do usuário que roda o
`run.sh`**. Sem a chave do F5 ali, toda conexão é recusada:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keyscan -p 22 10.10.10.11 10.10.10.12 >> ~/.ssh/known_hosts
```

Confira a impressão digital com a equipe do F5 antes de confiar no resultado do `ssh-keyscan`.

## 4. Rede do WSL até o F5

O agente só abre conexões de saída: SSH (porta do `inventory.yaml`, padrão 22) e HTTPS
443 para a API de captura onboard. Nenhuma porta de entrada.

- **NAT (padrão do WSL2):** o tráfego sai pelo IP da máquina Windows, como no Docker
  Desktop. Se o Docker alcançava o F5, o WSL também deve alcançar.
- **VPN/proxy corporativo:** o NAT costuma perder rotas e DNS da VPN. No Windows 11 22H2+
  copie [`wsl/wslconfig.example`](../wsl/wslconfig.example) para `%UserProfile%\.wslconfig`
  (`networkingMode=mirrored`) e rode `wsl --shutdown`.

Teste de dentro do WSL:

```bash
nc -vz <ip-gerencia-f5> 22
curl -kI https://<ip-gerencia-f5>/
```

## 5. Registrar no Claude

Mantenha o nome `f5-bigip-monitor`: o [agente](../agent/f5-bigip-assistant.md) referencia
as ferramentas como `mcp__f5-bigip-monitor__*`. Remova a entrada antiga `docker run` e a
`MCP_DOCKER` (gateway do MCP Toolkit do Docker Desktop).

**Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json`) ou **Claude Code no
Windows** (`.mcp.json`) — exemplo em [`wsl/claude_desktop_config.example.json`](../wsl/claude_desktop_config.example.json):

```json
{
  "mcpServers": {
    "f5-bigip-monitor": {
      "command": "C:\\Windows\\System32\\wsl.exe",
      "args": ["-d", "Ubuntu-24.04", "-e", "/home/SEU_USUARIO/f5-mcp-agent/run.sh"]
    }
  }
}
```

- Use `-e` (executa direto, sem shell de login), para nenhuma mensagem do `.bashrc`
  vazar para o stdout e corromper o MCP.
- Troque `SEU_USUARIO` e confira o nome da distro com `wsl -l -v`.
- Reinicie o Claude Desktop. O stderr do servidor fica em
  `%APPDATA%\Claude\logs\mcp-server-f5-bigip-monitor.log`.

**Claude Code dentro do WSL:**

```bash
claude mcp add f5-bigip-monitor -- /home/SEU_USUARIO/f5-mcp-agent/run.sh
```

### Isolamento

Sem container, o processo roda como o seu usuário do WSL e enxerga a home dele. Para se
aproximar do isolamento do Docker, use um usuário Linux só para o agente:

```bash
sudo adduser --disabled-password --gecos "" f5mcp
# instale o projeto em /home/f5mcp/f5-mcp-agent e o known_hosts em /home/f5mcp/.ssh/
```

e no Claude: `"args": ["-d", "Ubuntu-24.04", "-u", "f5mcp", "-e", "/home/f5mcp/f5-mcp-agent/run.sh"]`.

## 6. Validação

- [ ] `.venv/bin/python -m src._selftest` passa
- [ ] `nc -vz <ip-f5> 22` e `curl -kI https://<ip-f5>/` respondem de dentro do WSL
- [ ] `ssh -o StrictHostKeyChecking=yes <usuario>@<ip-f5>` não pergunta a host key
- [ ] `./run.sh < /dev/null` não imprime nada em stdout (avisos em stderr são esperados se faltar arquivo)
- [ ] O Claude mostra `f5-bigip-monitor` com 12 ferramentas
- [ ] `list_devices` devolve os nomes do inventário e `get_virtual_server_status` responde para uma VS conhecida

Para atualizar: `git pull && .venv/bin/pip install -r requirements.txt`.

## Alternativa: Docker Engine dentro do WSL

Mantém a imagem `f5-mcp-agent:latest` e o isolamento de container, sem Docker Desktop
(o Docker Engine CE não exige a licença do Desktop).

1. Confirme `systemd=true` na seção `[boot]` de `/etc/wsl.conf` (padrão no Ubuntu 24.04).
2. Instale `docker-ce`, `docker-ce-cli` e `containerd.io` pelo
   [repositório oficial](https://docs.docker.com/engine/install/ubuntu/); depois
   `sudo usermod -aG docker $USER` e `wsl --shutdown`.
3. `cd ~/f5-mcp-agent && docker build -t f5-mcp-agent:latest .`
4. No Claude, o mesmo `docker run` do README com `wsl.exe` na frente e caminhos Linux:

```json
{
  "mcpServers": {
    "f5-bigip-monitor": {
      "command": "C:\\Windows\\System32\\wsl.exe",
      "args": ["-d", "Ubuntu-24.04", "-e", "docker", "run", "-i", "--rm",
               "--env-file", "/home/SEU_USUARIO/f5-mcp-agent/.env",
               "-v", "/home/SEU_USUARIO/f5-mcp-agent/inventory.yaml:/app/inventory.yaml:ro",
               "-v", "/home/SEU_USUARIO/f5-mcp-agent/data:/app/data:ro",
               "-v", "/home/SEU_USUARIO/.ssh/known_hosts:/root/.ssh/known_hosts:ro",
               "f5-mcp-agent:latest"]
    }
  }
}
```

Custo: daemon para manter, `docker build` a cada mudança de código e partida um pouco
mais lenta por chamada.
