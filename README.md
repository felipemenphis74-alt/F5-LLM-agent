# f5-mcp-agent

Agente MCP **somente leitura** para monitoramento e observabilidade de F5 BIG-IP:
status de Virtual Servers e Pools, `show sys connection`, comparação com baseline de
propósito (Excel ou Google Sheets) e validação de padrões de tráfego via `tcpdump`
nativo do TMOS (SYN / SYN-ACK / RST / ACK e marcadores de payload tipo `0800`/`0810`).

## Por que isso é seguro para produção

O agente **nunca** monta comandos tmsh livres a partir de texto do modelo. Cada
ferramenta MCP chama uma função Python parametrizada que:

1. valida todo identificador (nome de VS, pool, device, interface...) contra uma
   allowlist estrita de caracteres ([src/safety.py](src/safety.py));
2. monta o comando tmsh a partir de um **template fixo** — nunca concatenação livre;
3. revalida o comando final contra uma allowlist de prefixos read-only
   (`show ltm virtual`, `list ltm virtual`, `show ltm pool`, `list ltm pool`,
   `show sys connection`, `show net vlan`) e uma blocklist de palavras perigosas
   (`modify`, `create`, `delete`, `save`, `load`, `reboot`, `reset`, `bigstart`, etc.).

O `tcpdump` roda com `-c <N>` (limite duro de pacotes) e `timeout <N>` (limite duro de
duração), ambos configuráveis mas com teto em `inventory.yaml`, e nunca grava `.pcap`
em disco — a saída texto é lida via stdout da sessão SSH e descartada ao final.
Nenhuma ferramenta escreve, salva ou reinicia configuração do BIG-IP.

**Ainda assim:** use uma conta de serviço BIG-IP com role `Auditor` ou `Operator`
(nunca `Administrator`) e, se possível, uma **Resource Administrator partition** ou
role restrita apenas às partições monitoradas. As camadas de código acima são defesa
em profundidade — o controle de acesso definitivo é o RBAC do próprio F5.

## Estrutura

```
f5-mcp-agent/
├── Dockerfile
├── docker-compose.yml          # conveniência para build/test local
├── requirements.txt
├── inventory.example.yaml      # copie para inventory.yaml e edite
├── .env.example                 # copie para .env e edite
├── data/                        # coloque aqui os .xlsx de baseline dos clientes
└── src/
    ├── server.py                # servidor MCP (FastMCP) — ferramentas expostas
    ├── safety.py                # allowlist/validação — camada de segurança
    ├── inventory.py             # carga do inventory.yaml + credenciais via .env
    ├── f5_client.py              # SSH/tmsh/tcpdump (somente comandos read-only)
    ├── tmsh_parser.py            # parsing best-effort da saída tmsh
    ├── tcpdump_parser.py         # parsing da saída texto do tcpdump -X
    ├── baseline_excel.py         # leitura de baseline via .xlsx local
    ├── baseline_sheets.py        # leitura de baseline via Google Sheets (opcional)
    ├── comparator.py             # diff baseline x estado real
    └── _selftest.py              # auto-testes sem depender de F5 real
```

## 1. Pré-requisitos no lado do F5

- Uma conta SSH dedicada ao monitoramento, com **Advanced shell (bash)** habilitado
  (`System > Users > <conta> > Terminal Access: Advanced shell`). É necessário porque
  `tcpdump` não roda dentro do prompt `tmsh` interativo.
- Role recomendada: `Auditor` (somente leitura) ou `Operator`. Nunca `Administrator`.
- Chave de host SSH do F5 conhecida previamente (veja passo 3) para evitar MITM.

## 2. Configuração

```bash
cd f5-mcp-agent
cp inventory.example.yaml inventory.yaml
cp .env.example .env
```

Edite `inventory.yaml` com seus devices (host, porta, partição, nomes das variáveis
de ambiente de credencial) e `.env` com usuário/senha reais — **nunca** coloque
credenciais direto no `inventory.yaml`. Ambos os arquivos já estão no `.gitignore`.

Coloque os arquivos Excel de baseline de cada cliente em `data/` (veja o schema de
colunas esperado no topo de [src/baseline_excel.py](src/baseline_excel.py): `VS Name`,
`Pool Name`, `Expected Port`, `Purpose`, `Expected Members`, `Partition`).

## 3. known_hosts (verificação de host key)

O cliente SSH usa `RejectPolicy` — conexões a hosts desconhecidos são recusadas por
padrão (proteção contra MITM). Popule um `known_hosts` antes do primeiro uso:

```bash
ssh-keyscan -p 22 10.10.10.11 10.10.10.12 > known_hosts
```

Monte esse arquivo em `/root/.ssh/known_hosts` no container (veja
`docker-compose.yml`, já comentado, ou o comando `docker run` abaixo).

## 4. Build

```bash
docker build -t f5-mcp-agent:latest .
```

## 5. Registrar no Claude Desktop / Claude Code

MCP roda sobre stdio — o cliente MCP sobe o container por chamada. Exemplo de entrada
em `claude_desktop_config.json` (ou configuração equivalente de MCP servers):

```json
{
  "mcpServers": {
    "f5-bigip-monitor": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", "F:/Felipe/Claude/f5-mcp-agent/.env",
        "-v", "F:/Felipe/Claude/f5-mcp-agent/inventory.yaml:/app/inventory.yaml:ro",
        "-v", "F:/Felipe/Claude/f5-mcp-agent/data:/app/data:ro",
        "-v", "F:/Felipe/Claude/f5-mcp-agent/known_hosts:/root/.ssh/known_hosts:ro",
        "f5-mcp-agent:latest"
      ]
    }
  }
}
```

Se for usar baseline via Google Sheets, adicione também
`-v .../google-creds.json:/app/google-creds.json:ro` e
`-e GOOGLE_SHEETS_CREDENTIALS_PATH=/app/google-creds.json`.

No **Docker Desktop** (aba MCP Toolkit, se disponível na sua versão), aponte para a
mesma imagem `f5-mcp-agent:latest` com os mesmos volumes/env acima.

## 6. Ferramentas expostas

| Ferramenta | O que faz |
|---|---|
| `list_devices` | Lista devices do inventário (sem credenciais) |
| `get_virtual_server_status` | `tmsh show ltm virtual` — status/estatísticas |
| `get_virtual_server_config` | `tmsh list ltm virtual` — destino/porta/pool |
| `get_pool_status` | `tmsh show ltm pool ... members detail` — disponibilidade dos members |
| `get_sys_connections` | `tmsh show sys connection` com filtros opcionais |
| `get_baseline_from_excel` | Lê baseline de propósito de um `.xlsx` em `data/` |
| `get_baseline_from_sheets` | Lê baseline de uma Google Sheet (opcional) |
| `compare_vs_with_excel_baseline` | Diff completo: todas as VS do device x baseline Excel |
| `compare_vs_with_sheets_baseline` | Igual, com baseline via Sheets |
| `compare_pool_members_with_baseline` | Diff de members de um pool x lista esperada |
| `tcpdump_validate_traffic` | Captura + parsing de SYN/SYN-ACK/RST/ACK e marcadores `0800`/`0810` |

Todas retornam também o comando exato executado (`command`) e, quando aplicável, a
saída bruta (`raw`/`stdout`) para conferência manual — o parsing é "melhor esforço"
porque a formatação exata do `tmsh`/`tcpdump` varia por versão de TMOS.

## 7. Testar sem um F5 real

```bash
docker run --rm --entrypoint python f5-mcp-agent:latest -m src._selftest
```

Isso roda os parsers e os guardrails de segurança contra dados de exemplo (nenhuma
conexão de rede é feita).

## 8. Ajustando o marcador de tráfego 0800/0810

`tcpdump_validate_traffic` procura, no payload de cada pacote, a string ASCII `0800`
(request) ou `0810` (resposta) — convenção comum em handshakes tipo ISO 8583. Se o
protocolo do seu cliente usar outro esquema, ajuste `PAYLOAD_MARKERS` em
[src/tcpdump_parser.py](src/tcpdump_parser.py).

## Limitações conhecidas

- O parsing de `tmsh list/show` é best-effort (regex) — sempre confira o campo `raw`
  quando o resultado parecer incompleto, e valide a sintaxe exata contra a versão de
  TMOS do seu ambiente antes de confiar cegamente no parsing.
- `tcpdump_validate_traffic` requer shell bash habilitado na conta SSH.
- O agente assume uma conexão SSH nova por chamada de ferramenta (sem pool de
  conexões) — simples e evita sessões penduradas, ao custo de um pequeno overhead de
  handshake por chamada.
