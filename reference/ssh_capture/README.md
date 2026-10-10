# Referência: captura de tráfego por SSH (aposentada)

Estes arquivos guardam, **apenas para consulta futura**, o cenário em que o MCP capturava
tráfego executando `tcpdump` por SSH no BIG-IP e interpretando a saída texto (`-X`).
Desde a branch `captura_api_onboard` a captura roda **somente pela API onboard**
(`onbox/` + `src/onbox_client.py`), com janela padrão de 60 s e teto de 180 s.

Nada aqui é importado nem executado pelo MCP: a imagem Docker copia só `src/`, e os
nomes têm sufixo `_ssh` justamente para não colidirem com os módulos ativos.

| Arquivo | Era | Conteúdo |
|---|---|---|
| `f5_client_ssh.py` | `src/f5_client.py` | Cliente SSH com `tcpdump_capture` (perl `alarm`+`exec`, filtro BPF por perna, contagem de processos `tcpdump`, aviso de instâncias do tmm) |
| `safety_ssh.py` | `src/safety.py` | Allowlist tmsh + validação dos comandos `tcpdump`/`ps` e proibição da porta 1222 no filtro |
| `tcpdump_parser_ssh.py` | `src/tcpdump_parser.py` | Parser da saída texto do `tcpdump -nn -X` (flags, ISO 8583, transações por STAN, visão simples/detalhes) |
| `server_ssh.py` | `src/server.py` | Ferramentas MCP de captura chamando o cliente SSH (`_run_capture`) |
| `selftest_ssh.py` | `src/_selftest.py` | Auto-testes do cenário SSH (capturas sintéticas em formato `-X`) |
| `check_app1_ssh.py`, `check_app2_ssh.py` | scripts da raiz | Verificações manuais de VS/pool + captura por SSH, usadas no laboratório |
| `verify_busy_guard_ssh.py` | script da raiz | Teste real da trava de concorrência (`TcpdumpBusyError`) por SSH |

## Como reutilizar

Os módulos usam importações relativas (`from . import tcpdump_parser`) e os scripts
importam `src.*`. Para rodar o cenário antigo, volte os arquivos para `src/` com o nome
original (sem `_ssh`) em um checkout separado — ou use o commit `3fd8797` (último estado
com captura por SSH): `git checkout 3fd8797`.

Os testes de paridade que comparavam este parser com o do script onboard foram
removidos junto com ele; o parser vigente é `onbox/f5_tcpdump.py`.
