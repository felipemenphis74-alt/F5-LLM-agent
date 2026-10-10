# onbox — captura tcpdump + safety + parsing ISO 8583 dentro do BIG-IP

`f5_tcpdump.py` junta num único arquivo o que o agente MCP faz hoje em três
lugares (captura via SSH, `safety.py`, `tcpdump_parser.py`), para rodar **no
equipamento** e ser exposto por uma API (iControl LX). Só biblioteca padrão e
escrito para Python **2.7 e 3.x** (o Python do TMOS pode ser 2.7).

## Contrato

Entrada (JSON, stdin ou `--request`): todos opcionais

| campo | tipo | observação |
|---|---|---|
| `interface` | string | `any` por padrão; só `[A-Za-z0-9_.-]`, sem `-` inicial |
| `server_port`, `node_port` | int 1–65535 | **1222 é bloqueada** |
| `host` | string | só IPv4/IPv6 literal (sem DNS) |
| `count` | int 1–500 | padrão 100 |
| `timeout_sec` | int 1–180 | padrão 20 |
| `vs_addr` | string | IPv4/IPv6 literal da VS. **Não entra no filtro**: só permite, junto de `server_port`, separar na resposta o tráfego da VS das sondas do monitor do pool |
| `verbose` | bool | `false` (padrão) = resposta simples; `true` = retorno completo, para depurar |
| `detalhes` | bool | `true` = cada transação traz `campos`, `trajeto`, `saltos`, `rtt_ms` e a resposta inclui `tabela_markdown` |
| `stan` | string 1–12 dígitos | com `detalhes`, restringe às transações com esse STAN (bit 11) |

Campos desconhecidos são recusados. Saída (JSON): `status` =
`ok | busy | blocked | invalid | error`.

* `ok` (**resposta simples**, padrão): só o tráfego da VS pedida —
  `resultado` (veredito em uma frase), `trafego` (`conexoes`, `pacotes`, `syn`,
  `syn_ack`, `rst`, `fin`, `mensagens_iso`), `transacoes` (ISO 8583 agrupadas por STAN:
  `hora`, `stan`, `pedido`, `resposta`, `respondida`, `tipo`, `origem`; até 50),
  `janela` (`max_s`, `encerrou_por`) e `avisos`. Sem `command`, `stderr` nem pacotes
  brutos. As sondas do monitor (`tcp_half_open`: SYN/SYN-ACK/RST sem dados e sem
  handshake completo no lado do node) são **descartadas e contadas em `avisos`** — só
  quando o lado da VS é identificável (`vs_addr` + `server_port`, ou `server_port` ≠
  `node_port`); caso contrário nada é descartado e um aviso explica.
* `ok` com `detalhes: true`: a resposta simples, mais, em cada item de `transacoes`:
  `campos` (bits 7, 11, 32, 37, 70, 100, 127), `trajeto` (os saltos, em ordem: `hora`,
  `de`, `para`, `mti`), `saltos` e `rtt_ms` (do 1º pedido à última resposta), e
  `tabela_markdown` — a tabela `# | Tipo | STAN | Enviada | Resposta | RTT | Rastreio` +
  observações, pronta para ser apresentada como está. Nunca traz payload bruto. Sem
  transação com o `stan` pedido: `resultado` avisa e não há tabela.
* `ok` com `verbose: true`: `command`, `exit_status` (124 se estourou o prazo),
  `timed_out`, `summary`, `packets` (≤ 200), `packet_count_truncated`, `stderr`,
  `warnings` — mesmo formato da ferramenta `tcpdump_validate_traffic(verbose=True)`.
* `busy`: já há `MAX_CONCURRENT_TCPDUMP` (2) capturas; nada é iniciado nem
  interrompido; `retry_after_minutes: 5`.
* `blocked`: *Capturas na porta TCP 1222 (porta de conexão com a captura RISe)
  estão desabilitadas para esta ferramenta.*

## O que muda em relação ao agente via SSH

* `tcpdump` é executado com **lista de argumentos** (sem shell) e `--` antes do filtro.
* Lê o **pcap binário** de `-w -` (stdout, sem gravar arquivo) em vez de texto `-X`.
* Concorrência: trava `flock` curta serializa *contar + iniciar* (elimina a corrida
  vista com o aviso `tmm tcpdump instances`) + contagem de `tcpdump` em `/proc`.
* A safety é **autoritativa no equipamento**: quem chamar a API direto não a contorna.
* Auditoria em syslog (`f5_tcpdump`, `LOG_AUTH`).

## Testes (sem F5)

```
PYTHONPATH=. python onbox/test_f5_tcpdump.py
```

Inclui paridade campo a campo com `src/tcpdump_parser.py` e um `tcpdump` falso
para o caminho `run()` completo.

## Validado no BIG-IP 17.0.0.2 (CentOS 7.3 base)

* Python **2.7.5** e **3.8.12** presentes (`/bin/python`, `/bin/python3`); o script
  compila e roda nos dois: validação, `parse_pcap`, `summarize`, `/proc`.
* `tcpdump` 4.9.3 / libpcap 0.9.4 (`/sbin/tcpdump`): aceita `-nn -U -s 512 -c N -i any
  -w - -- <filtro>`; `any` reporta linktype `EN10MB`. Captura real filtrada em um node,
  com prazo duro (exit 124), sem processo órfão; `flock` e `timeout` existem.
* `sudo` presente; `/shared` com ~14 GB livres; `restnoded`/`restjavad` rodando.
* Execução real de `run()` fora do agente: 1222 → `blocked`; captura de 8 s OK.

## Ainda NÃO validado

1. Offsets dos bits ISO 8583 (86–188): o tráfego capturado até agora são só
   sondas de monitor, sem payload — falta uma captura real do cliente.
2. Empacotamento como RPM iApps LX e RBAC com usuário não-admin (a validação foi com
   o usuário já existente e a instalação em modo desenvolvimento, ver Deploy).
3. Interface com `:` (ex.: `0.0:nnn`) não é aceita de propósito, por ora.

Validado no F5 (17.0.0.2): sudoers `restnoded` → script como root, extensão LX
carregada e persistida, capturas de 180 s via POST 202 + GET `?job_id=`, duas em
paralelo, com tráfego ISO 8583 rastreado pelos 4 saltos por STAN.

## Wrapper REST (iControl LX) — `onbox/lx/`

| Arquivo | Papel |
|---|---|
| `lx/nodejs/f5TcpdumpWorker.js` | worker: `POST /mgmt/shared/f5_tcpdump` → `sudo -n f5_tcpdump.py` (pedido por stdin) |
| `lx/package.json` | metadados da extensão |
| `lx/test/worker.test.js` | 20 testes com `child_process` simulado |
| `deploy/f5_tcpdump.sudoers` | regra única para `restnoded` executar só o script |

O worker é só transporte — a validação e a safety (1222, limites, trava) continuam
no `f5_tcpdump.py`. Mapeamento `status` → HTTP: `ok` 200, `invalid` 400, `blocked`
403, `busy` 429, `error` 500; prazo estourado 504. No máximo 4 processos simultâneos
por worker, corpo ≤ 2 KB, saída ≤ 4 MB, sem shell.

### Assíncrono (capturas de até 180 s)

O gateway REST do BIG-IP (`restjavad`) interrompe — **e reenvia ao worker** — POSTs que
passam de ~60 s (`TimeoutException` em `ForwarderPassThroughWorker`). Uma resposta
síncrona de 180 s duplicava a captura e ocupava as vagas do guard. Por isso:

| Chamada | Resposta |
|---|---|
| `POST /mgmt/shared/f5_tcpdump` (corpo JSON) | espera até 2 s. Se o script já terminou (`invalid`/`blocked`/`busy`/erro, ou captura curta): **a resposta de sempre** (200/400/403/429/500). Senão: **202** `{status:"running", job_id, poll, max_sec}` |
| `GET /mgmt/shared/f5_tcpdump?job_id=<id>` | **202** `running` enquanto roda; depois o **mesmo JSON e o mesmo código HTTP** que o POST síncrono teria devolvido, acrescido de `job_id`, `started_at`, `finished_at`; **404** id desconhecido; **400** id malformado |
| `GET /mgmt/shared/f5_tcpdump` | descritor (campos, limites, `jobs.running/stored`) — não executa nada |

* O id vai em **query string**: o `restjavad` só encaminha o caminho exato registrado
  (`/shared/f5_tcpdump/<id>` volta 404 "Public URI path not registered").
* Resultados ficam **só em memória** do worker por 15 min (máx. 50); um restart do
  `restnoded` apaga jobs em andamento (o script é encerrado junto) e resultados.
* O prazo duro continua: `timeout_sec` + 15 s, depois SIGTERM/SIGKILL (resultado 504).
* Duas capturas em paralelo funcionam (teto do F5 = 2 no total, contando capturas de
  outras pessoas); a terceira recebe 429 `busy` na hora, sem interromper nenhuma.

```
# exemplo (usuário final)
TOKEN=$(curl -sk -X POST https://<mgmt>/mgmt/shared/authn/login -H 'Content-Type: application/json' \
        -d '{"username":"<u>","password":"<p>","loginProviderName":"tmos"}' | jq -r .token.token)
curl -sk -X POST https://<mgmt>/mgmt/shared/f5_tcpdump -H "X-F5-Auth-Token: $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"server_port":17000,"node_port":15000,"host":"192.168.0.9","timeout_sec":180}'
#   -> 202 {"status":"running","job_id":"…","poll":"/mgmt/shared/f5_tcpdump?job_id=…"}
curl -sk "https://<mgmt>/mgmt/shared/f5_tcpdump?job_id=<id>" -H "X-F5-Auth-Token: $TOKEN"
```

Login: o mesmo usuário já existente (validado: `POST /mgmt/shared/authn/login` com
`providerName tmos` → token → `X-F5-Auth-Token`).

```
node onbox/lx/test/worker.test.js     # local, se houver Node
```

No BIG-IP o Node das extensões é o `/usr/bin/f5-rest-node` (v8.11.1; o `node` do PATH
é outro). Os testes rodam nele sem gravar arquivo: fonte do worker em
`global.__WORKER_SRC__` e o teste por `-e`.

### Deploy (passos manuais — exigem root no F5)

1. Copiar `f5_tcpdump.py` para `/shared/f5_tcpdump/` (`root:root`, `0755`).
2. Instalar a regra: `/etc/sudoers.d/f5_tcpdump` (`0440`); validar com
   `visudo -c -f /etc/sudoers.d/f5_tcpdump`.
3. Instalar a extensão: empacotar `onbox/lx` como RPM iApps LX e enviar por
   `/mgmt/shared/iapp/package-management-tasks`. **Só em desenvolvimento** (sem RPM),
   validado no 17.0.0.2: copiar `lx/nodejs/f5TcpdumpWorker.js` para
   `/var/config/rest/iapps/f5_tcpdump/nodejs/` (`root:root`, `0644`) **e registrar o
   caminho** com `POST /mgmt/shared/nodejs/loader-path-config`
   `{"workerPath":"/var/config/rest/iapps/f5_tcpdump/nodejs"}` — só copiar e reiniciar o
   `restnoded` **não** carrega o worker (o endpoint segue 404). O registro é persistido
   e o worker volta sozinho após `bigstart restart restnoded` (necessário em cada
   atualização do worker).
4. Testar com um usuário **não-admin** para conferir o RBAC de `/mgmt/shared/*`.

## Privilégio — opções para o wrapper

* **Recomendada:** `/etc/sudoers.d/` com uma regra única permitindo ao usuário
  `restnoded` executar *exatamente* este script (root-owned, não gravável por ele),
  com o pedido por stdin. Passo único, feito por root.
* Evitar: chamar `/mgmt/tm/util/bash` — exige admin e aceita qualquer comando,
  o que torna a safety contornável.

## Observações operacionais

* O IP de management veio por DHCP (`configured-by-dhcp`): não fixar no wrapper.
* A auditoria (`syslog`, tag `f5_tcpdump`) cai no **journal**
  (`journalctl -t f5_tcpdump`), não em `/var/log/messages`/`secure`.
* A trava fica em `/var/run/f5_tcpdump/guard.lock` (tmpfs, some no reboot).

## Próximo passo

Wrapper iControl LX (RPM, endpoint `/mgmt/shared/...`) chamando este script como
processo, com RBAC e TLS do management.
