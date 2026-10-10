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

Campos desconhecidos são recusados. Saída (JSON): `status` =
`ok | busy | blocked | invalid | error`.

* `ok`: `command`, `exit_status` (124 se estourou o prazo), `timed_out`, `summary`,
  `packets` (≤ 200), `packet_count_truncated`, `stderr`, `warnings` — mesmo formato
  da ferramenta `tcpdump_validate_traffic` do agente.
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
2. Privilégio: o worker do iControl LX roda como **`restnoded` (uid 198, nologin)**,
   sem regra de `sudo`; é preciso definir como ele chega ao script (ver abaixo).
3. Empacotamento iApps LX / autenticação REST (precisa de credencial `admin`).
4. Interface com `:` (ex.: `0.0:nnn`) não é aceita de propósito, por ora.

## Wrapper REST (iControl LX) — `onbox/lx/`

| Arquivo | Papel |
|---|---|
| `lx/nodejs/f5TcpdumpWorker.js` | worker: `POST /mgmt/shared/f5_tcpdump` → `sudo -n f5_tcpdump.py` (pedido por stdin) |
| `lx/package.json` | metadados da extensão |
| `lx/test/worker.test.js` | 12 testes com `child_process` simulado |
| `deploy/f5_tcpdump.sudoers` | regra única para `restnoded` executar só o script |

O worker é só transporte — a validação e a safety (1222, limites, trava) continuam
no `f5_tcpdump.py`. Mapeamento `status` → HTTP: `ok` 200, `invalid` 400, `blocked`
403, `busy` 429, `error` 500; prazo estourado 504. No máximo 4 processos simultâneos
por worker, corpo ≤ 2 KB, saída ≤ 4 MB, sem shell.

Login: o mesmo usuário já existente (validado: `POST /mgmt/shared/authn/login` com
`providerName tmos` → token → `X-F5-Auth-Token`).

```
node onbox/lx/test/worker.test.js     # local, se houver Node
```

### Deploy (passos manuais — exigem root no F5)

1. Copiar `f5_tcpdump.py` para `/shared/f5_tcpdump/` (`root:root`, `0755`).
2. Instalar a regra: `/etc/sudoers.d/f5_tcpdump` (`0440`); validar com
   `visudo -c -f /etc/sudoers.d/f5_tcpdump`.
3. Instalar a extensão: empacotar `onbox/lx` como RPM iApps LX e enviar por
   `/mgmt/shared/iapp/package-management-tasks` (ou, só em desenvolvimento, copiar para
   `/var/config/rest/iapps/f5_tcpdump/` e `bigstart restart restnoded`).
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
