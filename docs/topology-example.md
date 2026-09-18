# Exemplo de topologia — VS/Pool/Node de referência

Este documento registra um cenário real de configuração F5 BIG-IP usado como
referência para testar o [agente de monitoramento](../README.md) deste repositório.
Não é executado pelo agente (que é somente leitura) — serve como baseline de
comparação e contexto de topologia para quem for validar VS/Pool/conexões nesse
ambiente.

## Diagrama

```
                    192.168.170.1 (rede externa / cliente)
                         |                    |
                         v                    v
          mgmt 192.168.170.130      mgmt 192.168.170.135
          +----------------------+   +------------------+
          |      F5 BIG-IP       |   |  Servidor de App |
          |                      |   |  (via switch/rot)|
          |  VS 10.100.1.10:15000|   |  APP1 10.100.2.1 |
          |    -> NODE 10.100.2.1:15000  :15000          |
          |                      |   |  APP2 10.100.2.1 |
          |  VS 10.100.1.10:16000|   |    :16000        |
          |    -> NODE 10.100.2.1:16000                  |
          |                      |   |                  |
          |  Self IP 10.100.1.20 |   |                  |
          |  VLAN1 / Interface 1.1 --- VLAN1 --- Interface E1.1
          +----------------------+   +------------------+
```

- **Rede de management** (192.168.170.0/24): fora de banda, usada só para
  administração (SSH/GUI) do F5 e do servidor — não participa do caminho de
  tráfego das VS.
- **VLAN1** (tag 802.1Q real = 1, native/untagged na interface `1.1`): carrega o
  tráfego de dados entre o F5 e o roteador que dá acesso à subnet do node
  (`10.100.2.0/24`).
- **Gateway default do F5**: `10.100.1.254`, alcançado via VLAN1/interface `1.1`
  (rota default — cobre o caminho até `10.100.2.0/24`, já que o node está em
  subnet diferente da do Self IP).
- **Node único** (`10.100.2.1`) hospeda duas aplicações diferenciadas por porta
  (`15000` e `16000`), cada uma com sua própria VS/Pool no F5 (mesmo IP de VS,
  portas diferentes).
- **Protocolo**: TCP genérico (sem necessidade de profile HTTP na VS).
- **Health check**: monitor built-in `/Common/tcp_half_open` — valida apenas que
  a porta responde ao handshake TCP (SYN → SYN/ACK → RST), sem completar a
  conexão nem inspecionar payload da aplicação.

## Configuração tmsh completa

```
# 1. VLAN — tag 1 (nativa), interface 1.1 untagged
create net vlan VLAN1 {
    interfaces add { 1.1 { untagged } }
    tag 1
}

# 2. Self IP do F5
create net self self_vlan1 {
    address 10.100.1.20/24
    vlan VLAN1
    allow-service default
}

# 3. Rota default
create net route default_gw {
    network 0.0.0.0/0
    gw 10.100.1.254
}

# 4. Node único (reaproveitado pelas duas pools)
create ltm node node_app_10.100.2.1 {
    address 10.100.2.1
}

# 5. Pools — monitor built-in tcp_half_open
create ltm pool pool_app1_15000 {
    monitor /Common/tcp_half_open
    members add { node_app_10.100.2.1:15000 { } }
}

create ltm pool pool_app2_16000 {
    monitor /Common/tcp_half_open
    members add { node_app_10.100.2.1:16000 { } }
}

# 6. Virtual Servers — perfil TCP puro
create ltm virtual vs_app1_15000 {
    destination 10.100.1.10:15000
    ip-protocol tcp
    mask 255.255.255.255
    pool pool_app1_15000
    profiles add { tcp }
    source-address-translation { type automap }
    vlans add { VLAN1 }
    vlans-enabled
}

create ltm virtual vs_app2_16000 {
    destination 10.100.1.10:16000
    ip-protocol tcp
    mask 255.255.255.255
    pool pool_app2_16000
    profiles add { tcp }
    source-address-translation { type automap }
    vlans add { VLAN1 }
    vlans-enabled
}
```

## Baseline correspondente (Excel) para o agente de monitoramento

Para usar `compare_vs_with_excel_baseline` contra este ambiente, um `.xlsx` em
`data/` com este conteúdo reflete a topologia acima:

| VS Name          | Pool Name         | Expected Port | Purpose            | Expected Members    | Partition |
|-------------------|--------------------|----------------|---------------------|-----------------------|-----------|
| vs_app1_15000      | pool_app1_15000     | 15000          | APP1                | 10.100.2.1:15000       | Common    |
| vs_app2_16000      | pool_app2_16000     | 16000          | APP2                | 10.100.2.1:16000       | Common    |

## Observações / pontos já validados com o cliente

- Gateway confirmado como `10.100.1.254` (não `.255`, que seria o endereço de
  broadcast da subnet `/24` e inválido como next-hop).
- Tag de VLAN confirmada como 802.1Q real, com a interface física em modo
  untagged/native.
- Protocolo das aplicações confirmado como TCP genérico — sem profile HTTP.
- Monitor de saúde trocado de um `tcp` customizado para o built-in
  `tcp_half_open`, por ser mais leve (não completa a conexão nem troca
  payload).
