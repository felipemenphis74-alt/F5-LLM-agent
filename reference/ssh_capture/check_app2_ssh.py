"""Valida a VS/pool da APP2 e checa resposta a SYN via tcpdump nativo do TMOS.
Mesma lógica de check_app1.py, apontando para vs_app2_16000."""
import json
import sys

from src.inventory import Inventory
from src.f5_client import F5Client, F5ConnectionError, TcpdumpBusyError, describe_tcpdump_warnings
from src.safety import UnsafeInputError
from src import tmsh_parser, tcpdump_parser

DEVICE_NAME = "F5-LTM-LLM"
VS_NAME = "vs_app2_16000"

inv = Inventory.load()
device = inv.get(DEVICE_NAME)
client = F5Client(
    device=device,
    connect_timeout_sec=inv.limits.ssh_connect_timeout_sec,
    command_timeout_sec=inv.limits.command_timeout_sec,
)

print(f"== 1) Config declarada da VS {VS_NAME} (tmsh list) ==")
cfg_result = client.list_virtual_server_config(VS_NAME)
vs_list = tmsh_parser.parse_virtual_servers(cfg_result.stdout)
print(json.dumps(vs_list, indent=2, ensure_ascii=False))

if not vs_list:
    print("Nao consegui parsear a config da VS a partir do 'tmsh list' — raw output:")
    print(cfg_result.stdout[:2000])
    sys.exit(1)

vs_info = vs_list[0]
pool_name = vs_info.get("pool_name")
vs_port = vs_info.get("port")

if not pool_name:
    print("VS nao tem pool associado na config declarada. Raw:")
    print(cfg_result.stdout[:2000])
    sys.exit(1)

print(f"\n== 2) Status do pool '{pool_name}' (tmsh show ... members detail) ==")
pool_result = client.show_pool(pool_name)
members = tmsh_parser.parse_pool_members(pool_result.stdout)
print(json.dumps(members, indent=2, ensure_ascii=False))
print("\n---- raw show pool ----")
print(pool_result.stdout[:3000])

node_port = None
node_host = None
for m in members:
    if m.get("port"):
        node_port = m["port"]
        node_host = m.get("address")
        break

print(
    f"\n== 3) Captura tcpdump (SYN) — interface=any, server_port={vs_port}, "
    f"node_port={node_port}, host={node_host}, 60s =="
)
try:
    tcp_result = client.tcpdump_capture(
        interface="any",
        server_port=vs_port,
        node_port=node_port,
        host=node_host,
        count=inv.limits.tcpdump_max_count,
        max_count=inv.limits.tcpdump_max_count,
        timeout_sec=60,
        max_timeout_sec=inv.limits.tcpdump_max_duration_sec,
    )
    packets = tcpdump_parser.parse_tcpdump_output(tcp_result.stdout)
    summary = tcpdump_parser.summarize(packets)
    print(f"exit_status: {tcp_result.exit_status}")
    print("Resumo:", json.dumps(summary, indent=2, ensure_ascii=False))
    if tcp_result.stderr:
        print("---- stderr ----")
        print(tcp_result.stderr[:1500])
    warnings = describe_tcpdump_warnings(tcp_result.stderr)
    if warnings:
        print("\n!! AVISOS !!")
        for w in warnings:
            print(" -", w)
    if not packets:
        print("\nNenhum pacote capturado no periodo.")
    else:
        print(f"\n{len(packets)} pacote(s) capturado(s). Amostra:")
        print(json.dumps(packets[:10], indent=2, ensure_ascii=False))
except TcpdumpBusyError as exc:
    print(f"CAPTURA RECUSADA (concorrencia): {exc}")
except (F5ConnectionError, UnsafeInputError) as exc:
    print(f"ERRO na captura tcpdump: {exc}")
