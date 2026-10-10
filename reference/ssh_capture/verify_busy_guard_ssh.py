"""Verificacao end-to-end da guarda de concorrencia de tcpdump:
1) sobe 3 tcpdump 'de outro operador' no F5 via SSH cru (fora do agente)
2) chama F5Client.tcpdump_capture (o mesmo caminho que o agente usa) e confirma
   que ele RECUSA com TcpdumpBusyError, sem mexer nos 3 processos
3) confirma que os 3 processos de teste continuam vivos (agente nao tocou neles)
4) limpa os processos de teste (isso aqui, fora do agente -- o agente em si
   nao tem e nunca deve ter capacidade de matar processo nenhum)
"""
import sys
import time

import paramiko

from src.inventory import Inventory
from src.f5_client import F5Client, TcpdumpBusyError

DEVICE_NAME = "F5-LTM-LLM"

inv = Inventory.load()
device = inv.get(DEVICE_NAME)
creds = device.credentials

raw = paramiko.SSHClient()
raw.set_missing_host_key_policy(paramiko.AutoAddPolicy())
raw.connect(
    hostname=device.host, port=device.port, username=creds.user, password=creds.password,
    timeout=10, allow_agent=False, look_for_keys=False,
)

print("== Subindo 2 tcpdump de teste (fora do agente) ==")
for i in range(2):
    cmd = f"nohup tcpdump -i any -c 100000 -w /dev/null > /dev/null 2>&1 & echo started_{i}"
    stdin, stdout, stderr = raw.exec_command(cmd)
    print(stdout.read().decode().strip(), stderr.read().decode().strip())
time.sleep(2)

_, stdout, _ = raw.exec_command("ps -eo pid,comm")
before = [l.strip() for l in stdout.read().decode().splitlines() if "tcpdump" in l]
print(f"tcpdump rodando agora (fora do agente): {len(before)}")
for l in before:
    print(" ", l)

print("\n== Chamando F5Client.tcpdump_capture (caminho do agente) ==")
client = F5Client(device=device, connect_timeout_sec=inv.limits.ssh_connect_timeout_sec,
                   command_timeout_sec=inv.limits.command_timeout_sec)
try:
    client.tcpdump_capture(
        interface="any", server_port=None, node_port=15000, host="10.100.2.1",
        count=10, max_count=inv.limits.tcpdump_max_count,
        timeout_sec=5, max_timeout_sec=inv.limits.tcpdump_max_duration_sec,
    )
    print("ERRO: deveria ter sido recusado, mas a captura RODOU.")
    sys.exit(1)
except TcpdumpBusyError as exc:
    print(f"OK — agente recusou como esperado:\n  {exc}")

_, stdout, _ = raw.exec_command("ps -eo pid,comm")
after = [l.strip() for l in stdout.read().decode().splitlines() if "tcpdump" in l]
print(f"\ntcpdump rodando depois da recusa: {len(after)}")
same_pids = {l.split()[0] for l in before} == {l.split()[0] for l in after}
print(f"Mesmos PIDs de antes (agente nao tocou em nada)? {same_pids}")

print("\n== Limpando os 3 tcpdump de teste (feito por FORA do agente, nunca pelo agente) ==")
raw.exec_command("pkill -f 'tcpdump -i any -c 100000'")
time.sleep(1)
_, stdout, _ = raw.exec_command("ps -eo pid,comm")
remaining = [l.strip() for l in stdout.read().decode().splitlines() if "tcpdump" in l]
print(f"tcpdump restantes apos limpeza manual: {len(remaining)}")

raw.close()
