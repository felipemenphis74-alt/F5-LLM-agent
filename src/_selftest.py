"""Auto-teste rápido (sem F5 real) dos parsers, da API de captura e das camadas de segurança.
Roda dentro do container: docker run --rm --entrypoint python f5-mcp-agent:test -m src._selftest

A captura de tráfego é SOMENTE pela API onboard (script no equipamento): aqui ela é
substituída por um FakeOnbox; o parsing de pcap/ISO 8583 é testado em onbox/test_f5_tcpdump.py.
"""
import copy
import json
import os
from types import SimpleNamespace

from . import tmsh_parser, safety, comparator
from .f5_client import CommandResult, F5Client
from .safety import UnsafeInputError
from .inventory import Device, DeviceCredentials


class FakeOnbox:
    """Substitui o OnboxClient: registra (payload, janela) e devolve (HTTP, corpo)."""

    def __init__(self, status=200, body=None, error=None):
        self.status, self.body, self.error = status, body if body is not None else {}, error
        self.calls = []

    def capture(self, payload, window_sec):
        self.calls.append((copy.deepcopy(payload), window_sec))
        if self.error is not None:
            raise self.error
        return self.status, copy.deepcopy(self.body)


# Resposta de sucesso da API de captura (mais campos "internos" que NUNCA podem chegar
# ao cliente: o servidor MCP entrega só a lista conhecida de campos).
ONBOX_OK = {
    "status": "ok",
    "resultado": "1 transação ISO 8583 respondida na janela observada; os membros do pool "
                 "respondem ao SYN.",
    "janela": {"max_s": 60, "encerrou_por": "prazo"},
    "trafego": {"pacotes": 4, "syn": 1, "syn_ack": 1, "rst": 0, "psh_ack": 2},
    "transacoes": [{"hora": "14:10:00.001000", "stan": "111111", "pedido": "0800",
                    "resposta": "0810", "tipo": "Echo Test", "origem": "192.168.0.9",
                    "respondida": True}],
    "membros": [{"membro": "192.168.0.9:15000", "situacao": "responde ao SYN",
                 "syn": 1, "syn_ack": 1, "rst": 0}],
    "avisos": [],
    "command": "tcpdump -nn -w -", "stderr": "WARNING tmm", "packets": [{"src": "a"}],
    "exit_status": 0, "host": "192.0.2.1",
}

ONBOX_DOWN = dict(ONBOX_OK, resultado="Membro 10.100.2.1:16000 não responde ao SYN "
                  "(2 SYN, 0 SYN-ACK).", transacoes=[],
                  trafego={"pacotes": 0, "syn": 0, "syn_ack": 0, "rst": 0, "psh_ack": 0},
                  membros=[{"membro": "10.100.2.1:16000",
                            "situacao": "não responde ao SYN (sem SYN-ACK)",
                            "syn": 2, "syn_ack": 0, "rst": 0}])



SAMPLE_LIST_VS = """\
ltm virtual vs_web_443 {
    destination 10.1.1.10:443
    ip-protocol tcp
    mask 255.255.255.255
    pool pool_web_443
    profiles {
        tcp { }
    }
}
ltm virtual vs_api_8080 {
    destination 10.1.1.11:8080
    ip-protocol tcp
    mask 255.255.255.255
    pool pool_api_8080
}
"""

SAMPLE_SHOW_POOL_MEMBERS = """\
Ltm::Pool: pool_web_443
Ltm::Pool Member: 10.2.2.11:443
Status
    Availability : available
    State        : enabled
    Reason       : Pool member is available
Ltm::Pool Member: 10.2.2.12:443
Status
    Availability : offline
    State        : disabled
    Reason       : Manually forced offline
"""


# Saídas reais do F5 de teste (encurtadas). Node do pool da VS 3 renomeado para
# "web01" (sem IP no nome) para exercitar a busca do IP real no `list`.
SAMPLE_VS_LIST = """ltm virtual vs_app1_15000 {
    destination 10.100.1.10:hydap
    ip-protocol tcp
    pool pool_app1_15000
}
ltm virtual vs_app2_16000 {
    destination 10.100.1.10:fmsas
    pool pool_app2_16000
}
ltm virtual vs_app3_17000 {
    description "parceiro - Padaria do zezinho"
    destination 10.100.1.10:17000
    pool pool_app3_17000
}
"""

SAMPLE_VS_SHOW = """
Ltm::Virtual Server: vs_app3_17000
Status
  Availability     : available
  Destination      : 10.100.1.10:17000
"""

SAMPLE_POOL_LIST = """ltm pool pool_app1_15000 {
    members {
        node_app_10.100.2.1:hydap {
            address 10.100.2.1
            session monitor-enabled
            state down
        }
        web01:hydap {
            address 192.168.0.9
            session monitor-enabled
            state up
        }
    }
    monitor tcp_half_open
}
ltm pool pool_app2_16000 {
    members {
        node_app_10.100.2.1:fmsas {
            address 10.100.2.1
        }
    }
    monitor tcp_half_open
}
ltm pool pool_app3_17000 {
    members {
        web01:hydap {
            address 192.168.0.9
            session monitor-enabled
            state up
        }
    }
    monitor tcp_half_open
}
"""

SAMPLE_POOL_SHOW = """
Ltm::Pool: pool_app3_17000
  | Ltm::Pool Member: web01:15000
  |   Availability   : available
  |   State          : enabled
"""


SAMPLE_VS_LIST_FULL = """ltm virtual vs_full_443 {
    description "Portal"
    destination /Common/10.1.1.10:443
    ip-protocol tcp
    mask 255.255.255.255
    persist {
        /Common/source_addr {
            default yes
        }
    }
    pool /Common/pool_web_443
    profiles {
        /Common/http { }
        /Common/tcp { }
    }
    rules {
        /Common/redirect_irule
    }
    source 0.0.0.0/0
    source-address-translation {
        pool /Common/snat_pool_a
        type snat
    }
    translate-address enabled
    translate-port enabled
}
ltm virtual vs_off_80 {
    destination 10.1.1.11:http
    disabled
    ip-protocol tcp
    pool pool_off
    source-address-translation {
        type automap
    }
}
"""

SAMPLE_VS_STATUS = """
Ltm::Virtual Server: vs_app1_15000
------------------------------------------------------------
Status
  Availability     : available
  State            : enabled
  Reason           : The virtual server is available
  CMP              : enabled
  CMP Mode         : all-cpus
  Destination      : 10.100.1.10:15000
  PVA Acceleration : none

Traffic                             ClientSide  Ephemeral  General
  Bits In                                 8.8K          0        -
  Bits Out                                8.8K          0        -
  Packets In                                24          0        -
  Packets Out                               24          0        -
  Current Connections                        0          0        -
  Maximum Connections                        2          0        -
  Total Connections                         12          0        -
  Total Software Accepted                    0
"""

SAMPLE_POOL_STATUS = """
Ltm::Pool: pool_app1_15000
------------------------------------------------------------
Status
  Availability           : available
  State                  : enabled
  Reason                 : The pool is available
  Monitor                : tcp_half_open
  Minimum Active Members : 0
Traffic                  ServerSide
  Current Connections    0
  |   Ltm::Pool Member: node_app_10.100.2.1:15000
  |   Status
  |   Availability   : offline
  |   State          : enabled
  |   Reason         : tcp_half_open: No successful responses received before deadline.
  |   Monitor        : tcp_half_open (pool monitor)
  |   Ltm::Pool Member: node_app_192.168.0.9:15000
  |   Availability   : available
  |   State          : enabled
  |   Reason         : Pool member is available
"""

SAMPLE_SYS_CONNECTIONS = """Sys::Connections
10.100.1.20:4598  10.100.2.1:15000  10.100.1.20:15691  10.100.2.1:15000  tcp  4  (tmm: 0)  none  none
192.168.0.9:50000  10.100.1.10:17000  10.100.1.20:50000  192.168.0.9:15000  tcp  7  (tmm: 1)  none  none

Total records returned: 2
"""

# Saída com lixo de configuração do dispositivo (NTP/ARP/VLAN/autenticação) misturado:
# nada disso pode sobreviver aos parsers.
SAMPLE_NOISE = """
sys ntp { servers { 10.9.9.9 } timezone America/Sao_Paulo }
net arp 10.1.1.1 { ip-address 10.1.1.1 mac-address 00:11:22:33:44:55 }
net vlan external { interface 1.1 tag 4094 }
auth user admin { encrypted-password $6$secretsalt$hash }
"""


FORBIDDEN_IN_OUTPUT = (
    "tmsh", "ssh", "paramiko", "perl", "bash", "stderr", "exit_status", "command",
    "known_hosts", "inventory", "docker", "/app/", "password", "senha", "F5_PROD",
    "secretsalt", "00:11:22:33:44:55", "4094", "Sao_Paulo", "10.9.9.9",
    "192.0.2.1",          # host do dispositivo de teste
)
FORBIDDEN_WORDS_RE = r"\b(ntp|arp|vlan|tmm|cmp)\b"


def _assert_clean(label, value):
    import re
    text = json.dumps(value, ensure_ascii=False)
    for term in FORBIDDEN_IN_OUTPUT:
        assert term.lower() not in text.lower(), f"{label}: vazou {term!r}: {text[:300]}"
    assert not re.search(FORBIDDEN_WORDS_RE, text, re.I), f"{label}: termo de dispositivo: {text[:300]}"


def _security_checks(device, real_client):
    import asyncio

    import paramiko
    from . import baseline_excel, server
    from .f5_client import F5ConnectionError
    from .inventory import InventoryError

    print("== segurança: allowlist só de VS/pool/conexões (nada do dispositivo) ==")
    for cmd in ("tmsh show net vlan", "tmsh list net vlan", "tmsh show net arp",
                "tmsh list net self", "tmsh list sys ntp", "tmsh list sys global-settings",
                "tmsh list auth user", "tmsh list auth remote-role", "tmsh show sys version",
                "tmsh list sys dns", "tmsh list ltm virtual-address",
                "tmsh show ltm virtual-address", "tmsh list ltm node", "tmsh show ltm pool-x"):
        try:
            safety.assert_safe_tmsh_command(cmd)
            raise AssertionError(f"deveria recusar: {cmd}")
        except safety.CommandNotAllowedError:
            pass
    for cmd in ("tmsh list ltm virtual", "tmsh list ltm virtual vs_a",
                "tmsh show ltm virtual vs_a", "tmsh show ltm pool pool_a members detail",
                "tmsh list ltm pool", "tmsh show sys connection cs-server-port 17000"):
        assert safety.assert_safe_tmsh_command(cmd) == cmd
    print("OK: 14 comandos de dispositivo/rede/autenticação recusados; os de VS/pool passam")

    print("== tmsh parser: config e status só da VS ==")
    cfg = {v["vs_name"]: v for v in tmsh_parser.parse_virtual_servers(SAMPLE_VS_LIST_FULL)}
    full = cfg["vs_full_443"]
    assert (full["port"], full["ip_protocol"], full["enabled"], full["service"]) == \
        (443, "tcp", True, None), full
    assert full["profiles"] == ["http", "tcp"] and full["persistence"] == ["source_addr"], full
    assert full["rules"] == ["redirect_irule"], full
    assert full["snat"] == {"type": "snat", "pool": "snat_pool_a"}, full
    assert full["pool_name"] == "/Common/pool_web_443" and full["description"] == "Portal", full
    off = cfg["vs_off_80"]
    assert (off["port"], off["service"], off["enabled"], off["profiles"]) == \
        (None, "http", False, []), off
    assert off["snat"] == {"type": "automap"}, off

    status = tmsh_parser.parse_vs_status(SAMPLE_VS_STATUS + SAMPLE_NOISE)
    assert status == [{
        "vs_name": "vs_app1_15000", "availability": "available", "state": "enabled",
        "reason": "The virtual server is available", "destination": "10.100.1.10:15000",
        "connections": {"current": 0, "max": 2, "total": 12},
        "traffic": {"bits_in": "8.8K", "bits_out": "8.8K", "packets_in": "24",
                    "packets_out": "24"}}], status
    pool = tmsh_parser.parse_pool_status(SAMPLE_POOL_STATUS)
    assert pool["availability"] == "available" and pool["reason"] == "The pool is available", pool
    assert [(m["address"], m["port"], m["availability"]) for m in pool["members"]] == \
        [("10.100.2.1", 15000, "offline"), ("192.168.0.9", 15000, "available")], pool
    assert "tcp_half_open" in pool["members"][0]["reason"], pool
    assert set(pool) == {"availability", "state", "reason", "members"}, pool
    assert all(set(m) == {"address", "port", "availability", "state", "reason"}
               for m in pool["members"]), pool
    rows = tmsh_parser.parse_sys_connections(SAMPLE_SYS_CONNECTIONS)
    assert rows[1] == {"client": "192.168.0.9:50000", "virtual_server": "10.100.1.10:17000",
                       "snat": "10.100.1.20:50000", "node": "192.168.0.9:15000",
                       "protocol": "tcp", "idle_s": 7}, rows
    print("OK: VS (perfis/persistência/SNAT/regras), status, pool e conexões sem campos internos")

    print("== segurança: respostas das ferramentas não trazem método nem config do dispositivo ==")

    class SweepClient:
        def show_virtual_servers(self, vs_name=None):
            return CommandResult("c", SAMPLE_VS_STATUS + SAMPLE_NOISE, "stderr-secret", 0)

        def list_virtual_server_config(self, vs_name=None):
            return CommandResult("c", SAMPLE_VS_LIST_FULL + SAMPLE_NOISE, "", 0)

        def show_pool(self, pool_name=None):
            return CommandResult("c", SAMPLE_POOL_STATUS + SAMPLE_NOISE, "", 0)

        def list_pool_config(self, pool_name=None):
            return CommandResult("c", SAMPLE_POOL_LIST, "", 0)

        def show_sys_connections(self, *args, **kwargs):
            return CommandResult("c", SAMPLE_SYS_CONNECTIONS + SAMPLE_NOISE, "", 0)


    server._get_inventory = lambda: SimpleNamespace(
        limits=SimpleNamespace(tcpdump_max_count=500, tcpdump_max_duration_sec=180,
                               ssh_connect_timeout_sec=5, command_timeout_sec=5),
        list_devices=lambda: [device])
    server._client_for = lambda name: SweepClient()
    server._onbox_for = lambda name: FakeOnbox(body=ONBOX_OK)
    outputs = {
        "list_devices": server.list_devices(),
        "get_virtual_server_status": server.get_virtual_server_status("d", "vs_full_443"),
        "get_virtual_server_config": server.get_virtual_server_config("d", "vs_full_443"),
        "get_pool_status": server.get_pool_status("d", vs_name="vs_full_443"),
        "get_sys_connections": server.get_sys_connections("d", "vs_full_443"),
        "tcpdump_validate_traffic": server.tcpdump_validate_traffic(
            "d", server_port=443, node_port=8443, count=10, timeout_sec=5),
        "tcpdump_validate_traffic(detalhes)": server.tcpdump_validate_traffic(
            "d", server_port=443, node_port=8443, count=10, timeout_sec=5, detalhes=True),
    }
    assert outputs["list_devices"] == [{"name": "f5-selftest"}], outputs["list_devices"]
    assert outputs["get_pool_status"]["pool"] == "/Common/pool_web_443", outputs["get_pool_status"]
    for label, value in outputs.items():
        _assert_clean(label, value)
    # o que a API devolve a mais (comando, stderr, pacotes, host) nunca chega ao cliente
    assert set(outputs["tcpdump_validate_traffic"]) <= {"status", *server.CAPTURE_RESPONSE_KEYS}
    # sem filtro, a tabela de conexões não é entregue
    for call in (lambda: server.get_pool_status("d", ""),
                 lambda: server.get_virtual_server_status("d", "   "),
                 lambda: server.get_virtual_server_config("d", None)):
        try:
            call()
            raise AssertionError("deveria exigir filtro/VS")
        except safety.UnsafeInputError:
            pass
    print("OK: %d respostas sem comando/stderr/host/NTP/ARP/VLAN/autenticação" % len(outputs))

    print("== escopo: perguntar da app2 NUNCA devolve app1/app3 ==")
    three = SAMPLE_VS_LIST.replace("hydap", "15000").replace("fmsas", "16000")

    class ScopeClient:
        def __init__(self):
            self.calls = []

        def list_virtual_server_config(self, vs_name=None):
            self.calls.append(("list", vs_name))
            return CommandResult("c", three, "", 0)

        def show_virtual_servers(self, vs_name=None):
            self.calls.append(("show", vs_name))
            return CommandResult("c", SAMPLE_VS_STATUS.replace("vs_app1_15000", vs_name or "x")
                                 .replace("10.100.1.10:15000", "10.100.1.10:16000"), "", 0)

        def show_pool(self, pool_name=None):
            self.calls.append(("pool", pool_name))
            return CommandResult("c", SAMPLE_POOL_STATUS, "", 0)

        def show_sys_connections(self, client_addr=None, server_addr=None, server_port=None,
                                 client_port=None):
            self.calls.append(("conn", server_addr, server_port))
            return CommandResult("c", SAMPLE_SYS_CONNECTIONS, "", 0)

    scope_client = ScopeClient()
    server._client_for = lambda name: scope_client
    others = ("vs_app1_15000", "vs_app3_17000", "pool_app1_15000", "pool_app3_17000", "zezinho")
    for asked in ("app 2", "app2", "App-2", "vs_app2_16000"):
        for label, out in (
                ("status", server.get_virtual_server_status("d", asked)),
                ("config", server.get_virtual_server_config("d", asked)),
                ("pool", server.get_pool_status("d", asked)),
                ("conexoes", server.get_sys_connections("d", asked))):
            text = json.dumps(out, ensure_ascii=False)
            assert "vs_app2_16000" in text or label in ("pool", "conexoes"), (asked, label, text[:200])
            for other in others:
                assert other not in text, f"{asked!r} {label}: vazou {other}: {text[:200]}"
    # a conexao e sempre filtrada pelo IP:porta DA VS (nunca so pelo IP do VIP, compartilhado)
    assert ("conn", "10.100.1.10", 16000) in scope_client.calls, scope_client.calls
    assert all(c[0] != "conn" or c[2] == 16000 for c in scope_client.calls), scope_client.calls
    # sem nome, ou nome ambiguo/inexistente: so uma mensagem para refinar - sem listar VS
    for bad, expect in (("app", "corresponde a 3 VS"), ("nada disso", "Nenhuma VS corresponde")):
        try:
            server.get_virtual_server_config("d", bad)
            raise AssertionError("deveria recusar " + bad)
        except safety.UnsafeInputError as exc:
            assert expect in str(exc), str(exc)
            for other in others + ("vs_app2_16000", "pool_app2_16000"):
                assert other not in str(exc), (bad, str(exc))
    print("OK: 4 grafias de app2 x status/config/pool/conexões: só app2; ambíguo/inexistente "
          "não lista VS; conexões filtradas por IP:porta da VS")

    print("== escopo: baseline e comparações só da VS pedida ==")
    rows = [{"vs_name": "vs_app1_15000", "pool_name": "pool_app1_15000", "expected_port": 15000,
             "purpose": "app1"},
            {"vs_name": "vs_app2_16000", "pool_name": "pool_app2_16000", "expected_port": 16000,
             "purpose": "app2"},
            {"vs_name": "vs_app3_17000", "pool_name": "pool_app3_17000", "expected_port": 17000,
             "purpose": "app3"}]
    real_excel, real_sheets = server.baseline_excel.load_baseline, \
        server.baseline_sheets.load_baseline_from_sheet
    server.baseline_excel.load_baseline = lambda filename, sheet=None: list(rows)
    server.baseline_sheets.load_baseline_from_sheet = lambda sid, rng="A1:F1000": list(rows)
    try:
        only = server.get_baseline_from_excel("b.xlsx", "app 2")
        assert [r["vs_name"] for r in only] == ["vs_app2_16000"], only
        assert [r["vs_name"] for r in server.get_baseline_from_sheets("id", "app 2")] == \
            ["vs_app2_16000"]
        diff = server.compare_vs_with_excel_baseline("d", "b.xlsx", "app 2")
        text = json.dumps(diff)
        assert [m["vs_name"] for m in diff["matched"]] == ["vs_app2_16000"], diff
        assert diff["summary"]["total_live"] == 1 and diff["summary"]["total_baseline"] == 1, diff
        assert diff["unexpected_on_device"] == [] and diff["missing_on_device"] == [], diff
        for other in ("vs_app1_15000", "vs_app3_17000", "app1", "app3"):
            assert other not in text, other
        again = server.compare_vs_with_sheets_baseline("d", "id", "app 2")
        assert [m["vs_name"] for m in again["matched"]] == ["vs_app2_16000"], again
        members = server.compare_pool_members_with_baseline(
            "d", "app 2", ["10.100.2.1:15000", "192.168.0.9:15000"])
        assert members["vs_name"] == "vs_app2_16000" and "observacao" in members, members
        assert "recomenda" in members["observacao"] and "não é" in members["observacao"]
    finally:
        server.baseline_excel.load_baseline, server.baseline_sheets.load_baseline_from_sheet = \
            real_excel, real_sheets
    print("OK: baseline/comparações devolvem só a linha da VS pedida; comparação de membros é "
          "informativa (sem recomendação)")

    print("== segurança: erros chegam ao cliente como mensagem genérica ==")
    errors = (
        (F5ConnectionError("Falha ao conectar em d (192.0.2.1): Authentication failed, "
                           "password=p@ss"), server.MSG_UNAVAILABLE),
        (paramiko.AuthenticationException("Authentication failed."), server.MSG_UNAVAILABLE),
        (paramiko.SSHException("Error reading SSH protocol banner"), server.MSG_UNAVAILABLE),
        (OSError("[Errno 111] Connection refused 192.0.2.1:22"), server.MSG_UNAVAILABLE),
        (InventoryError("Device d: variável de ambiente de usuário (F5_PROD01_USER) não "
                        "definida. Verifique seu .env."), server.MSG_DEVICE),
        (baseline_excel.BaselineError("Arquivo não encontrado: /app/data/x.xlsx"),
         server.MSG_BASELINE),
        (safety.CommandNotAllowedError("Comando tmsh fora da allowlist: tmsh show net vlan"),
         server.MSG_NOT_ALLOWED),
        (KeyError("/app/inventory.yaml"), server.MSG_INTERNAL),
    )
    for exc, expected in errors:
        def boom(name, exc=exc):
            raise exc
        server._client_for = boom
        try:
            server.get_virtual_server_status("d", "app 2")
            raise AssertionError(f"deveria falhar: {exc!r}")
        except RuntimeError as raised:
            assert str(raised) == expected, (exc, str(raised))
            _assert_clean("erro", str(raised))
    print("OK: %d tipos de falha -> mensagem genérica, sem host/credencial/variável/caminho"
          % len(errors))

    print("== segurança: descrições e parâmetros das ferramentas (o que o modelo vê) ==")
    import re
    tools = asyncio.run(server.mcp.list_tools())
    assert {t.name for t in tools} == {
        "list_devices", "get_virtual_server_status", "get_virtual_server_config",
        "get_pool_status", "get_sys_connections", "get_baseline_from_excel",
        "get_baseline_from_sheets", "compare_vs_with_excel_baseline",
        "compare_vs_with_sheets_baseline", "compare_pool_members_with_baseline",
        "tcpdump_validate_traffic", "tcpdump_capture_connection"}, [t.name for t in tools]
    banned = ("ssh", "tmsh", "perl", "paramiko", "bash", "advanced shell", "known_hosts",
              "inventory", "senha", "password", "credencia", "sudo", "docker", "/app/",
              "stderr", "pcap", "alarm", "processo", "autentic", "onbox", "icontrol",
              "restjavad", "restnoded", "f5_tcpdump", "/mgmt")
    for tool in tools:
        text = (tool.description or "") + json.dumps(tool.inputSchema, ensure_ascii=False)
        for term in banned:
            assert term not in text.lower(), f"{tool.name}: descrição cita {term!r}"
        assert not re.search(FORBIDDEN_WORDS_RE, text, re.I), tool.name
        assert not re.search(r"\b(api|rest|rest api)\b", text, re.I), (tool.name, "cita API")
        props = set(tool.inputSchema.get("properties", {}))
        assert not props & {"interface", "verbose", "command", "raw"}, (tool.name, props)
    instructions = server.mcp.instructions or ""
    for term in banned:
        assert term not in instructions.lower(), f"instructions cita {term!r}"

    print("== agente de IA (agent/f5-bigip-assistant.md): ferramentas e regras batem com o MCP ==")
    import pathlib
    agent_file = pathlib.Path(__file__).resolve().parent.parent / "agent" / "f5-bigip-assistant.md"
    if not agent_file.exists():
        print("PULADO (arquivo do agente não está na imagem; rode a partir do repositório)")
    else:
        text = agent_file.read_text(encoding="utf-8")
        front = text.split("---")[1]
        listed = {t.strip() for line in front.splitlines() if line.startswith("tools:")
                  for t in line[len("tools:"):].split(",")}
        expected = {f"mcp__f5-bigip-monitor__{t.name}" for t in tools}
        assert listed == expected, (sorted(listed ^ expected))
        # só ferramentas do conector: nenhuma de escrita/execução no front-matter
        assert not any(w in front for w in ("Bash", "Write", "Edit", "PowerShell")), front
        # as regras que reforçam a política precisam estar no texto do agente
        for rule in ("Somente leitura", "Confidencialidade", "Nunca invente",
                     "Sem sugestões de configuração", "AD, RADIUS, NTP", "tabela_markdown",
                     "busy", "não tente de novo", "Nunca enumere VS", "vs_name", "60 s", "180 s",
                     "adicionar, remover, substituir"):
            assert rule.lower() in text.lower(), f"agente sem a regra: {rule!r}"
        # toda ferramenta citada na tabela de uso existe de fato
        import re as _re
        cited = set(_re.findall(r"`(get_[a-z_]+|compare_[a-z_]+|tcpdump_[a-z_]+|list_devices)", text))
        real = {t.name for t in tools}
        assert cited and all(c in real or any(r.startswith(c) for r in real)   # citacao com curinga (compare_vs_with_*)
                             for c in cited), sorted(cited - real)
        print("OK: %d ferramentas listadas == MCP; regras de segurança presentes" % len(listed))
    print("OK: %d ferramentas sem termos de método/credencial; sem parâmetros interface/verbose"
          % len(tools))

def run():
    print("== tmsh parser (virtual servers) ==")
    vs_list = tmsh_parser.parse_virtual_servers(SAMPLE_LIST_VS)
    assert len(vs_list) == 2, vs_list
    first_vs = vs_list[0]
    assert (first_vs["vs_name"], first_vs["address"], first_vs["port"], first_vs["pool_name"],
            first_vs["description"]) == ("vs_web_443", "10.1.1.10", 443, "pool_web_443", None), first_vs
    assert first_vs["ip_protocol"] == "tcp" and first_vs["enabled"] is True, first_vs
    assert first_vs["profiles"] == ["tcp"] and first_vs["snat"] is None, first_vs
    print("OK:", vs_list)

    print("== tmsh parser (pool members) ==")
    members = tmsh_parser.parse_pool_members(SAMPLE_SHOW_POOL_MEMBERS)
    assert len(members) == 2, members
    assert members[0]["availability"] == "available"
    assert members[1]["availability"] == "offline"
    print("OK:", members)

    print("== comparator ==")
    baseline = [{"vs_name": "vs_web_443", "pool_name": "pool_web_443", "expected_port": 443,
                 "purpose": "site institucional", "expected_members": [], "partition": "Common"},
                {"vs_name": "vs_missing", "pool_name": "pool_x", "expected_port": 80,
                 "purpose": "legado", "expected_members": [], "partition": "Common"}]
    diff = comparator.compare_vs_to_baseline(vs_list, baseline)
    assert diff["summary"]["ok"] == 1
    assert diff["summary"]["missing_on_device"] == 1
    assert diff["summary"]["unexpected_on_device"] == 1  # vs_api_8080
    print("OK:", diff["summary"])

    print("== safety guardrails ==")
    try:
        safety.assert_safe_tmsh_command("tmsh delete ltm virtual vs_web_443")
        raise AssertionError("deveria ter bloqueado comando de delete")
    except safety.UnsafeInputError:
        print("OK: comando destrutivo bloqueado")

    try:
        safety.require_identifier("vs_web; tmsh delete ltm virtual all", "vs_name")
        raise AssertionError("deveria ter bloqueado identificador malicioso")
    except safety.UnsafeInputError:
        print("OK: identificador malicioso bloqueado")

    assert safety.assert_safe_tmsh_command("tmsh show ltm virtual vs_web_443").startswith("tmsh show")
    print("OK: comando read-only permitido")

    print("== safety: o MCP não executa tcpdump (nem processos) por SSH ==")
    for gone in ("assert_safe_tcpdump_command", "assert_safe_ps_command"):
        assert not hasattr(safety, gone), gone
    for cmd in ("tcpdump -nn -i any -c 10", "ps -eo args", "perl -e 'alarm 5'", "cat /etc/passwd"):
        try:
            safety.assert_safe_tmsh_command(cmd)
            raise AssertionError(f"deveria recusar: {cmd}")
        except safety.CommandNotAllowedError:
            pass
    print("OK: só a allowlist tmsh de leitura existe; tcpdump/ps recusados")

    print("== safety: porta TCP 1222 (captura RISe) proibida ==")
    assert safety.require_capturable_port(15000, "node_port") == 15000
    for bad in (1222, "1222", " 1222 ", 1222.0):  # qualquer forma de entrada da porta
        try:
            safety.require_capturable_port(bad, "node_port")
            raise AssertionError(f"deveria ter bloqueado porta {bad!r}")
        except safety.BlockedPortError as exc:
            assert str(exc) == (
                "Capturas na porta TCP 1222 (porta de conexão com a captura RISe) estão "
                "desabilitadas para esta ferramenta."
            ), str(exc)
    print("OK: porta comum passa; 1222 bloqueada em qualquer forma; mensagem exata ao usuário")

    device = Device(
        name="f5-selftest", host="192.0.2.1", port=22, partition="Common", tags=[],
        credentials=DeviceCredentials(user="u", password="p", key_path=None),
    )
    client = F5Client(device=device, connect_timeout_sec=1, command_timeout_sec=1)
    assert not any(n.startswith("tcpdump") or n in ("count_running_tcpdump",)
                   for n in dir(client)), "o cliente SSH não captura tráfego"

    print("== cliente da API de captura: login -> POST -> job_id (202) -> resultado ==")
    from . import onbox_client as oc
    from .f5_client import F5ConnectionError

    scripted = iter([
        (200, {"token": {"token": "TKN"}}),                  # login
        (202, {"job_id": "j1", "status": "running"}),         # POST: captura em andamento
        (202, {"job_id": "j1", "status": "running"}),         # GET 1: ainda rodando
        (200, {"status": "ok", "resultado": "pronto"}),       # GET 2: fim
    ])
    sent = []

    def scripted_http(method, path, body=None, token=None, timeout=None):
        sent.append((method, path, token, body))
        return next(scripted)

    api = oc.OnboxClient(device, host="192.0.2.9", port=443)
    api._http = scripted_http
    real_poll = oc.POLL_INTERVAL_SEC
    oc.POLL_INTERVAL_SEC = 0.0
    try:
        status, body = api.capture({"server_port": 17000, "timeout_sec": 60}, 60)
        assert (status, body["status"]) == (200, "ok"), (status, body)
        assert [(m, p, t) for m, p, t, _ in sent] == [
            ("POST", oc.LOGIN_PATH, None),
            ("POST", oc.CAPTURE_PATH, "TKN"),
            ("GET", oc.CAPTURE_PATH + "?job_id=j1", "TKN"),
            ("GET", oc.CAPTURE_PATH + "?job_id=j1", "TKN")], sent
        assert sent[0][3] == {"username": "u", "password": "p", "loginProviderName": "tmos"}
        assert sent[1][3] == {"server_port": 17000, "timeout_sec": 60}, sent[1]

        # respostas rápidas (invalid/blocked/busy) voltam direto, sem consulta de job
        for code, answer in ((400, "invalid"), (403, "blocked"), (429, "busy")):
            scripted = iter([(200, {"token": {"token": "T"}}), (code, {"status": answer})])
            sent.clear()
            assert api.capture({"count": 0}, 60) == (code, {"status": answer})
            assert len(sent) == 2, sent

        # prazo vencido (janela + folga) com a captura ainda em andamento -> 504 genérico
        scripted = iter([(200, {"token": {"token": "T"}}), (202, {"job_id": "j9"})])
        assert api.capture({}, -oc.EXTRA_WAIT_SEC - 1) == (504, {"status": "error"})

        # login recusado / sem senha -> falha de conexão (o servidor troca por msg genérica)
        scripted = iter([(401, {})])
        try:
            api.capture({}, 60)
            raise AssertionError("login recusado deveria falhar")
        except F5ConnectionError:
            pass
        no_pwd = Device(name="n", host="192.0.2.1", port=22, partition="Common", tags=[],
                        credentials=DeviceCredentials(user="u", password=None, key_path="k"))
        try:
            oc.OnboxClient(no_pwd, host="192.0.2.9").capture({}, 60)
            raise AssertionError("sem senha deveria falhar")
        except F5ConnectionError:
            pass
    finally:
        oc.POLL_INTERVAL_SEC = real_poll

    # transporte real sem rede: conexão recusada vira F5ConnectionError (sem vazar nada)
    try:
        oc.OnboxClient(device, host="127.0.0.1", port=1, connect_timeout_sec=2)._http("GET", "/x")
        raise AssertionError("deveria falhar")
    except F5ConnectionError:
        pass
    # destino: o próprio dispositivo por padrão; variável de ambiente só para o lab
    saved = {k: os.environ.pop(k, None) for k in ("F5_MCP_REST_HOST", "F5_MCP_REST_PORT",
                                                  "F5_MCP_REST_VERIFY_TLS", "F5_MCP_REST_CA_BUNDLE")}
    try:
        default = oc.OnboxClient(device)
        assert (default.host, default.port, default.verify_tls) == ("192.0.2.1", 443, False)
        os.environ["F5_MCP_REST_HOST"] = "198.51.100.7"
        os.environ["F5_MCP_REST_PORT"] = "8443"
        os.environ["F5_MCP_REST_VERIFY_TLS"] = "true"
        tuned = oc.OnboxClient(device)
        assert (tuned.host, tuned.port, tuned.verify_tls) == ("198.51.100.7", 8443, True)
        import ssl
        assert tuned._context().verify_mode == ssl.CERT_REQUIRED
        assert default._context().verify_mode == ssl.CERT_NONE
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value
    print("OK: sequência login/POST/GET ?job_id=; 400/403/429 diretos; prazo -> 504; login/sem "
          "senha/rede -> F5ConnectionError; destino e TLS por ambiente")

    print("== server: captura SOMENTE pela API; padrão 60 s, extensível até 180 s ==")
    from . import server

    server._get_inventory = lambda: SimpleNamespace(
        limits=SimpleNamespace(tcpdump_max_count=500, tcpdump_max_duration_sec=180,
                               ssh_connect_timeout_sec=5, command_timeout_sec=5),
        list_devices=lambda: [device], get=lambda name: device)
    assert type(server._onbox_for("f5-selftest")).__name__ == "OnboxClient"

    def no_tmsh(name):
        raise AssertionError("captura por porta não deve abrir sessão de comando no dispositivo")

    server._client_for = no_tmsh
    fake = FakeOnbox(body=ONBOX_OK)
    server._onbox_for = lambda name: fake
    scope = dict(server_port=17000, vs_addr="10.100.1.10", node_port=15000, node_addr="192.168.0.9")

    out = server.tcpdump_validate_traffic("f5-selftest", **scope)
    payload, window = fake.calls[-1]
    assert window == 60 and payload == {
        "server_port": 17000, "node_port": 15000, "vs_addr": "10.100.1.10",
        "node_addr": "192.168.0.9", "count": 100, "timeout_sec": 60, "detalhes": False}, payload
    assert out["status"] == "ok" and out["avisos"] == [], out
    assert set(out) <= {"status", *server.CAPTURE_RESPONSE_KEYS}, set(out)
    for noisy in ("command", "stderr", "packets", "exit_status", "host"):
        assert noisy not in out, noisy
    _assert_clean("captura", out)
    import inspect
    assert inspect.signature(server.tcpdump_validate_traffic).parameters["timeout_sec"].default == 60
    assert inspect.signature(server.tcpdump_capture_connection).parameters["timeout_sec"].default == 60

    server.tcpdump_validate_traffic("f5-selftest", **scope, timeout_sec=180)
    assert fake.calls[-1][0]["timeout_sec"] == 180 and fake.calls[-1][1] == 180
    server.tcpdump_validate_traffic("f5-selftest", **scope, timeout_sec=1, count=500)
    assert fake.calls[-1][0]["count"] == 500 and fake.calls[-1][1] == 1
    before = len(fake.calls)
    for kwargs in ({"timeout_sec": 0}, {"timeout_sec": 181}, {"timeout_sec": -5},
                   {"count": 0}, {"count": 501}):
        try:
            server.tcpdump_validate_traffic("f5-selftest", **scope, **kwargs)
            raise AssertionError(f"deveria recusar {kwargs}")
        except UnsafeInputError as exc:
            assert "entre 1 e" in str(exc), str(exc)
    assert len(fake.calls) == before, "limites inválidos não podem chegar ao equipamento"
    print("OK: padrão 60 s (janela e payload), 180 s aceito, 0/181/count 501 recusados antes da API")

    print("== server: porta 1222 e IP inválido são recusados ANTES de qualquer chamada ==")
    before = len(fake.calls)
    for kwargs in ({"server_port": 1222}, {"node_port": 1222},
                   {"server_port": 17000, "node_port": 1222}):
        refused = server.tcpdump_validate_traffic("f5-selftest", **kwargs)
        assert refused == {"status": "blocked", "message": safety.blocked_port_message(1222)}, refused
        assert "RISe" in refused["message"]
    for field in ("host", "client_addr", "vs_addr", "node_addr"):
        for bad in ("10.100.1.10 or port 22", "10.100.1.0/24", "zezinho", "10.100.1.10'"):
            try:
                server.tcpdump_validate_traffic("f5-selftest", server_port=17000, **{field: bad})
                raise AssertionError(f"deveria ter recusado {field}={bad!r}")
            except UnsafeInputError:
                pass
    assert len(fake.calls) == before, "recusas locais não podem gerar chamada à API"
    print("OK: 1222 -> blocked com a mensagem RISe; IP inválido recusado nos 4 campos")

    print("== server: status da API viram respostas estruturadas e genéricas ==")
    cases = (
        (FakeOnbox(429, {"status": "busy", "message": "tmm tcpdump instances (2) exceeded"}),
         "busy"),
        (FakeOnbox(200, {"status": "busy"}), "busy"),
        (FakeOnbox(403, {"status": "blocked", "message": "x"}), "blocked"),
        (FakeOnbox(400, {"status": "invalid", "message": "node_port inválido"}), "invalid"),
        (FakeOnbox(500, {"status": "error", "message": "Traceback: /shared/f5_tcpdump.py"}),
         "error"),
        (FakeOnbox(504, {"status": "error"}), "error"),
        (FakeOnbox(200, "texto qualquer"), "error"),
    )
    for onbox, expected in cases:
        server._onbox_for = lambda name, o=onbox: o
        got = server.tcpdump_validate_traffic("f5-selftest", **scope)
        assert got["status"] == expected, (expected, got)
        _assert_clean("status " + expected, got)
        assert "Traceback" not in json.dumps(got) and "tmm" not in json.dumps(got), got
        if expected == "busy":
            assert got["message"] == server.MSG_BUSY and got["retry_after_minutes"] == 5, got
        if expected == "error":
            assert got == {"status": "error", "message": server.MSG_CAPTURE_FAILED}, got
        if expected == "blocked":
            assert got["message"] == safety.blocked_port_message(1222), got
    for failure in (F5ConnectionError("REST indisponível em 192.0.2.1: [Errno 111] password=p"),
                    OSError("[Errno 113] No route to host 192.0.2.1")):
        server._onbox_for = lambda name, f=failure: FakeOnbox(error=f)
        try:
            server.tcpdump_validate_traffic("f5-selftest", **scope)
            raise AssertionError("deveria falhar")
        except RuntimeError as raised:
            assert str(raised) == server.MSG_UNAVAILABLE, str(raised)
    print("OK: busy/blocked/invalid/error estruturados; falha de transporte -> mensagem genérica")

    print("== server: captura só por porta avisa que é abrangente ==")
    fake = FakeOnbox(body=ONBOX_OK)
    server._onbox_for = lambda name: fake
    broad = server.tcpdump_validate_traffic("f5-selftest", server_port=17000, node_port=15000)
    assert any("Captura abrangente" in w for w in broad["avisos"]), broad["avisos"]
    narrow = server.tcpdump_validate_traffic("f5-selftest", **scope)
    assert narrow["avisos"] == [], narrow["avisos"]
    print("OK: porta sem IP -> aviso; IP+porta nos dois lados -> sem aviso")

    print("== server: membro do pool sem SYN+ACK é informado (análise por membro) ==")
    server._onbox_for = lambda name: FakeOnbox(body=ONBOX_DOWN)
    down = server.tcpdump_validate_traffic(
        "f5-selftest", server_port=16000, vs_addr="10.100.1.10", node_port=16000,
        node_addr="10.100.2.1")
    assert down["status"] == "ok", down
    assert down["membros"] == [{"membro": "10.100.2.1:16000",
                                "situacao": "não responde ao SYN (sem SYN-ACK)",
                                "syn": 2, "syn_ack": 0, "rst": 0}], down["membros"]
    assert "10.100.2.1:16000 não responde ao SYN" in down["resultado"], down["resultado"]
    assert down["trafego"]["pacotes"] == 0 and down["avisos"] == [], down
    print("OK: \"Membro 10.100.2.1:16000 não responde ao SYN (2 SYN, 0 SYN-ACK)\" repassado")

    print("== server: detalhes=True/stan seguem para a API e a tabela é repassada ==")
    table = ("**Transações (VS 10.100.1.10:17000)** — 1 respondida(s) de 1\n\n"
             "| # | Tipo | STAN | Enviada | Resposta | RTT | Rastreio |\n"
             "|---|---|---|---|---|---|---|\n"
             "| 1 | 0800 | 111111 | 14:10:00.001 | 0810 / 111111 | 1 ms | 2/4 |")
    fake = FakeOnbox(body=dict(ONBOX_OK, tabela_markdown=table))
    server._onbox_for = lambda name: fake
    detailed = server.tcpdump_validate_traffic("f5-selftest", **scope, detalhes=True, stan="111111")
    payload = fake.calls[-1][0]
    assert payload["detalhes"] is True and payload["stan"] == "111111", payload
    assert detailed["tabela_markdown"] == table, detailed
    simple = server.tcpdump_validate_traffic("f5-selftest", **scope)
    assert fake.calls[-1][0]["detalhes"] is False and "stan" not in fake.calls[-1][0]
    print("OK: payload com detalhes/stan; tabela_markdown entregue como veio")

    print("== tmsh parser: descrição, destino numérico e members do `list` ==")
    vs_all = tmsh_parser.parse_virtual_servers(SAMPLE_VS_LIST)
    assert [v["description"] for v in vs_all] == [None, None, "parceiro - Padaria do zezinho"], vs_all
    assert vs_all[0]["port"] is None  # `list` traz "hydap": porta numérica só pelo `show`
    assert tmsh_parser.parse_vs_destination(SAMPLE_VS_SHOW) == ("10.100.1.10", 17000)
    assert tmsh_parser.parse_vs_destination("nada") == (None, None)
    pool_lists = tmsh_parser.parse_pool_list_members(SAMPLE_POOL_LIST)
    assert pool_lists["pool_app3_17000"] == [
        {"node": "web01", "address": "192.168.0.9", "service": "hydap"}], pool_lists
    assert len(pool_lists["pool_app1_15000"]) == 2, pool_lists
    print("OK:", pool_lists["pool_app3_17000"])

    print("== tmsh parser: conexão pedida pelo usuário -> VS ==")
    match = tmsh_parser.match_virtual_servers
    assert [v["vs_name"] for v in match(vs_all, "Padaria do Zézinho")] == ["vs_app3_17000"]
    assert [v["vs_name"] for v in match(vs_all, "vs_app1_15000")] == ["vs_app1_15000"]
    assert len(match(vs_all, "app")) == 3  # abrangente: casa com várias
    # palavra solta nao pode puxar as outras: "app 1" -> so a app1 (antes casava as 3)
    assert [v["vs_name"] for v in match(vs_all, "app 1")] == ["vs_app1_15000"]
    assert [v["vs_name"] for v in match(vs_all, "App-2")] == ["vs_app2_16000"]
    assert [v["vs_name"] for v in match(vs_all, "app 3")] == ["vs_app3_17000"]
    assert match(vs_all, "padaria do joaozinho") == [] and match(vs_all, "  ") == []
    print("OK: nome/descrição sem acento e caixa; 'app' -> 3 candidatas; inexistente -> 0")

    print("== server: tcpdump_capture_connection foca só a conexão pedida ==")

    class ConnClient:
        def __init__(self, pool_show=SAMPLE_POOL_SHOW):
            self.pool_show = pool_show

        def list_virtual_server_config(self, vs_name=None):
            return CommandResult(command="", stdout=SAMPLE_VS_LIST, stderr="", exit_status=0)

        def show_virtual_servers(self, vs_name=None):
            return CommandResult(command="", stdout=SAMPLE_VS_SHOW, stderr="", exit_status=0)

        def list_pool_config(self, pool_name=None):
            return CommandResult(command="", stdout=SAMPLE_POOL_LIST, stderr="", exit_status=0)

        def show_pool(self, pool_name=None):
            return CommandResult(command="", stdout=self.pool_show, stderr="", exit_status=0)

    fake = FakeOnbox(body=ONBOX_OK)
    server._onbox_for = lambda name: fake
    server._client_for = lambda name: ConnClient()
    for broad_name, status in (("app", "ambiguous"), ("padaria do joaozinho", "not_found")):
        out = server.tcpdump_capture_connection("f5-selftest", broad_name)
        assert out["status"] == status, out
        assert fake.calls == [], "pedido abrangente/inexistente NÃO pode capturar"
        for other in ("vs_app1_15000", "vs_app2_16000", "vs_app3_17000", "pool_app"):
            assert other not in json.dumps(out), other
        assert "available_connections" not in out and "candidates" not in out, out

    out = server.tcpdump_capture_connection("f5-selftest", "padaria do zezinho",
                                            client_addr="192.168.170.1")
    assert out["status"] == "ok", out
    payload, window = fake.calls[-1]
    assert window == 60 and payload == {
        "server_port": 17000, "vs_addr": "10.100.1.10", "client_addr": "192.168.170.1",
        "members": [{"addr": "192.168.0.9", "port": 15000}],  # IP do node "web01" via `list`
        "count": 100, "timeout_sec": 60, "detalhes": False}, payload
    assert out["conexao"]["membros"] == ["192.168.0.9:15000"], out["conexao"]
    assert out["conexao"]["vs_ip_porta"] == "10.100.1.10:17000", out["conexao"]
    assert out["conexao"]["vs"] == "vs_app3_17000", out["conexao"]
    for noisy in ("command", "packets", "stderr", "summary", "connection", "warnings"):
        assert noisy not in out, noisy
    assert not any("compartilhado" in w or "app1" in w for w in out["avisos"]), out["avisos"]

    server.tcpdump_capture_connection("f5-selftest", "padaria do zezinho", timeout_sec=180,
                                      detalhes=True, stan="111111")
    payload, window = fake.calls[-1]
    assert window == 180 and payload["timeout_sec"] == 180, (payload, window)
    assert payload["detalhes"] is True and payload["stan"] == "111111", payload
    assert "client_addr" not in payload and "node_port" not in payload, payload

    before = len(fake.calls)
    for kwargs in ({"timeout_sec": 181}, {"timeout_sec": 0}, {"count": 501}):
        try:
            server.tcpdump_capture_connection("f5-selftest", "padaria do zezinho", **kwargs)
            raise AssertionError(f"deveria recusar {kwargs}")
        except UnsafeInputError:
            pass
    # membro do pool na porta 1222: recusado sem chamar a API
    server._client_for = lambda name: ConnClient(SAMPLE_POOL_SHOW.replace("web01:15000", "web01:1222"))
    refused = server.tcpdump_capture_connection("f5-selftest", "padaria do zezinho")
    assert refused["status"] == "blocked" and "1222" in refused["message"], refused
    assert len(fake.calls) == before, "limites/1222 não podem chegar ao equipamento"
    # a API ocupada/recusando chega estruturada também por aqui, com a conexão identificada
    server._client_for = lambda name: ConnClient()
    server._onbox_for = lambda name: FakeOnbox(429, {"status": "busy"})
    busy = server.tcpdump_capture_connection("f5-selftest", "padaria do zezinho")
    assert busy["status"] == "busy" and busy["conexao"]["vs"] == "vs_app3_17000", busy
    print("OK: 'app' -> ambiguous e inexistente -> not_found sem captura; padaria -> só a VS "
          "10.100.1.10:17000 + membro 192.168.0.9:15000; 60 s padrão, 180 s aceito")

    _security_checks(device, client)

    print("\nTODOS OS AUTO-TESTES PASSARAM")


if __name__ == "__main__":
    run()
