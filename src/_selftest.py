"""Auto-teste rápido (sem F5 real) dos parsers e das camadas de segurança.
Roda dentro do container: docker run --rm --entrypoint python f5-mcp-agent:test -m src._selftest
"""
from . import tcpdump_parser, tmsh_parser, safety, comparator

SAMPLE_TCPDUMP = """\
14:01:02.100000 IP 10.1.1.5.51000 > 10.1.1.10.443: Flags [S], seq 1000, win 64240, length 0
\t0x0000:  4500 0034 0000 4000 4006 0000 0a01 0105  E..4..@.@.......
\t0x0010:  0a01 010a 010b 000f 0000 0000 0000 0000  ................
14:01:02.100500 IP 10.1.1.10.443 > 10.1.1.5.51000: Flags [S.], seq 2000, ack 1001, win 65535, length 0
\t0x0000:  4500 0034 0000 4000 4006 0000 0a01 010a  E..4..@.@.......
14:01:02.101000 IP 10.1.1.5.51000 > 10.1.1.10.443: Flags [P.], seq 1001, ack 2001, win 502, length 20
\t0x0000:  4500 0038 0000 4000 4006 0000 0a01 0105  E..8..@.@.......
\t0x0010:  0a01 010a 010b 000f 0000 0000 0000 0000  ................
\t0x0020:  3038 3030 3030 3030 3030 3030 3030 3030  0800000000000000
14:01:02.150000 IP 10.1.1.10.443 > 10.1.1.5.51000: Flags [P.], seq 2001, ack 1021, win 65535, length 20
\t0x0020:  3038 3130 3030 3030 3030 3030 3030 3030  0810000000000000
14:01:02.200000 IP 10.1.1.10.443 > 10.1.1.5.51000: Flags [R.], seq 2021, ack 1021, win 0, length 0
"""

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


def run():
    print("== tcpdump parser ==")
    packets = tcpdump_parser.parse_tcpdump_output(SAMPLE_TCPDUMP)
    assert len(packets) == 5, f"esperado 5 pacotes, veio {len(packets)}"
    labels = [p["flags_label"] for p in packets]
    assert labels == ["SYN", "SYN-ACK", "PSH-ACK", "PSH-ACK", "RST-ACK"], labels
    assert any("request_0800" in m for m in packets[2]["markers_found"]), packets[2]
    assert any("response_0810" in m for m in packets[3]["markers_found"]), packets[3]
    summary = tcpdump_parser.summarize(packets)
    assert summary["syn"] == 1 and summary["syn_ack"] == 1 and summary["rst_ack"] == 1
    assert summary["request_0800_count"] == 1 and summary["response_0810_count"] == 1
    print("OK:", summary)

    print("== tmsh parser (virtual servers) ==")
    vs_list = tmsh_parser.parse_virtual_servers(SAMPLE_LIST_VS)
    assert len(vs_list) == 2, vs_list
    assert vs_list[0] == {"vs_name": "vs_web_443", "address": "10.1.1.10", "port": 443, "pool_name": "pool_web_443"}
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

    print("\nTODOS OS AUTO-TESTES PASSARAM")


if __name__ == "__main__":
    run()
