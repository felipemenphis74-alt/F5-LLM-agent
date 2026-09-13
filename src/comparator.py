"""Compara o baseline (Excel/Sheets) fornecido pelo cliente com o estado real lido
do F5, e reporta divergências. Não faz nenhuma alteração — só diffs."""
from __future__ import annotations


def compare_vs_to_baseline(live_vs: list[dict], baseline: list[dict]) -> dict:
    live_by_name = {v["vs_name"]: v for v in live_vs}
    baseline_by_name = {b["vs_name"]: b for b in baseline}

    matched = []
    missing_on_device = []   # está no baseline, não existe no F5
    unexpected_on_device = []  # existe no F5, não está no baseline

    for name, base in baseline_by_name.items():
        live = live_by_name.get(name)
        if live is None:
            missing_on_device.append({"vs_name": name, "purpose": base.get("purpose")})
            continue

        diffs = {}
        if base.get("pool_name") and live.get("pool_name") != base["pool_name"]:
            diffs["pool_name"] = {"expected": base["pool_name"], "actual": live.get("pool_name")}
        if base.get("expected_port") and live.get("port") != base["expected_port"]:
            diffs["port"] = {"expected": base["expected_port"], "actual": live.get("port")}

        matched.append({
            "vs_name": name,
            "purpose": base.get("purpose"),
            "status": "OK" if not diffs else "DIVERGENTE",
            "diffs": diffs,
        })

    for name in live_by_name:
        if name not in baseline_by_name:
            unexpected_on_device.append({"vs_name": name})

    return {
        "matched": matched,
        "missing_on_device": missing_on_device,
        "unexpected_on_device": unexpected_on_device,
        "summary": {
            "total_baseline": len(baseline_by_name),
            "total_live": len(live_by_name),
            "ok": sum(1 for m in matched if m["status"] == "OK"),
            "divergent": sum(1 for m in matched if m["status"] == "DIVERGENTE"),
            "missing_on_device": len(missing_on_device),
            "unexpected_on_device": len(unexpected_on_device),
        },
    }


def compare_pool_members_to_baseline(vs_name: str, live_members: list[dict], expected_members: list[str]) -> dict:
    live_set = {f"{m['address']}:{m['port']}" for m in live_members}
    expected_set = set(expected_members)

    missing = sorted(expected_set - live_set)
    unexpected = sorted(live_set - expected_set)
    down_members = [m for m in live_members if (m.get("availability") or "").lower() not in ("available", "green")]

    return {
        "vs_name": vs_name,
        "expected_count": len(expected_set),
        "live_count": len(live_set),
        "missing_members": missing,
        "unexpected_members": unexpected,
        "down_members": down_members,
        "status": "OK" if not missing and not unexpected and not down_members else "ATENCAO",
    }
