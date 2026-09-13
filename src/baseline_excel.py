"""Leitura do baseline de propósito de cada Virtual Server a partir de um Excel local.

Schema esperado (nomes de coluna flexíveis via aliases abaixo — case-insensitive,
espaços/underscores equivalentes):

    VS Name | Pool Name | Expected Port | Purpose | Expected Members | Partition

- VS Name           (obrigatório): nome da Virtual Server no BIG-IP
- Pool Name         (opcional): nome do pool associado esperado
- Expected Port     (opcional): porta esperada da VS
- Purpose           (opcional): descrição de propósito/negócio fornecida pelo cliente
- Expected Members  (opcional): lista de members esperados, separados por vírgula
                                 ou ponto-e-vírgula, formato "ip:porta"
- Partition         (opcional): partição BIG-IP (default "Common")

Arquivos e caminhos são sempre restritos ao diretório de dados montado no container
(F5_MCP_DATA_DIR) — nunca um caminho arbitrário do sistema de arquivos do host.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import pandas as pd

COLUMN_ALIASES = {
    "vs_name": {"vs name", "vsname", "virtual server", "virtual_server", "vs"},
    "pool_name": {"pool name", "poolname", "pool"},
    "expected_port": {"expected port", "port", "expected_port"},
    "purpose": {"purpose", "proposito", "propósito", "descricao", "descrição"},
    "expected_members": {"expected members", "members", "expected_members", "nodes", "expected nodes"},
    "partition": {"partition", "particao", "partição"},
}


class BaselineError(ValueError):
    pass


def _resolve_data_path(filename: str) -> Path:
    data_dir = Path(os.environ.get("F5_MCP_DATA_DIR", "/app/data")).resolve()
    candidate = (data_dir / filename).resolve()
    if data_dir not in candidate.parents and candidate != data_dir:
        raise BaselineError(
            f"Caminho fora do diretório de dados permitido ({data_dir}): {filename!r}"
        )
    if not candidate.exists():
        raise BaselineError(f"Arquivo de baseline não encontrado: {candidate}")
    return candidate


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    normalized_map = {}
    for col in df.columns:
        key = str(col).strip().lower().replace("_", " ")
        matched = None
        for canonical, aliases in COLUMN_ALIASES.items():
            if key in aliases:
                matched = canonical
                break
        normalized_map[col] = matched or str(col).strip().lower().replace(" ", "_")
    return df.rename(columns=normalized_map)


def load_baseline(filename: str, sheet_name: Optional[str] = None) -> list[dict]:
    """Lê um .xlsx do diretório de dados e retorna uma lista de dicts normalizados.

    `filename` é relativo a F5_MCP_DATA_DIR (nunca um path absoluto arbitrário).
    """
    path = _resolve_data_path(filename)
    try:
        df = pd.read_excel(path, sheet_name=sheet_name or 0, engine="openpyxl")
    except Exception as exc:
        raise BaselineError(f"Falha ao ler {path.name}: {exc}") from exc

    df = _normalize_columns(df)

    if "vs_name" not in df.columns:
        raise BaselineError(
            f"Coluna obrigatória 'VS Name' não encontrada em {path.name}. "
            f"Colunas encontradas: {list(df.columns)}"
        )

    records = []
    for _, row in df.iterrows():
        vs_name = row.get("vs_name")
        if pd.isna(vs_name) or not str(vs_name).strip():
            continue

        expected_members_raw = row.get("expected_members")
        expected_members = []
        if isinstance(expected_members_raw, str) and expected_members_raw.strip():
            expected_members = [
                m.strip()
                for m in expected_members_raw.replace(";", ",").split(",")
                if m.strip()
            ]

        expected_port = row.get("expected_port")
        try:
            expected_port = int(expected_port) if not pd.isna(expected_port) else None
        except (TypeError, ValueError):
            expected_port = None

        records.append({
            "vs_name": str(vs_name).strip(),
            "pool_name": (str(row.get("pool_name")).strip()
                          if not pd.isna(row.get("pool_name")) else None),
            "expected_port": expected_port,
            "purpose": (str(row.get("purpose")).strip()
                        if not pd.isna(row.get("purpose")) else None),
            "expected_members": expected_members,
            "partition": (str(row.get("partition")).strip()
                          if not pd.isna(row.get("partition")) else "Common"),
        })

    if not records:
        raise BaselineError(f"Nenhuma linha válida encontrada em {path.name}")

    return records
