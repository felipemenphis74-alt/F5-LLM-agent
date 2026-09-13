"""Leitura opcional de baseline via Google Sheets.

Só funciona se você mesmo criar uma Service Account no Google Cloud, compartilhar a
planilha com o e-mail dela (permissão de Leitor) e montar o JSON de credenciais no
container, apontado por GOOGLE_SHEETS_CREDENTIALS_PATH. Este agente NUNCA realiza o
fluxo OAuth por você — apenas consome credenciais que você já provisionou.

Mesmo schema de colunas (por posição, primeira linha = cabeçalho) descrito em
baseline_excel.py.
"""
from __future__ import annotations

import os
from typing import Optional

from .baseline_excel import COLUMN_ALIASES, BaselineError


def _get_service():
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise BaselineError(
            "Dependências do Google Sheets não instaladas. "
            "Verifique requirements.txt (google-api-python-client, google-auth)."
        ) from exc

    creds_path = os.environ.get("GOOGLE_SHEETS_CREDENTIALS_PATH")
    if not creds_path or not os.path.exists(creds_path):
        raise BaselineError(
            "GOOGLE_SHEETS_CREDENTIALS_PATH não definido ou arquivo inexistente. "
            "Este recurso é opcional: configure-o apenas se for usar baseline via "
            "Google Sheets (veja README)."
        )

    creds = service_account.Credentials.from_service_account_file(
        creds_path,
        scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"],
    )
    return build("sheets", "v4", credentials=creds)


def load_baseline_from_sheet(
    spreadsheet_id: str, sheet_range: str = "A1:F1000"
) -> list[dict]:
    """Lê uma planilha Google Sheets (somente leitura) e normaliza como o Excel local."""
    service = _get_service()
    try:
        result = (
            service.spreadsheets()
            .values()
            .get(spreadsheetId=spreadsheet_id, range=sheet_range)
            .execute()
        )
    except Exception as exc:
        raise BaselineError(f"Falha ao ler Google Sheet {spreadsheet_id!r}: {exc}") from exc

    values = result.get("values", [])
    if not values:
        raise BaselineError("Planilha vazia ou range sem dados.")

    header, *rows = values
    normalized_header = []
    for col in header:
        key = str(col).strip().lower().replace("_", " ")
        matched = None
        for canonical, aliases in COLUMN_ALIASES.items():
            if key in aliases:
                matched = canonical
                break
        normalized_header.append(matched or str(col).strip().lower().replace(" ", "_"))

    if "vs_name" not in normalized_header:
        raise BaselineError(
            f"Coluna obrigatória 'VS Name' não encontrada. Cabeçalho: {header}"
        )

    vs_idx = normalized_header.index("vs_name")
    records = []
    for row in rows:
        if len(row) <= vs_idx or not str(row[vs_idx]).strip():
            continue

        def get(col_name: str) -> Optional[str]:
            if col_name not in normalized_header:
                return None
            idx = normalized_header.index(col_name)
            return row[idx].strip() if idx < len(row) and str(row[idx]).strip() else None

        expected_members_raw = get("expected_members")
        expected_members = []
        if expected_members_raw:
            expected_members = [
                m.strip() for m in expected_members_raw.replace(";", ",").split(",") if m.strip()
            ]

        expected_port_raw = get("expected_port")
        try:
            expected_port = int(expected_port_raw) if expected_port_raw else None
        except ValueError:
            expected_port = None

        records.append({
            "vs_name": str(row[vs_idx]).strip(),
            "pool_name": get("pool_name"),
            "expected_port": expected_port,
            "purpose": get("purpose"),
            "expected_members": expected_members,
            "partition": get("partition") or "Common",
        })

    if not records:
        raise BaselineError("Nenhuma linha válida encontrada na planilha.")

    return records
