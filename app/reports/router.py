from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response

from app.api.dependencies import current_principal
from app.core.pagination import Page
from app.core.security import Principal
from app.database import get_connection, transaction
from app.reports.schemas import ExportCreate, ExportRevoke, PolicyUpdate, ReportCreate
from app.reports.service import ReportService

router = APIRouter(prefix="/api/reports", tags=["灾情报告分级"])


@router.post("", status_code=201)
def create_report(data: ReportCreate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return ReportService(connection).create_report(principal, data.model_dump())


@router.get("/policies")
def list_policies(principal: Principal = Depends(current_principal)) -> list[dict]:
    return ReportService(get_connection()).list_policies(principal)


@router.put("/policies/{role_code}")
def put_policy(role_code: str, data: PolicyUpdate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return ReportService(connection).put_policy(principal, role_code, data.model_dump())


@router.post("/exports", status_code=201)
def create_export(data: ExportCreate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return ReportService(connection).create_export(principal, data.model_dump(exclude_none=True))


@router.get("/exports")
def list_exports(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    return ReportService(get_connection()).list_exports(principal, Page(page, size))


@router.get("/exports/{export_id}")
def get_export(export_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return ReportService(get_connection()).get_export(principal, export_id)


@router.get("/exports/{export_id}/download")
def download_export(export_id: int, token: str = Query(..., min_length=1)) -> Response:
    result = ReportService(get_connection()).download_export(export_id, token)
    return Response(
        content=result["content"],
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{result["filename"]}"',
            "X-Content-Digest": result["content_digest"],
        },
    )


@router.post("/exports/{export_id}/revoke")
def revoke_export(export_id: int, data: ExportRevoke, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return ReportService(connection).revoke_export(principal, export_id, data.reason)


@router.get("")
def list_reports(
    township: str | None = None,
    classification: str | None = None,
    damage_level: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    filters = {"township": township, "classification": classification, "damage_level": damage_level}
    return ReportService(get_connection()).list_reports(principal, filters, Page(page, size))


@router.get("/{report_id}")
def get_report(report_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return ReportService(get_connection()).get_report(principal, report_id)
