from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.disaster.schemas import DisasterReportCreate, DisasterReportPatch, ExportRequest
from app.disaster.service import DisasterReportService

router = APIRouter(prefix="/api/disaster", tags=["灾情报告分级保护"])


def service() -> DisasterReportService:
    return DisasterReportService()


@router.post("/reports", status_code=201)
def create_report(payload: DisasterReportCreate, principal: Principal = Depends(current_principal)) -> dict:
    return service().create_report(principal, payload.model_dump())


@router.get("/reports")
def list_reports(
    township: str | None = Query(default=None, max_length=80),
    principal: Principal = Depends(current_principal),
) -> dict:
    return service().list_reports(principal, township)


@router.get("/reports/{report_id}")
def get_report(report_id: int, principal: Principal = Depends(current_principal)) -> dict:
    return service().get_detail(principal, report_id)


@router.patch("/reports/{report_id}")
def patch_report(report_id: int, payload: DisasterReportPatch, principal: Principal = Depends(current_principal)) -> dict:
    return service().patch_report(principal, report_id, payload.model_dump(exclude_unset=True))


@router.post("/exports", status_code=201)
def create_export(payload: ExportRequest, principal: Principal = Depends(current_principal)) -> dict:
    return service().create_export(principal, payload.classification, payload.township)


@router.get("/exports")
def list_exports(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("disaster.export")
    return {"data": service().list_exports(principal)}


@router.get("/exports/{export_id}/download")
def download_export(
    export_id: int,
    principal: Principal = Depends(current_principal),
    x_export_token: str = Header(..., alias="X-Export-Token", min_length=8),
) -> dict:
    return service().download_export(principal, export_id, x_export_token)


@router.post("/exports/{export_id}/revoke")
def revoke_export(
    export_id: int,
    reason: str = Query(..., min_length=1, max_length=200),
    principal: Principal = Depends(current_principal),
) -> dict:
    return service().revoke_export(principal, export_id, reason)
