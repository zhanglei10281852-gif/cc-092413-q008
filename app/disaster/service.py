from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import (
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from app.core.security import Principal, generate_token, token_digest
from app.database import get_connection, transaction
from app.disaster.policy import (
    CLASSIFICATION_RANK,
    EXPORT_COLUMNS,
    REASON_CLASSIFICATION,
    REASON_NOT_OWNER,
    REASON_TOKEN_EXPIRED,
    REASON_TOKEN_REVOKED,
    REASON_TOKEN_UNKNOWN,
    ViewProfile,
    can_see_classification,
    profile_for,
    project_report,
    to_export_row,
)
from app.services.audit import AuditContext, AuditService

SCHEMA = """
CREATE TABLE IF NOT EXISTS disaster_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    township TEXT NOT NULL,
    reporter_name TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    address TEXT NOT NULL,
    damage_description TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN ('public','internal','restricted')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','verified','archived')),
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS disaster_export_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_digest TEXT NOT NULL UNIQUE,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    owner_name TEXT NOT NULL,
    requested_classification TEXT NOT NULL,
    township TEXT,
    view_code TEXT NOT NULL,
    columns_json TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    filtered_count INTEGER NOT NULL,
    filters_json TEXT NOT NULL,
    rows_json TEXT NOT NULL,
    summary_sha256 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
    revoke_reason TEXT,
    revoked_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_disaster_reports_cls ON disaster_reports(classification, township);
CREATE INDEX IF NOT EXISTS idx_disaster_exports_owner ON disaster_export_tokens(owner_user_id, status);
"""

EXPORT_TTL_MINUTES = 60
REASON_ABOVE_REQUESTED = "classification_above_requested"


def ensure_schema() -> None:
    get_connection().executescript(SCHEMA)


def _compute_summary(columns: list[str], rows: list[dict[str, str]], filters: list[dict[str, Any]]) -> str:
    """对导出快照（列顺序 + 数据行 + 过滤原因）计算固化摘要。"""
    payload = json.dumps(
        {"columns": columns, "rows": rows, "filters": filters},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


class DisasterReportService:
    """灾情报告的密级过滤、字段投影、导出令牌与审计。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        ensure_schema()
        self.clock = clock or SystemClock()
        self.audit = AuditService(self.connection, self.clock)

    # ----- 报告维护 -----

    def create_report(self, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
        principal.require("disaster.write")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            cursor = connection.execute(
                "INSERT INTO disaster_reports(township,reporter_name,contact_phone,address,damage_description,"
                "classification,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,'pending',?,?,?)",
                (
                    payload["township"],
                    payload["reporter_name"],
                    payload["contact_phone"],
                    payload["address"],
                    payload["damage_description"],
                    payload["classification"],
                    principal.user_id,
                    now,
                    now,
                ),
            )
            report_id = int(cursor.lastrowid)
            self.audit.record(
                AuditContext(principal.user_id, principal.display_name),
                action="disaster.report.create",
                resource_type="disaster_report",
                resource_id=report_id,
                after={"township": payload["township"], "classification": payload["classification"]},
            )
        return self.get_detail(principal, report_id, audit_denied=False)

    def patch_report(self, principal: Principal, report_id: int, changes: dict[str, Any]) -> dict[str, Any]:
        principal.require("disaster.write")
        with transaction(immediate=True) as connection:
            row = connection.execute("SELECT * FROM disaster_reports WHERE id=?", (report_id,)).fetchone()
            if row is None:
                raise NotFoundError("灾情报告不存在")
            updates = {key: value for key, value in changes.items() if value is not None and key in {"classification", "status"}}
            if updates:
                assignments = ", ".join(f"{key}=?" for key in updates)
                connection.execute(
                    f"UPDATE disaster_reports SET {assignments},updated_at=? WHERE id=?",
                    (*updates.values(), to_storage(self.clock.now()), report_id),
                )
            self.audit.record(
                AuditContext(principal.user_id, principal.display_name),
                action="disaster.report.patch",
                resource_type="disaster_report",
                resource_id=report_id,
                before={key: row[key] for key in ("classification", "status")},
                after=updates or {key: row[key] for key in ("classification", "status")},
            )
        return self.get_detail(principal, report_id, audit_denied=False)

    # ----- 读取：详情与列表 -----

    def get_detail(self, principal: Principal, report_id: int, *, audit_denied: bool = True) -> dict[str, Any]:
        profile = profile_for(principal)
        row = self.connection.execute("SELECT * FROM disaster_reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            raise NotFoundError("灾情报告不存在")
        if not can_see_classification(profile, row["classification"]):
            self._deny(
                principal,
                action="disaster.report.detail",
                resource_id=report_id,
                reason=REASON_CLASSIFICATION,
                profile=profile,
                classification=row["classification"],
                audit=audit_denied,
            )
        return project_report(dict(row), profile)

    def list_reports(self, principal: Principal, township: str | None = None) -> dict[str, Any]:
        profile = profile_for(principal)
        conditions = ["1=1"]
        params: list[Any] = []
        if township:
            conditions.append("township=?")
            params.append(township)
        rows = self.connection.execute(
            "SELECT * FROM disaster_reports WHERE " + " AND ".join(conditions) + " ORDER BY id",
            tuple(params),
        ).fetchall()
        visible: list[dict[str, Any]] = []
        hidden = 0
        for row in rows:
            if can_see_classification(profile, row["classification"]):
                visible.append(project_report(dict(row), profile))
            else:
                hidden += 1
        return {
            "view": profile.code,
            "clearance": profile.clearance,
            "total_matched": len(rows),
            "returned": len(visible),
            "filtered_out": hidden,
            "filters": [{"reason": REASON_CLASSIFICATION, "count": hidden}] if hidden else [],
            "data": visible,
        }

    # ----- 批量导出与可撤销令牌 -----

    def create_export(self, principal: Principal, requested: str, township: str | None) -> dict[str, Any]:
        principal.require("disaster.export")
        profile = profile_for(principal)
        if requested not in CLASSIFICATION_RANK:
            raise ValidationError(f"未知密级：{requested}")
        if CLASSIFICATION_RANK[requested] > CLASSIFICATION_RANK[profile.clearance]:
            self._deny(
                principal,
                action="disaster.export.issue",
                resource_id=None,
                reason=REASON_CLASSIFICATION,
                audit=True,
                profile=profile,
                classification=requested,
            )
        rows = self.connection.execute(
            "SELECT * FROM disaster_reports WHERE (? IS NULL OR township=?) ORDER BY id",
            (township, township),
        ).fetchall()

        effective_cap = CLASSIFICATION_RANK[requested]
        filters: dict[str, dict[str, Any]] = {}

        def bump(reason: str, **extra: Any) -> None:
            item = filters.setdefault(reason, {"reason": reason, "count": 0})
            item["count"] += 1
            item.update(extra)

        projected: list[dict[str, str]] = []
        for row in rows:
            rank = CLASSIFICATION_RANK[row["classification"]]
            if rank > effective_cap:
                bump(REASON_ABOVE_REQUESTED, requested=requested)
                continue
            projected.append(to_export_row(project_report(dict(row), profile)))

        # 固定列顺序：严格按 EXPORT_COLUMNS 重建每一行，杜绝视图投影带来的列差异
        ordered_rows = [{column: row.get(column, "") for column in EXPORT_COLUMNS} for row in projected]
        filter_list = [filters[key] for key in sorted(filters)]
        filtered_count = sum(item["count"] for item in filter_list)
        summary = _compute_summary(list(EXPORT_COLUMNS), ordered_rows, filter_list)

        token = generate_token()
        now = self.clock.now()
        expires = now + timedelta(minutes=EXPORT_TTL_MINUTES)
        with transaction(immediate=True) as connection:
            cursor = connection.execute(
                "INSERT INTO disaster_export_tokens(token_digest,owner_user_id,owner_name,requested_classification,"
                "township,view_code,columns_json,row_count,filtered_count,filters_json,rows_json,summary_sha256,"
                "expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    token_digest(token),
                    principal.user_id,
                    principal.display_name,
                    requested,
                    township,
                    profile.code,
                    json.dumps(list(EXPORT_COLUMNS), ensure_ascii=False),
                    len(ordered_rows),
                    filtered_count,
                    json.dumps(filter_list, ensure_ascii=False, sort_keys=True),
                    json.dumps(ordered_rows, ensure_ascii=False),
                    summary,
                    to_storage(expires),
                    to_storage(now),
                ),
            )
            export_id = int(cursor.lastrowid)
            self.audit.record(
                AuditContext(principal.user_id, principal.display_name),
                action="disaster.export.issue",
                resource_type="disaster_export",
                resource_id=export_id,
                after={
                    "view": profile.code,
                    "requested_classification": requested,
                    "township": township,
                    "row_count": len(ordered_rows),
                    "filtered_count": filtered_count,
                    "filters": filter_list,
                    "columns": list(EXPORT_COLUMNS),
                    "summary_sha256": summary,
                },
            )
        return {
            "export_id": export_id,
            "token": token,
            "view": profile.code,
            "expires_at": to_storage(expires),
            "columns": list(EXPORT_COLUMNS),
            "row_count": len(ordered_rows),
            "filtered_count": filtered_count,
            "filters": filter_list,
            "summary_sha256": summary,
            "download_path": f"/api/disaster/exports/{export_id}/download",
        }

    def list_exports(self, principal: Principal) -> list[dict[str, Any]]:
        can_view_all = principal.can("disaster.export.revoke")
        if can_view_all:
            rows = self.connection.execute("SELECT * FROM disaster_export_tokens ORDER BY id DESC").fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM disaster_export_tokens WHERE owner_user_id=? ORDER BY id DESC",
                (principal.user_id,),
            ).fetchall()
        return [self._export_brief(row) for row in rows]

    def download_export(self, principal: Principal, export_id: int, token: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM disaster_export_tokens WHERE id=?", (export_id,)).fetchone()
        digest = token_digest(token)
        if row is None or row["token_digest"] != digest:
            self._deny(
                principal,
                action="disaster.export.download",
                resource_id=export_id,
                reason=REASON_TOKEN_UNKNOWN,
                audit=True,
            )
        if row["owner_user_id"] != principal.user_id and not principal.can("disaster.export.revoke"):
            self._deny(
                principal,
                action="disaster.export.download",
                resource_id=export_id,
                reason=REASON_NOT_OWNER,
                audit=True,
            )
        if row["status"] == "revoked":
            self._deny(
                principal,
                action="disaster.export.download",
                resource_id=export_id,
                reason=REASON_TOKEN_REVOKED,
                audit=True,
            )
        if from_storage(row["expires_at"]) <= self.clock.now():
            self._deny(
                principal,
                action="disaster.export.download",
                resource_id=export_id,
                reason=REASON_TOKEN_EXPIRED,
                audit=True,
            )
        columns = json.loads(row["columns_json"])
        rows_data = json.loads(row["rows_json"])
        filters_data = json.loads(row["filters_json"])
        # 授权变化立即生效：按账号当前密级重新校验快照，降权后旧导出不可再下载，
        # 但快照与签发时的摘要原样保留、绝不改写。
        current_profile = profile_for(principal)
        max_row_rank = max((CLASSIFICATION_RANK[item["classification"]] for item in rows_data), default=-1)
        if max_row_rank > CLASSIFICATION_RANK[current_profile.clearance]:
            self._deny(
                principal,
                action="disaster.export.download",
                resource_id=export_id,
                reason="export_clearance_reduced",
                audit=True,
                profile=current_profile,
            )
        # 重新计算摘要，证明已固化的导出快照没有被后续授权变化或其他更新篡改
        current_summary = _compute_summary(columns, rows_data, filters_data)
        if not hmac.compare_digest(current_summary, row["summary_sha256"]):
            self._deny(
                principal,
                action="disaster.export.download",
                resource_id=export_id,
                reason="export_summary_tampered",
                audit=True,
            )
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="disaster.export.download",
            resource_type="disaster_export",
            resource_id=export_id,
            metadata={"row_count": row["row_count"], "summary_sha256": row["summary_sha256"]},
        )
        return {
            "export_id": export_id,
            "view": row["view_code"],
            "columns": columns,
            "rows": rows_data,
            "filters": filters_data,
            "summary_sha256": row["summary_sha256"],
        }

    def revoke_export(self, principal: Principal, export_id: int, reason: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM disaster_export_tokens WHERE id=?", (export_id,)).fetchone()
        if row is None:
            raise NotFoundError("导出任务不存在")
        if row["owner_user_id"] != principal.user_id and not principal.can("disaster.export.revoke"):
            self._deny(
                principal,
                action="disaster.export.revoke",
                resource_id=export_id,
                reason=REASON_NOT_OWNER,
                audit=True,
            )
        before_summary = row["summary_sha256"]
        with transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE disaster_export_tokens SET status='revoked',revoke_reason=?,revoked_at=? WHERE id=?",
                (reason, to_storage(self.clock.now()), export_id),
            )
            # 撤令牌只改令牌状态，摘要与数据快照原样保留
            untouched = connection.execute(
                "SELECT summary_sha256 FROM disaster_export_tokens WHERE id=?", (export_id,)
            ).fetchone()["summary_sha256"]
            if untouched != before_summary:
                raise RuntimeError("撤销令牌时导出摘要发生变化")
            self.audit.record(
                AuditContext(principal.user_id, principal.display_name),
                action="disaster.export.revoke",
                resource_type="disaster_export",
                resource_id=export_id,
                after={"status": "revoked", "revoke_reason": reason, "summary_sha256": before_summary},
            )
        return self._export_brief(
            self.connection.execute("SELECT * FROM disaster_export_tokens WHERE id=?", (export_id,)).fetchone()
        )

    # ----- 辅助 -----

    def _export_brief(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "export_id": row["id"],
            "owner_user_id": row["owner_user_id"],
            "owner_name": row["owner_name"],
            "view": row["view_code"],
            "requested_classification": row["requested_classification"],
            "township": row["township"],
            "row_count": row["row_count"],
            "filtered_count": row["filtered_count"],
            "filters": json.loads(row["filters_json"]),
            "columns": json.loads(row["columns_json"]),
            "summary_sha256": row["summary_sha256"],
            "status": row["status"],
            "revoke_reason": row["revoke_reason"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "revoked_at": row["revoked_at"],
        }

    def _deny(
        self,
        principal: Principal,
        *,
        action: str,
        resource_id: int,
        reason: str,
        audit: bool,
        profile: ViewProfile | None = None,
        classification: str | None = None,
        clearance: str | None = None,
    ) -> None:
        messages = {
            REASON_CLASSIFICATION: (
                f"报告密级 {classification} 高于当前账号可见密级 {profile.clearance if profile else clearance}"
                if classification else f"当前账号可见密级不足（{profile.clearance if profile else clearance}）"
            ),
            REASON_TOKEN_UNKNOWN: "下载令牌不存在或不正确",
            REASON_TOKEN_REVOKED: "下载令牌已被撤销",
            REASON_TOKEN_EXPIRED: "下载令牌已过期",
            REASON_NOT_OWNER: "导出任务不属于当前账号",
            "export_summary_tampered": "导出快照摘要校验失败，数据可能已被篡改",
            "export_clearance_reduced": (
                f"账号当前密级 {profile.clearance if profile else ''} 已低于导出快照密级，"
                "旧令牌不可用，请按当前权限重新申请导出"
            ),
        }
        if audit:
            self.audit.record(
                AuditContext(principal.user_id, principal.display_name),
                action=action,
                resource_type="disaster_export" if "export" in action else "disaster_report",
                resource_id=resource_id,
                outcome="denied",
                metadata={"reason": reason, "view": profile.code if profile else None},
            )
        raise PermissionDeniedError(f"{messages.get(reason, '访问被拒绝')}（{reason}）", context={"reason": reason})
