from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import NotFoundError, PermissionDeniedError
from app.core.pagination import Page, page_result
from app.core.security import Principal, generate_token, token_digest
from app.database import get_connection
from app.reports.policy import (
    CLASSIFICATION_LEVELS,
    EXPORT_COLUMNS,
    FIELD_TIER_LEVELS,
    classification_label,
    field_tier_label,
    project_report,
)
from app.services.audit import AuditContext, AuditService

SCHEMA = """
CREATE TABLE IF NOT EXISTS disaster_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_no TEXT NOT NULL UNIQUE,
    event_id INTEGER REFERENCES seismic_events(id),
    township TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    address TEXT NOT NULL,
    damage_description TEXT NOT NULL,
    damage_level TEXT NOT NULL CHECK(damage_level IN ('轻微','一般','严重','特别严重')),
    classification TEXT NOT NULL DEFAULT 'general' CHECK(classification IN ('general','sensitive','critical')),
    status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','verified','archived')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS report_role_grants (
    role_code TEXT PRIMARY KEY,
    max_classification TEXT NOT NULL CHECK(max_classification IN ('general','sensitive','critical')),
    field_tier TEXT NOT NULL CHECK(field_tier IN ('public','masked','full')),
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS report_exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER NOT NULL,
    actor_name TEXT NOT NULL,
    field_tier TEXT NOT NULL,
    max_classification TEXT NOT NULL,
    filters_json TEXT NOT NULL,
    columns_json TEXT NOT NULL,
    included_count INTEGER NOT NULL,
    excluded_json TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    content_text TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS report_export_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    export_id INTEGER NOT NULL REFERENCES report_exports(id) ON DELETE CASCADE,
    token_digest TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_township ON disaster_reports(township, classification);
CREATE INDEX IF NOT EXISTS idx_report_exports_actor ON report_exports(actor_user_id, created_at);
"""

# 预置角色及其默认授权：密级上限 + 字段可见级别。
SEED_ROLES = (
    ("commander", "应急指挥员", "查看完整灾情报告并批量导出", ("reports.read", "reports.write", "reports.export"), ("critical", "full")),
    ("collaborator", "跨部门协作员", "查看脱敏灾情副本并导出", ("reports.read", "reports.export"), ("sensitive", "masked")),
    ("public-liaison", "公开信息员", "查看公开汇总口径的灾情信息", ("reports.read",), ("general", "public")),
)
# 已存在的系统角色补充默认授权。
SEED_GRANTS = (("administrator", "critical", "full"),)


def ensure_schema() -> None:
    connection = get_connection()
    connection.executescript(SCHEMA)
    now = to_storage(SystemClock().now())
    for code, name, description, permissions, (max_classification, field_tier) in SEED_ROLES:
        connection.execute(
            "INSERT OR IGNORE INTO roles(code,name,description,is_system,created_at,updated_at) VALUES(?,?,?,1,?,?)",
            (code, name, description, now, now),
        )
        role_id = int(connection.execute("SELECT id FROM roles WHERE code=?", (code,)).fetchone()[0])
        for permission in permissions:
            connection.execute(
                "INSERT OR IGNORE INTO role_permissions(role_id,permission_id,granted_at) "
                "SELECT ?,id,? FROM permissions WHERE code=?",
                (role_id, now, permission),
            )
        connection.execute(
            "INSERT OR IGNORE INTO report_role_grants(role_code,max_classification,field_tier,updated_by,updated_at) VALUES(?,?,?,?,?)",
            (code, max_classification, field_tier, "system", now),
        )
    for code, max_classification, field_tier in SEED_GRANTS:
        connection.execute(
            "INSERT OR IGNORE INTO report_role_grants(role_code,max_classification,field_tier,updated_by,updated_at) VALUES(?,?,?,?,?)",
            (code, max_classification, field_tier, "system", now),
        )


@dataclass(frozen=True, slots=True)
class Grant:
    max_classification: str
    field_tier: str

    def allows(self, classification: str) -> bool:
        return CLASSIFICATION_LEVELS[classification] <= CLASSIFICATION_LEVELS[self.max_classification]


def _deny_classification(report_classification: str, grant: Grant) -> PermissionDeniedError:
    return PermissionDeniedError(
        f"报告密级（{classification_label(report_classification)}）超出当前角色授权上限（{classification_label(grant.max_classification)}）",
        context={
            "reason_code": "classification_exceeded",
            "report_classification": report_classification,
            "granted_max_classification": grant.max_classification,
        },
    )


class ReportService:
    """灾情报告的密级授权、字段脱敏与导出审计服务。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()
        self.audit = AuditService(self.connection, self.clock)
        self.token_ttl_hours = int(os.getenv("TOWNSHIP_EXPORT_TOKEN_TTL_HOURS", "24"))

    # ------------------------------------------------------------------ 授权
    def effective_grant(self, principal: Principal) -> Grant:
        """实时汇总当前账号各角色的授权，取最宽组合；不缓存，授权变化立即生效。"""
        if "*" in principal.permissions:
            return Grant("critical", "full")
        rows = self.connection.execute(
            "SELECT g.role_code,g.max_classification,g.field_tier FROM report_role_grants g "
            "JOIN roles r ON r.code=g.role_code "
            "JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?",
            (principal.user_id,),
        ).fetchall()
        if not rows:
            roles = [str(row[0]) for row in self.connection.execute(
                "SELECT r.code FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=? ORDER BY r.code",
                (principal.user_id,),
            ).fetchall()]
            raise PermissionDeniedError(
                "当前账号的角色未配置灾情报告授权策略",
                context={"reason_code": "grant_not_configured", "roles": roles},
            )
        best = max(rows, key=lambda row: (CLASSIFICATION_LEVELS[row["max_classification"]],))
        tier = max((row["field_tier"] for row in rows), key=lambda value: FIELD_TIER_LEVELS[value])
        return Grant(best["max_classification"], tier)

    def _require_grant(self, principal: Principal, permission: str) -> Grant:
        principal.require(permission)
        return self.effective_grant(principal)

    # ------------------------------------------------------------------ 报告
    def create_report(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        self._require_grant(principal, "reports.write")
        if data.get("event_id") is not None:
            if not self.connection.execute("SELECT 1 FROM seismic_events WHERE id=?", (data["event_id"],)).fetchone():
                raise NotFoundError("关联的地震事件不存在")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO disaster_reports(report_no,event_id,township,contact_name,contact_phone,address,"
            "damage_description,damage_level,classification,status,created_by,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,'submitted',?,?,?)",
            (
                f"PENDING-{generate_token()}",
                data.get("event_id"),
                data["township"],
                data["contact_name"],
                data["contact_phone"],
                data["address"],
                data["damage_description"],
                data["damage_level"],
                data.get("classification", "general"),
                principal.display_name,
                now,
                now,
            ),
        )
        report_id = int(cursor.lastrowid)
        report_no = f"DR-{self.clock.now():%Y%m%d}-{report_id:05d}"
        self.connection.execute("UPDATE disaster_reports SET report_no=? WHERE id=?", (report_no, report_id))
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="report.create",
            resource_type="disaster_report",
            resource_id=report_id,
            metadata={"report_no": report_no, "township": data["township"], "classification": data.get("classification", "general")},
        )
        return self._require_report(report_id)

    def get_report(self, principal: Principal, report_id: int) -> dict[str, Any]:
        grant = self._require_grant(principal, "reports.read")
        row = self._require_report(report_id)
        if not grant.allows(row["classification"]):
            raise _deny_classification(row["classification"], grant)
        return project_report(row, grant.field_tier)

    def list_reports(self, principal: Principal, filters: dict[str, Any], page: Page) -> dict[str, Any]:
        grant = self._require_grant(principal, "reports.read")
        allowed = [name for name, level in CLASSIFICATION_LEVELS.items() if level <= CLASSIFICATION_LEVELS[grant.max_classification]]
        conditions = ["classification IN (" + ",".join("?" for _ in allowed) + ")"]
        params: list[Any] = list(allowed)
        for column, value in (("township", filters.get("township")), ("classification", filters.get("classification")), ("damage_level", filters.get("damage_level"))):
            if value:
                conditions.append(f"{column}=?")
                params.append(value)
        where = " WHERE " + " AND ".join(conditions)
        total = int(self.connection.execute("SELECT COUNT(*) FROM disaster_reports" + where, tuple(params)).fetchone()[0])
        rows = self.connection.execute(
            "SELECT * FROM disaster_reports" + where + " ORDER BY id LIMIT ? OFFSET ?",
            (*params, page.size, page.offset),
        ).fetchall()
        return page_result(total=total, page=page, rows=[project_report(dict(row), grant.field_tier) for row in rows])

    def _require_report(self, report_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM disaster_reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            raise NotFoundError("灾情报告不存在")
        return dict(row)

    # ------------------------------------------------------------------ 授权策略
    def list_policies(self, principal: Principal) -> list[dict[str, Any]]:
        principal.require("reports.policy")
        rows = self.connection.execute("SELECT * FROM report_role_grants ORDER BY role_code").fetchall()
        return [dict(row) for row in rows]

    def put_policy(self, principal: Principal, role_code: str, update: dict[str, Any]) -> dict[str, Any]:
        principal.require("reports.policy")
        if not self.connection.execute("SELECT 1 FROM roles WHERE code=?", (role_code,)).fetchone():
            raise NotFoundError(f"角色不存在：{role_code}")
        before_row = self.connection.execute("SELECT * FROM report_role_grants WHERE role_code=?", (role_code,)).fetchone()
        before = dict(before_row) if before_row else None
        now = to_storage(self.clock.now())
        self.connection.execute(
            "INSERT INTO report_role_grants(role_code,max_classification,field_tier,updated_by,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(role_code) DO UPDATE SET max_classification=excluded.max_classification,"
            "field_tier=excluded.field_tier,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
            (role_code, update["max_classification"], update["field_tier"], principal.display_name, now),
        )
        after = dict(self.connection.execute("SELECT * FROM report_role_grants WHERE role_code=?", (role_code,)).fetchone())
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="report.policy.update",
            resource_type="report_role_grant",
            resource_id=role_code,
            before=before,
            after=after,
        )
        return after

    # ------------------------------------------------------------------ 导出
    def create_export(self, principal: Principal, filters: dict[str, Any]) -> dict[str, Any]:
        grant = self._require_grant(principal, "reports.export")
        conditions: list[str] = []
        params: list[Any] = []
        active_filters = {key: value for key, value in filters.items() if value}
        for column, value in active_filters.items():
            conditions.append(f"{column}=?")
            params.append(value)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        rows = [dict(row) for row in self.connection.execute(
            "SELECT * FROM disaster_reports" + where + " ORDER BY id", tuple(params)
        ).fetchall()]

        columns = EXPORT_COLUMNS[grant.field_tier]
        included: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        for row in rows:
            if grant.allows(row["classification"]):
                included.append(project_report(row, grant.field_tier))
            else:
                excluded.append({
                    "report_no": row["report_no"],
                    "classification": row["classification"],
                    "reason": f"报告密级（{classification_label(row['classification'])}）超出当前角色授权上限（{classification_label(grant.max_classification)}），已过滤",
                })

        content = self._csv(columns, included)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        now = to_storage(self.clock.now())
        summary = {
            "actor": {"user_id": principal.user_id, "name": principal.display_name},
            "field_tier": grant.field_tier,
            "field_tier_label": field_tier_label(grant.field_tier),
            "max_classification": grant.max_classification,
            "filters": active_filters,
            "columns": [key for key, _ in columns],
            "included_count": len(included),
            "excluded": excluded,
            "content_digest": digest,
            "created_at": now,
        }
        cursor = self.connection.execute(
            "INSERT INTO report_exports(actor_user_id,actor_name,field_tier,max_classification,filters_json,"
            "columns_json,included_count,excluded_json,content_digest,content_text,summary_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                principal.user_id,
                principal.display_name,
                grant.field_tier,
                grant.max_classification,
                json.dumps(active_filters, ensure_ascii=False, sort_keys=True),
                json.dumps(summary["columns"], ensure_ascii=False),
                len(included),
                json.dumps(excluded, ensure_ascii=False),
                digest,
                content,
                json.dumps(summary, ensure_ascii=False, sort_keys=True),
                now,
            ),
        )
        export_id = int(cursor.lastrowid)
        summary["export_id"] = export_id
        self.connection.execute(
            "UPDATE report_exports SET summary_json=? WHERE id=?",
            (json.dumps(summary, ensure_ascii=False, sort_keys=True), export_id),
        )
        token = generate_token()
        expires_at = to_storage(self.clock.now() + timedelta(hours=self.token_ttl_hours))
        self.connection.execute(
            "INSERT INTO report_export_tokens(export_id,token_digest,issued_at,expires_at) VALUES(?,?,?,?)",
            (export_id, token_digest(token), now, expires_at),
        )
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="report.export.create",
            resource_type="report_export",
            resource_id=export_id,
            metadata={
                "field_tier": grant.field_tier,
                "included_count": len(included),
                "excluded_count": len(excluded),
                "content_digest": digest,
            },
        )
        return {
            "export": summary,
            "download_token": token,
            "download_url": f"/api/reports/exports/{export_id}/download",
            "token_expires_at": expires_at,
        }

    def get_export(self, principal: Principal, export_id: int) -> dict[str, Any]:
        self._require_export_reader(principal)
        row = self._require_export(export_id)
        return self._export_view(row)

    def list_exports(self, principal: Principal, page: Page) -> dict[str, Any]:
        self._require_export_reader(principal)
        total = int(self.connection.execute("SELECT COUNT(*) FROM report_exports").fetchone()[0])
        rows = self.connection.execute(
            "SELECT * FROM report_exports ORDER BY id DESC LIMIT ? OFFSET ?", (page.size, page.offset)
        ).fetchall()
        return page_result(total=total, page=page, rows=[self._export_view(dict(row)) for row in rows])

    def revoke_export(self, principal: Principal, export_id: int, reason: str) -> dict[str, Any]:
        row = self._require_export(export_id)
        if row["actor_user_id"] != principal.user_id and not principal.can("reports.policy"):
            raise PermissionDeniedError(
                "只能撤销本人创建的导出令牌，或由报告授权管理员撤销",
                context={"reason_code": "not_export_owner", "export_id": export_id},
            )
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE report_export_tokens SET revoked_at=?,revoke_reason=? WHERE export_id=? AND revoked_at IS NULL",
            (now, reason, export_id),
        )
        if cursor.rowcount == 0:
            raise NotFoundError("该导出没有可撤销的有效令牌")
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="report.export.revoke",
            resource_type="report_export",
            resource_id=export_id,
            metadata={"reason": reason},
        )
        return self._export_view(self._require_export(export_id))

    def download_export(self, export_id: int, token: str) -> dict[str, Any]:
        row = self._require_export(export_id)
        token_row = self.connection.execute(
            "SELECT * FROM report_export_tokens WHERE export_id=? AND token_digest=?",
            (export_id, token_digest(token)),
        ).fetchone()
        if token_row is None:
            self._audit_download(row, "denied", "下载令牌无效")
            raise PermissionDeniedError("下载令牌无效", context={"reason_code": "token_invalid", "export_id": export_id})
        if token_row["revoked_at"] is not None:
            self._audit_download(row, "denied", "下载令牌已撤销")
            raise PermissionDeniedError(
                "下载令牌已撤销",
                context={"reason_code": "token_revoked", "export_id": export_id, "revoked_at": token_row["revoked_at"], "revoke_reason": token_row["revoke_reason"]},
            )
        expires_at = from_storage(token_row["expires_at"])
        if expires_at is not None and expires_at <= self.clock.now():
            self._audit_download(row, "denied", "下载令牌已过期")
            raise PermissionDeniedError("下载令牌已过期", context={"reason_code": "token_expired", "export_id": export_id, "expires_at": token_row["expires_at"]})
        self._audit_download(row, "success", "")
        return {
            "filename": f"disaster-reports-{export_id}.csv",
            "content": row["content_text"],
            "content_digest": row["content_digest"],
        }

    def _require_export_reader(self, principal: Principal) -> None:
        if not (principal.can("reports.export") or principal.can("audit.read")):
            raise PermissionDeniedError(
                "缺少权限：reports.export 或 audit.read",
                context={"reason_code": "permission_missing", "any_of": ["reports.export", "audit.read"]},
            )

    def _require_export(self, export_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM report_exports WHERE id=?", (export_id,)).fetchone()
        if row is None:
            raise NotFoundError("导出记录不存在")
        return dict(row)

    def _export_view(self, row: dict[str, Any]) -> dict[str, Any]:
        """审计视图：只读已生成的摘要，绝不回写，也不暴露导出内容本身。"""
        summary = json.loads(row["summary_json"])
        token = self.connection.execute(
            "SELECT revoked_at,revoke_reason,expires_at FROM report_export_tokens WHERE export_id=? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        summary["token_status"] = "revoked" if token and token["revoked_at"] else "active"
        if token and token["revoked_at"]:
            summary["token_revoked_at"] = token["revoked_at"]
            summary["token_revoke_reason"] = token["revoke_reason"]
        return summary

    def _audit_download(self, export_row: dict[str, Any], outcome: str, reason: str) -> None:
        self.audit.record(
            AuditContext(export_row["actor_user_id"], export_row["actor_name"]),
            action="report.export.download",
            resource_type="report_export",
            resource_id=export_row["id"],
            outcome=outcome,
            metadata={"reason": reason} if reason else {},
        )

    @staticmethod
    def _csv(columns: tuple[tuple[str, str], ...], rows: list[dict[str, Any]]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([label for _, label in columns])
        for row in rows:
            writer.writerow(["" if row.get(key) is None else str(row.get(key)) for key, _ in columns])
        return buffer.getvalue()
