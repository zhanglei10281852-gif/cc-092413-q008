from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.core.errors import PermissionDeniedError
from app.core.privacy import mask_phone, sanitize_text
from app.core.security import Principal

#: 报告密级，等级依次升高
CLASSIFICATIONS: tuple[str, ...] = ("public", "internal", "restricted")
CLASSIFICATION_RANK: dict[str, int] = {name: index for index, name in enumerate(CLASSIFICATIONS)}

#: 越权（请求密级高于角色可见密级）的统一原因码
REASON_CLASSIFICATION = "classification_above_clearance"
#: 导出令牌相关原因码
REASON_TOKEN_UNKNOWN = "export_token_unknown"
REASON_TOKEN_REVOKED = "export_token_revoked"
REASON_TOKEN_EXPIRED = "export_token_expired"
#: 导出资源不属于当前账号
REASON_NOT_OWNER = "export_not_owner"

#: 批量导出的固定列顺序，任何视图都不得增删或调换列
EXPORT_COLUMNS: tuple[str, ...] = (
    "report_id",
    "township",
    "classification",
    "reporter_name",
    "contact_phone",
    "address",
    "damage_description",
    "status",
    "created_at",
)

#: 可回溯到个人的字段，公开视图中必须整体剥离
PERSONAL_FIELDS: tuple[str, ...] = ("reporter_name", "contact_phone", "address")

_ADDRESS_DETAIL_RE = re.compile(r"\d+\s*(?:号|栋|幢|单元|室|楼)")


@dataclass(frozen=True, slots=True)
class ViewProfile:
    """一个角色在灾情报告上的完整视图策略。"""

    code: str
    #: 可见的最高密级
    clearance: str
    #: 个人字段处理方式：full 明文 / mask 脱敏 / strip 剥离
    pii_mode: str


#: 指挥员：全部密级、联系人与住址原文
COMMANDER = ViewProfile("commander", "restricted", "full")
#: 跨部门协作：最高 internal 密级，个人字段保留脱敏副本
COLLABORATOR = ViewProfile("collaborator", "internal", "mask")
#: 公开汇总：仅 public 密级，个人字段整体剥离
PUBLIC = ViewProfile("public", "public", "strip")


def profile_for(principal: Principal) -> ViewProfile:
    """根据账号当前权限实时解析视图；权限变化在下一次请求即生效。"""
    if principal.can("disaster.read.restricted"):
        return COMMANDER
    if principal.can("disaster.read.internal"):
        return COLLABORATOR
    if principal.can("disaster.read"):
        return PUBLIC
    raise PermissionDeniedError("缺少权限：disaster.read")


def can_see_classification(profile: ViewProfile, classification: str) -> bool:
    return CLASSIFICATION_RANK[classification] <= CLASSIFICATION_RANK[profile.clearance]


def mask_name(value: str) -> str:
    if len(value) <= 1:
        return "*"
    return value[0] + "*" * (len(value) - 1)


def mask_address(value: str) -> str:
    """保留乡镇、村组等定位粒度，隐去门牌号、楼栋等可回溯细节。"""
    return _ADDRESS_DETAIL_RE.sub("***", value)


def project_report(report: dict[str, Any], profile: ViewProfile) -> dict[str, Any]:
    """按视图投影单条报告：密级过滤由调用方负责，这里只处理字段。"""
    result = {
        "id": report["id"],
        "township": report["township"],
        "classification": report["classification"],
        "status": report["status"],
        "created_at": report["created_at"],
    }
    if profile.pii_mode == "full":
        result["reporter_name"] = report["reporter_name"]
        result["contact_phone"] = report["contact_phone"]
        result["address"] = report["address"]
        result["damage_description"] = report["damage_description"]
    elif profile.pii_mode == "mask":
        result["reporter_name"] = mask_name(report["reporter_name"])
        result["contact_phone"] = mask_phone(report["contact_phone"])
        result["address"] = mask_address(report["address"])
        # 受损描述为自由文本，可能内嵌电话、身份证号，统一清洗
        result["damage_description"] = sanitize_text(report["damage_description"])
    else:
        # 公开汇总不返回任何可回溯到个人的字段，仅保留灾情概况
        result["damage_description"] = sanitize_text(report["damage_description"])
    return result


def to_export_row(projected: dict[str, Any]) -> dict[str, str]:
    """投影后的报告转为导出行；固定列始终齐全，剥离视图以空值占位。"""
    return {
        "report_id": str(projected["id"]),
        "township": projected["township"],
        "classification": projected["classification"],
        "reporter_name": projected.get("reporter_name") or "",
        "contact_phone": projected.get("contact_phone") or "",
        "address": projected.get("address") or "",
        "damage_description": projected["damage_description"],
        "status": projected["status"],
        "created_at": projected["created_at"],
    }
