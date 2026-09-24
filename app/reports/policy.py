from __future__ import annotations

import re
from typing import Any

from app.core.privacy import mask_phone, sanitize_text

# 报告密级，数值越大越敏感。
CLASSIFICATION_LEVELS = {"general": 1, "sensitive": 2, "critical": 3}
CLASSIFICATION_LABELS = {"general": "一般", "sensitive": "敏感", "critical": "重大"}

# 字段可见级别：public 公开汇总口径 / masked 脱敏副本 / full 完整信息。
FIELD_TIER_LEVELS = {"public": 1, "masked": 2, "full": 3}
FIELD_TIER_LABELS = {"public": "公开汇总", "masked": "脱敏副本", "full": "完整信息"}

DAMAGE_LEVELS = ("轻微", "一般", "严重", "特别严重")

# 所有 tier 都保留的非个人字段。
BASE_FIELDS = (
    "id",
    "report_no",
    "township",
    "damage_level",
    "classification",
    "event_id",
    "status",
    "created_at",
)
# 可回溯到个人的字段，按 tier 脱敏或剔除。
PII_FIELDS = ("contact_name", "contact_phone", "address", "damage_description")

# 批量导出的固定列顺序（键, 表头），任何角色导出的列顺序都以此为准。
_EXPORT_COLUMN_KEYS = (
    "report_no",
    "township",
    "damage_level",
    "classification",
    "contact_name",
    "contact_phone",
    "address",
    "damage_description",
    "event_id",
    "status",
    "created_at",
)
_COLUMN_LABELS = {
    "report_no": "报告编号",
    "township": "乡镇",
    "damage_level": "受损程度",
    "classification": "密级",
    "contact_name": "联系人",
    "contact_phone": "联系电话",
    "address": "住址",
    "damage_description": "受损描述",
    "event_id": "关联事件",
    "status": "状态",
    "created_at": "上报时间",
}
_PUBLIC_EXPORT_KEYS = ("report_no", "township", "damage_level", "classification", "event_id", "created_at")

EXPORT_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "full": tuple((key, _COLUMN_LABELS[key]) for key in _EXPORT_COLUMN_KEYS),
    "masked": tuple((key, _COLUMN_LABELS[key]) for key in _EXPORT_COLUMN_KEYS),
    "public": tuple((key, _COLUMN_LABELS[key]) for key in _PUBLIC_EXPORT_KEYS),
}

_TOWNSHIP_RE = re.compile(r"^.+?(?:镇|乡|民族乡|街道|苏木)")


def mask_name(value: str | None) -> str | None:
    """联系人姓名只保留首尾，中间以 * 代替。"""
    if not value:
        return value
    if len(value) == 1:
        return "*"
    if len(value) == 2:
        return value[0] + "*"
    return value[0] + "*" * (len(value) - 2) + value[-1]


def mask_address(value: str | None) -> str | None:
    """住址只保留到乡镇/街道一级，门牌细节用 * 代替。"""
    if not value:
        return value
    match = _TOWNSHIP_RE.search(value)
    if match:
        return match.group(0) + "***"
    return value[:2] + "***" if len(value) > 2 else "***"


def project_report(row: dict[str, Any], field_tier: str) -> dict[str, Any]:
    """按字段可见级别裁剪报告字段。"""
    if field_tier == "full":
        return dict(row)
    projected = {key: row.get(key) for key in BASE_FIELDS}
    if field_tier == "masked":
        projected["contact_name"] = mask_name(row.get("contact_name"))
        projected["contact_phone"] = mask_phone(row.get("contact_phone"))
        projected["address"] = mask_address(row.get("address"))
        description = row.get("damage_description")
        projected["damage_description"] = sanitize_text(description) if isinstance(description, str) else description
    return projected


def classification_label(value: str) -> str:
    return CLASSIFICATION_LABELS.get(value, value)


def field_tier_label(value: str) -> str:
    return FIELD_TIER_LABELS.get(value, value)
