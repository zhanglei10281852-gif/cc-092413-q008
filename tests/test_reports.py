from __future__ import annotations

import hashlib

import pytest

REPORTS = [
    {
        "township": "幸福镇",
        "contact_name": "张小明",
        "contact_phone": "13812345678",
        "address": "幸福镇团结村三组12号",
        "damage_description": "房屋墙体开裂，住户电话13812345678",
        "damage_level": "严重",
        "classification": "general",
    },
    {
        "township": "平安乡",
        "contact_name": "李芳",
        "contact_phone": "13998765432",
        "address": "平安乡建设路15号",
        "damage_description": "两层砖房倒塌一间",
        "damage_level": "特别严重",
        "classification": "sensitive",
    },
    {
        "township": "幸福镇",
        "contact_name": "王强",
        "contact_phone": "13711112222",
        "address": "幸福镇民主街8号",
        "damage_description": "人员被困待救援",
        "damage_level": "特别严重",
        "classification": "critical",
    },
]

MASKED_EXPORT_HEADER = "报告编号,乡镇,受损程度,密级,联系人,联系电话,住址,受损描述,关联事件,状态,上报时间"


def create_user(client, admin, username, role_codes):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": username, "password": "Report!23456", "display_name": username, "role_codes": role_codes},
    )
    assert response.status_code == 201, response.text
    login = client.post("/api/auth/login", json={"username": username, "password": "Report!23456", "client_label": "tests"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}


@pytest.fixture()
def seeded(client, admin):
    ids = []
    for payload in REPORTS:
        created = client.post("/api/reports", json=payload, headers=admin["headers"])
        assert created.status_code == 201, created.text
        ids.append(created.json()["id"])
    return {
        "ids": ids,
        "commander": create_user(client, admin, "cmd.one", ["commander"]),
        "collaborator": create_user(client, admin, "colab.one", ["collaborator"]),
        "liaison": create_user(client, admin, "public.one", ["public-liaison"]),
    }


def test_detail_differs_by_role(client, seeded):
    sensitive_id = seeded["ids"][1]

    full = client.get(f"/api/reports/{sensitive_id}", headers=seeded["commander"])
    assert full.status_code == 200
    assert full.json()["contact_phone"] == "13998765432"
    assert full.json()["address"] == "平安乡建设路15号"
    assert full.json()["contact_name"] == "李芳"

    masked = client.get(f"/api/reports/{sensitive_id}", headers=seeded["collaborator"])
    assert masked.status_code == 200
    body = masked.json()
    assert body["contact_phone"] == "139****5432"
    assert body["contact_name"] == "李*"
    assert body["address"] == "平安乡***"
    assert body["damage_description"] == "两层砖房倒塌一间"

    denied = client.get(f"/api/reports/{sensitive_id}", headers=seeded["liaison"])
    assert denied.status_code == 403
    error = denied.json()["error"]
    assert error["context"]["reason_code"] == "classification_exceeded"
    assert error["context"]["report_classification"] == "sensitive"
    assert "授权上限" in error["message"]


def test_detail_masks_free_text_and_denies_critical(client, seeded):
    general_id = seeded["ids"][0]
    masked = client.get(f"/api/reports/{general_id}", headers=seeded["collaborator"])
    assert masked.status_code == 200
    assert "13812345678" not in str(masked.json())
    assert "138****5678" in masked.json()["damage_description"]

    critical_id = seeded["ids"][2]
    denied = client.get(f"/api/reports/{critical_id}", headers=seeded["collaborator"])
    assert denied.status_code == 403
    assert denied.json()["error"]["context"]["granted_max_classification"] == "sensitive"

    full = client.get(f"/api/reports/{critical_id}", headers=seeded["commander"])
    assert full.status_code == 200
    assert full.json()["contact_phone"] == "13711112222"


def test_list_differs_by_role(client, seeded):
    masked = client.get("/api/reports", headers=seeded["collaborator"])
    assert masked.status_code == 200
    rows = masked.json()["data"]
    assert masked.json()["total"] == 2
    assert {row["classification"] for row in rows} == {"general", "sensitive"}
    assert all("****" in row["contact_phone"] for row in rows)
    assert all(row["address"].endswith("***") for row in rows)

    public = client.get("/api/reports", headers=seeded["liaison"])
    assert public.status_code == 200
    rows = public.json()["data"]
    assert public.json()["total"] == 1
    assert rows[0]["classification"] == "general"
    assert rows[0]["township"] == "幸福镇"
    for field in ("contact_name", "contact_phone", "address", "damage_description"):
        assert field not in rows[0]

    full = client.get("/api/reports", headers=seeded["commander"])
    assert full.json()["total"] == 3


def test_export_fixed_columns_filter_reasons_and_token_revocation(client, seeded):
    created = client.post("/api/reports/exports", json={}, headers=seeded["collaborator"])
    assert created.status_code == 201, created.text
    payload = created.json()
    summary = payload["export"]
    assert summary["field_tier"] == "masked"
    assert summary["included_count"] == 2
    assert summary["columns"] == [
        "report_no", "township", "damage_level", "classification", "contact_name",
        "contact_phone", "address", "damage_description", "event_id", "status", "created_at",
    ]
    assert len(summary["excluded"]) == 1
    assert summary["excluded"][0]["classification"] == "critical"
    assert "超出当前角色授权上限" in summary["excluded"][0]["reason"]

    export_id = summary["export_id"]
    token = payload["download_token"]
    download = client.get(f"/api/reports/exports/{export_id}/download?token={token}")
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() == summary["content_digest"]
    text = download.content.decode("utf-8")
    assert text.splitlines()[0] == MASKED_EXPORT_HEADER
    assert "139****5432" in text and "13998765432" not in text
    assert "平安乡***" in text and "建设路15号" not in text
    assert "13711112222" not in text

    invalid = client.get(f"/api/reports/exports/{export_id}/download?token=not-the-token")
    assert invalid.status_code == 403
    assert invalid.json()["error"]["context"]["reason_code"] == "token_invalid"

    revoked = client.post(
        f"/api/reports/exports/{export_id}/revoke",
        json={"reason": "副本已线下回收"},
        headers=seeded["collaborator"],
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["token_status"] == "revoked"
    after = client.get(f"/api/reports/exports/{export_id}/download?token={token}")
    assert after.status_code == 403
    assert after.json()["error"]["context"]["reason_code"] == "token_revoked"


def test_export_commander_full_and_liaison_denied(client, seeded):
    full = client.post("/api/reports/exports", json={}, headers=seeded["commander"])
    assert full.status_code == 201
    summary = full.json()["export"]
    assert summary["included_count"] == 3
    assert summary["excluded"] == []

    denied = client.post("/api/reports/exports", json={}, headers=seeded["liaison"])
    assert denied.status_code == 403
    assert "reports.export" in denied.json()["error"]["message"]

    filtered = client.post("/api/reports/exports", json={"township": "幸福镇"}, headers=seeded["commander"])
    assert filtered.status_code == 201
    assert filtered.json()["export"]["filters"] == {"township": "幸福镇"}
    assert filtered.json()["export"]["included_count"] == 2


def test_policy_change_immediate_and_export_summary_immutable(client, admin, seeded):
    sensitive_id = seeded["ids"][1]
    before = client.get(f"/api/reports/{sensitive_id}", headers=seeded["collaborator"])
    assert before.status_code == 200

    export = client.post("/api/reports/exports", json={}, headers=seeded["collaborator"]).json()["export"]
    assert export["included_count"] == 2

    updated = client.put(
        "/api/reports/policies/collaborator",
        json={"max_classification": "general", "field_tier": "public"},
        headers=admin["headers"],
    )
    assert updated.status_code == 200, updated.text

    after = client.get(f"/api/reports/{sensitive_id}", headers=seeded["collaborator"])
    assert after.status_code == 403
    assert after.json()["error"]["context"]["granted_max_classification"] == "general"
    listing = client.get("/api/reports", headers=seeded["collaborator"])
    assert listing.json()["total"] == 1
    assert "contact_phone" not in listing.json()["data"][0]

    summary = client.get(f"/api/reports/exports/{export['export_id']}", headers=admin["headers"])
    assert summary.status_code == 200
    assert summary.json()["content_digest"] == export["content_digest"]
    assert summary.json()["included_count"] == 2
    assert summary.json()["field_tier"] == "masked"
    assert summary.json()["max_classification"] == "sensitive"


def test_policy_management_requires_permission(client, seeded):
    denied = client.put(
        "/api/reports/policies/collaborator",
        json={"max_classification": "critical", "field_tier": "full"},
        headers=seeded["collaborator"],
    )
    assert denied.status_code == 403
    listed = client.get("/api/reports/policies", headers=seeded["collaborator"])
    assert listed.status_code == 403


def test_role_without_grant_gets_explicit_denial(client, admin):
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "report.reader", "name": "报告只读", "permission_codes": ["reports.read"]},
    )
    assert role.status_code == 201
    headers = create_user(client, admin, "nogrant.one", ["report.reader"])
    response = client.get("/api/reports", headers=headers)
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["context"]["reason_code"] == "grant_not_configured"
    assert "授权策略" in error["message"]


def test_unauthenticated_rejected(client):
    assert client.get("/api/reports").status_code == 401
    assert client.post("/api/reports/exports", json={}).status_code == 401
