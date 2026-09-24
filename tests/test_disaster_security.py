from __future__ import annotations

import pytest


def _login(client, username: str, password: str = "Role!23456x") -> dict:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _make_user(client, admin, username: str, display: str, roles: list[str]) -> None:
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": username, "password": "Role!23456x", "display_name": display, "role_codes": roles},
    )
    assert created.status_code == 201, created.text


@pytest.fixture()
def roles_users(client, admin):
    """指挥员、协作员、公开分析员三个分级角色账号。"""
    _make_user(client, admin, "commander.z", "指挥员张", ["commander"])
    _make_user(client, admin, "partner.li", "协作员李", ["collaborator"])
    _make_user(client, admin, "analyst.wang", "分析员王", ["public_analyst"])
    _make_user(client, admin, "auditor.chen", "审计员陈", ["auditor"])
    return {
        "commander": _login(client, "commander.z"),
        "collaborator": _login(client, "partner.li"),
        "public": _login(client, "analyst.wang"),
        "outsider": _login(client, "auditor.chen"),
    }


@pytest.fixture()
def reports(client, roles_users):
    """同一乡镇三条报告，密级各一，公开报告描述中内嵌手机号。"""
    payloads = [
        {
            "township": "龙泉镇",
            "reporter_name": "周建国",
            "contact_phone": "13912345678",
            "address": "龙泉镇青山村3组12号2栋3单元",
            "damage_description": "土木结构房屋倒塌两间，联系人手机13912345678保持畅通",
            "classification": "public",
        },
        {
            "township": "龙泉镇",
            "reporter_name": "吴秀兰",
            "contact_phone": "13787654321",
            "address": "龙泉镇和平街88号",
            "damage_description": "围墙开裂约3米，需现场排查",
            "classification": "internal",
        },
        {
            "township": "龙泉镇",
            "reporter_name": "赵卫东",
            "contact_phone": "13500001111",
            "address": "龙泉镇救灾物资仓库",
            "damage_description": "仓库进水，物资受潮",
            "classification": "restricted",
        },
    ]
    ids = []
    for payload in payloads:
        response = client.post("/api/disaster/reports", headers=roles_users["commander"], json=payload)
        assert response.status_code == 201, response.text
        ids.append(response.json()["id"])
    return {"public": ids[0], "internal": ids[1], "restricted": ids[2]}


EXPECTED_COLUMNS = [
    "report_id",
    "township",
    "classification",
    "reporter_name",
    "contact_phone",
    "address",
    "damage_description",
    "status",
    "created_at",
]


# ---------- 详情：同一报告三种角色 ----------

def test_detail_commander_sees_full_plaintext(client, roles_users, reports):
    response = client.get(f"/api/disaster/reports/{reports['restricted']}", headers=roles_users["commander"])
    assert response.status_code == 200
    body = response.json()
    assert body["reporter_name"] == "赵卫东"
    assert body["contact_phone"] == "13500001111"
    assert body["address"] == "龙泉镇救灾物资仓库"
    assert body["damage_description"] == "仓库进水，物资受潮"


def test_detail_collaborator_gets_masked_copy_and_blocked_on_restricted(client, roles_users, reports):
    internal = client.get(f"/api/disaster/reports/{reports['internal']}", headers=roles_users["collaborator"])
    assert internal.status_code == 200
    body = internal.json()
    assert body["reporter_name"] == "吴**"
    assert body["contact_phone"] == "137****4321"
    assert body["address"] == "龙泉镇和平街***"

    public = client.get(f"/api/disaster/reports/{reports['public']}", headers=roles_users["collaborator"])
    assert public.status_code == 200
    # 自由文本内嵌手机号同样被清洗，不留可回溯号码
    assert "13912345678" not in public.json()["damage_description"]
    assert "139****5678" in public.json()["damage_description"]

    denied = client.get(f"/api/disaster/reports/{reports['restricted']}", headers=roles_users["collaborator"])
    assert denied.status_code == 403
    error = denied.json()["error"]
    assert error["context"]["reason"] == "classification_above_clearance"
    assert "restricted" in error["message"] and "internal" in error["message"]


def test_detail_public_analyst_has_no_personal_fields(client, roles_users, reports):
    body = client.get(f"/api/disaster/reports/{reports['public']}", headers=roles_users["public"]).json()
    assert "reporter_name" not in body
    assert "contact_phone" not in body
    assert "address" not in body
    assert "13912345678" not in body["damage_description"]

    for level in ("internal", "restricted"):
        denied = client.get(f"/api/disaster/reports/{reports[level]}", headers=roles_users["public"])
        assert denied.status_code == 403
        assert denied.json()["error"]["context"]["reason"] == "classification_above_clearance"


def test_detail_without_disaster_permission_gets_clear_reason(client, roles_users, reports):
    denied = client.get(f"/api/disaster/reports/{reports['public']}", headers=roles_users["outsider"])
    assert denied.status_code == 403
    assert "disaster.read" in denied.json()["error"]["message"]


# ---------- 列表：过滤数量与原因 ----------

def test_list_views_filter_by_clearance_with_reasons(client, roles_users, reports):
    commander = client.get("/api/disaster/reports", headers=roles_users["commander"]).json()
    assert commander["returned"] == 3 and commander["filtered_out"] == 0

    collaborator = client.get("/api/disaster/reports", headers=roles_users["collaborator"]).json()
    assert collaborator["view"] == "collaborator"
    assert collaborator["returned"] == 2
    assert collaborator["filtered_out"] == 1
    assert collaborator["filters"] == [{"reason": "classification_above_clearance", "count": 1}]
    assert {item["id"] for item in collaborator["data"]} == {reports["public"], reports["internal"]}
    # 列表行同样脱敏
    internal_row = next(item for item in collaborator["data"] if item["id"] == reports["internal"])
    assert internal_row["contact_phone"] == "137****4321"

    public = client.get("/api/disaster/reports", headers=roles_users["public"]).json()
    assert public["returned"] == 1 and public["filtered_out"] == 2
    assert public["data"][0]["id"] == reports["public"]
    assert "contact_phone" not in public["data"][0]


# ---------- 导出：固定列、脱敏、过滤原因、令牌撤销 ----------

def _issue(client, headers, classification="restricted", township=None):
    response = client.post(
        "/api/disaster/exports",
        headers=headers,
        json={"classification": classification, "township": township},
    )
    assert response.status_code in (201, 403), response.text
    return response


def _download(client, headers, export_id, token):
    return client.get(
        f"/api/disaster/exports/{export_id}/download",
        headers={**headers, "X-Export-Token": token},
    )


def test_export_columns_are_fixed_and_rows_are_masked_per_view(client, roles_users, reports):
    issued = _issue(client, roles_users["collaborator"], classification="internal").json()
    assert issued["columns"] == EXPECTED_COLUMNS
    assert issued["row_count"] == 2
    assert issued["filtered_count"] == 1
    assert issued["filters"] == [
        {"reason": "classification_above_requested", "count": 1, "requested": "internal"}
    ]

    downloaded = _download(client, roles_users["collaborator"], issued["export_id"], issued["token"])
    assert downloaded.status_code == 200, downloaded.text
    body = downloaded.json()
    assert body["columns"] == EXPECTED_COLUMNS
    for row in body["rows"]:
        # 固定列顺序：每行键集合与顺序完全一致，不随视图增删
        assert list(row.keys()) == EXPECTED_COLUMNS
    by_classification = {row["classification"]: row for row in body["rows"]}
    assert by_classification["internal"]["reporter_name"] == "吴**"
    assert by_classification["internal"]["contact_phone"] == "137****4321"
    assert by_classification["internal"]["address"] == "龙泉镇和平街***"
    assert by_classification["public"]["reporter_name"] == "周**"


def test_export_public_view_keeps_columns_but_empties_personal_cells(client, roles_users, reports):
    issued = _issue(client, roles_users["public"], classification="public").json()
    assert issued["row_count"] == 1
    body = _download(client, roles_users["public"], issued["export_id"], issued["token"]).json()
    assert len(body["rows"]) == 1
    row = body["rows"][0]
    assert list(row.keys()) == EXPECTED_COLUMNS  # 列仍固定，个人列以空值占位
    assert row["reporter_name"] == ""
    assert row["contact_phone"] == ""
    assert row["address"] == ""
    assert "13912345678" not in row["damage_description"]


def test_export_records_filter_reason_for_requested_cap(client, roles_users, reports):
    # 指挥员只请求 internal：restricted 行因高于请求密级被过滤并记录原因
    issued = _issue(client, roles_users["commander"], classification="internal").json()
    assert issued["row_count"] == 2
    reasons = {item["reason"]: item["count"] for item in issued["filters"]}
    assert reasons == {"classification_above_requested": 1}


def test_export_requesting_above_clearance_is_denied_with_reason(client, roles_users, reports):
    denied = _issue(client, roles_users["public"], classification="restricted")
    assert denied.status_code == 403
    assert denied.json()["error"]["context"]["reason"] == "classification_above_clearance"


def test_export_token_required_and_revocation_blocks_download(client, roles_users, reports):
    issued = _issue(client, roles_users["commander"]).json()
    path = f"/api/disaster/exports/{issued['export_id']}/download"

    missing = client.get(path, headers=roles_users["commander"])
    assert missing.status_code == 422  # 缺少 X-Export-Token

    wrong = client.get(path, headers={**roles_users["commander"], "X-Export-Token": "x" * 40})
    assert wrong.status_code == 403
    assert wrong.json()["error"]["context"]["reason"] == "export_token_unknown"

    # 他人令牌不可用
    foreign = _download(client, roles_users["collaborator"], issued["export_id"], issued["token"])
    assert foreign.status_code == 403
    assert foreign.json()["error"]["context"]["reason"] == "export_not_owner"

    revoked = client.post(
        f"/api/disaster/exports/{issued['export_id']}/revoke?reason=误发，立即收回",
        headers=roles_users["commander"],
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    again = _download(client, roles_users["commander"], issued["export_id"], issued["token"])
    assert again.status_code == 403
    assert again.json()["error"]["context"]["reason"] == "export_token_revoked"


def test_export_requires_disaster_export_permission(client, roles_users, reports):
    response = _issue(client, roles_users["outsider"], classification="public")
    assert response.status_code == 403
    assert "disaster.export" in response.json()["error"]["message"]


# ---------- 授权变更：立即生效且不改写旧审计摘要 ----------

def test_permission_change_takes_effect_immediately_without_touching_summaries(client, admin, roles_users, reports):
    issued = _issue(client, roles_users["collaborator"], classification="internal").json()
    summary_before = issued["summary_sha256"]
    export_id = issued["export_id"]

    # 收权：把协作员降为公开分析员
    user_id = next(
        row["id"]
        for row in client.get("/api/users", headers=admin["headers"]).json()["data"]
        if row["username"] == "partner.li"
    )
    replaced = client.put(
        f"/api/users/{user_id}/roles",
        headers=admin["headers"],
        json={"role_codes": ["public_analyst"]},
    )
    assert replaced.status_code == 200, replaced.text

    # 新请求立即受新权限约束：internal 详情现在被拒绝
    denied = client.get(f"/api/disaster/reports/{reports['internal']}", headers=roles_users["collaborator"])
    assert denied.status_code == 403
    assert denied.json()["error"]["context"]["reason"] == "classification_above_clearance"

    # 含 internal 行的旧导出快照不能再凭旧令牌下载：当前密级重新校验拦截
    blocked = _download(client, roles_users["collaborator"], export_id, issued["token"])
    assert blocked.status_code == 403
    assert blocked.json()["error"]["context"]["reason"] == "export_clearance_reduced"

    # 已固化的审计摘要与行计数没有被授权变化或撤权操作篡改
    listing = client.get("/api/disaster/exports", headers=admin["headers"])
    assert listing.status_code == 200
    record = next(item for item in listing.json()["data"] if item["export_id"] == export_id)
    assert record["summary_sha256"] == summary_before
    assert record["row_count"] == 2

    # 审计流水：签发成功与各类拒绝均留痕，拒绝都带明确原因
    events = client.get("/api/audit?resource_type=disaster_export", headers=admin["headers"]).json()
    actions = {(item["action"], item["outcome"]) for item in events["data"]}
    assert ("disaster.export.issue", "success") in actions
    denied_events = [item for item in events["data"] if item["outcome"] == "denied"]
    assert denied_events
    assert all('"reason"' in item["metadata_json"] for item in denied_events)
