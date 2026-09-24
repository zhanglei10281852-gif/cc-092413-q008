# 地震灾害科学协同服务

这是一个面向地震台网与应急指挥中心的模块化后端，集中管理地震事件、台站观测、震情计算、灾情协同、用户权限、会话、审计和可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 主要模块

- 震情档案：登记地震事件、震源参数和台站观测，保留计算输入摘要。
- 科学计算：提供震级、距离和烈度的确定性计算，以及可恢复后台任务。
- 灾情协同：管理灾情报告、公告、部门责任和跨部门办理状态。
- 报告分级：灾情报告密级、角色授权、按字段脱敏和带审计的批量导出。
- 身份与权限：用户、角色、细粒度权限、会话令牌、账号停用和会话撤销。
- 审计记录：关键身份操作留痕，并对口令和令牌等敏感字段做过滤。
- 后台任务：使用 SQLite 保存待执行任务，支持去重、租约、重试和完成回执。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

配置项均以 `TOWNSHIP_` 开头。可以复制 `.env.example` 后按需设置，默认数据库位于 `./data/township.db`。

## 初始化与检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动服务

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

首次部署可创建唯一的初始管理员：

```bash
curl -sS -X POST http://127.0.0.1:8432/api/auth/bootstrap   -H 'Content-Type: application/json'   -d '{"username":"admin","password":"Admin!23456","client_label":"initial-setup"}'
```

之后通过 `/api/auth/login` 获取会话令牌，并在管理接口请求头中使用 `Authorization: Bearer <token>`。

## 测试

```bash
python -m pytest
```

测试覆盖身份初始化、登录、用户与角色维护、权限计算、账号停用后的会话撤销、审计脱敏、事件与台站观测、烈度计算、后台任务去重与领取，以及数据库时间格式。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

该命令在进程内启动应用并检查服务根路径与健康接口，适合部署前快速确认路由和数据库初始化是否正常。

## 目录结构

```text
app/
  api/             用户、角色、审计、认证和系统接口
  core/            时钟、安全、异常和分页能力
  repositories/    SQLite 查询与持久化读取
  reports/         灾情报告密级、字段脱敏与导出审计
  routers/         灾情、事件、公告、部门和信访业务接口
  seismic/         地震事件、台站观测和科学计算服务
  schemas/         管理接口输入模型
  services/        身份、审计和后台任务领域服务
  cli.py           初始化、检查和冒烟入口
  database.py      SQLite 连接、事务、表结构与基础权限
tests/             核心、管理接口和原有业务回归测试
tools/             本地维护脚本
```

## 灾情报告分级与导出

灾情报告带有密级（`general` 一般 / `sensitive` 敏感 / `critical` 重大），每个角色在 `report_role_grants` 中配置「密级上限 + 字段可见级别」，每次请求实时读取，授权调整立即生效：

- `full` 完整信息：指挥员视角，所有字段原样返回。
- `masked` 脱敏副本：联系人姓名保留首尾、电话中间四位隐藏、住址截断到乡镇一级、描述文本中的电话与证件号自动打码。
- `public` 公开汇总：只保留编号、乡镇、受损程度等不可回溯到个人的字段。

预置角色：`commander`（critical/full）、`collaborator`（sensitive/masked）、`public-liaison`（general/public）。管理员可通过 `PUT /api/reports/policies/{role_code}` 调整授权（需 `reports.policy` 权限），变更留痕于审计事件。

批量导出（`POST /api/reports/exports`，需 `reports.export`）按当前角色的字段级别生成固定列顺序的 CSV，超出密级上限的报告逐条记录过滤原因；导出摘要（列清单、纳入数量、过滤明细、内容 SHA-256）落库后不可篡改，之后的授权变化不会改写已生成的摘要。下载通过一次性签发的令牌进行（默认 24 小时有效，`TOWNSHIP_EXPORT_TOKEN_TTL_HOURS` 可调），`POST /api/reports/exports/{id}/revoke` 可立即撤销；无效、已撤销或过期令牌的下载请求都会返回明确的拒绝原因并记入审计。

## 数据一致性

SQLite 连接默认启用外键、WAL、busy timeout 与同步写入策略。需要跨多张表更新的管理操作在即时事务中执行，失败会整体回滚。会话令牌只保存摘要；用户停用会撤销仍有效的会话。审计事件保存操作者、动作、资源、结果和前后状态，但不会保存明文密码或令牌。
