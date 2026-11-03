# 轻量化零知识证明验证系统

用 Python 构造和验证 Schnorr 非交互式零知识证明。证明者在本地持有秘密整数 `x`，验证方使用可信渠道提供的公开值 `y = g^x mod p` 检查证明。项目提供 CLI、FastAPI 验证服务、单条与批量验证，以及 SQLite 审计日志和通过率统计。

## 本地运行

需要 Python 3.10 或更新版本。CLI 使用标准库，可从仓库根目录直接运行。

```powershell
python main.py demo
python main.py logs --limit 10
python main.py stats
```

`demo` 依次检查原始证明与篡改响应后的证明。`stats` 将实际验证归入 `verification`，将内置演示归入 `demo`。`acceptance_rate` 是 0 到 1 之间的小数，空组为 `null`。

```powershell
$publicValue = python main.py prove --context lesson-01
python main.py verify data/proof.json --public-value $publicValue --context lesson-01
```

`prove` 默认随机生成秘密，输出公开值并将证明写入 `data/proof.json`。已有秘密时，可用 `--prompt-secret` 在交互式终端隐藏输入。验证方应独立取得预期公开值和场景字符串。将验证命令中的 `lesson-01` 改成其他值可观察验证失败。`verify` 和 `verify-batch` 的退出码 `0` 表示全部通过，`1` 表示至少一项拒绝，`2` 表示参数、输入或存储错误。旧版的 `schnorr-ffdhe2048-sha256-v1` 证明 JSON 可直接使用。

## HTTP API

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[api]"
.\.venv\Scripts\python.exe -m uvicorn zkp_verifier.api.app:app --host 127.0.0.1 --port 8000
```

启动后访问 `http://127.0.0.1:8000/docs` 查看并试用接口。在另一终端按上一节生成证明，然后提交公开数据。

```powershell
$publicValue = python main.py prove --context lesson-01
$proof = Get-Content data/proof.json -Raw | ConvertFrom-Json
$item = @{ public_value = $publicValue; context = 'lesson-01'; proof = $proof }
$body = $item | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/verify -ContentType 'application/json' -Body $body
```

| 接口 | 用途 |
| --- | --- |
| `GET /health` | 服务进程存活检查 |
| `POST /v1/verify` | 接收 `public_value`、`context` 和 `proof` |
| `POST /v1/verify/batch` | 接收 `{"items": [...]}`，每批 1 至 32 项 |
| `GET /v1/logs?limit=20` | 查看日志，使用最后一条 `id` 作为 `before_id` 获取下一页 |
| `GET /v1/stats` | 查看验证总数、通过数、拒绝数和通过率 |

CLI 的 `verify-batch` 接收和批量 API 相同的 JSON 文件。结构合法的请求返回 `200`，每条结果的 `accepted` 表示是否通过，`verdict` 表示判定原因。输入结构错误返回 `422`，请求体超过 128 KiB 返回 `413`，审计存储不可用返回 `503`。批量输入全部通过格式检查后才开始验证，每批结果使用同一事务写入。

## 四层结构

| 层 | 实现 |
| --- | --- |
| 秘密生成 | `zkp_verifier/core/secret_gen.py` 从大整数标量范围均匀采样，计算公开值 |
| 证明构造 | `zkp_verifier/core/proof_build.py` 生成独立随机数，计算承诺与响应 |
| 公开验证 | `zkp_verifier/core/verify_logic.py` 检查群元素、响应范围及验证等式 |
| 结果输出 | `zkp_verifier/service.py` 组织验证，`audit.py` 持久化日志并聚合统计 |

`cli.py` 与 `api/` 共享验证服务。`log/verification.sqlite3` 是默认日志路径，可用环境变量 `ZKP_LOG_DB` 指定，CLI 也支持在子命令前使用 `--log-db`。日志保存运行编号、UTC 时间、来源、批内位置和判定。秘密、随机数、公开值、场景与证明本身只参与对应的本地计算或请求处理。新版数据库从空统计开始，旧项目的日志可在原本地目录查阅。

## 证明原理

项目使用 ffdhe2048 素数群参数与 SHA-256 挑战哈希。证明者用随机数 `k` 计算承诺 `t = g^k mod p`，再计算 `r = (k - c*x) mod q`。验证方用公开值、承诺与场景重算挑战 `c`，检查 `g^r * y^c mod p == t`。证明的陈述是知道指定公开值的离散对数。猜得到的小整数可能被枚举。同一场景的证明可以被重复验证，服务会逐次记录。该实现面向教学与本地实验，默认监听回环地址。部署到共享网络时，访问控制、TLS 和请求配额应由部署层提供。[Schnorr 证明 RFC 8235](https://www.rfc-editor.org/rfc/rfc8235.html#section-2) · [ffdhe2048 参数 RFC 7919](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1)

## 测试

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[api,test]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

GitHub Actions 在 Linux 和 Windows 上运行协议、CLI、API 与 SQLite 事务测试。
