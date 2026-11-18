# 云讯短信中心

多用户短信接收 API + 自适应后台管理系统，Go 编写，**零第三方依赖、单二进制部署**。

设备端把收到的短信通过 HTTP 上报到接口，服务端用该用户的 Token 派生密钥（AES-256-GCM）加密后落盘；后台以短信列表框展示（点击条目看原文），支持设备区分、搜索、清空与删除。Token 与登录凭证（password_hash + salt）都不明文落盘，只存主密钥加密后的密文（Token 另存 SHA-256 哈希用于鉴权查找）。数据主密钥由编译进二进制的基值加 `config.ini` 可选追加串派生，只拿到 `data` 目录无法解密 Token，也无法靠改 `meta.json` 伪造登录。

## 密钥说明（重要，先读这里）

本项目有两把独立的密钥，不要混淆：

| 密钥 | 默认值 | 配置位置 | 作用 |
| --- | --- | --- | --- |
| 注册授权码密钥 | 基值 `sdwl88` | 内置常量 `DefaultRegisterAuthSecret`（`internal/config.go`），可**拼接** `config.ini [auth] secret` | 实际密钥 = `sdwl88` + ini 追加串（留空仅用基值），只用于注册授权码 `md5(用户名+密码+密钥)` 校验，与数据加密无关 |
| 数据主密钥 `appKey` | 基值 `sdwl88` | `internal/crypto.go` 的 `appKeyBase`，**可拼接** `config.ini [security] appKey` | `sha256(appKeyBase + ini追加串)`，用于 Token、登录凭证、用户名/邮箱/设备字段与短信发送方号码的加解密及 HMAC 索引 |

数据主密钥的派生方式：

- `config.ini` 未配置或留空 `[security] appKey`：实际密钥 = `sha256("sdwl88")`。
- 配置了 `appKey = xyz`：实际密钥 = `sha256("sdwl88xyz")`，即**追加串拼接在内置基值之后**，不是替换基值。

> 提醒一：基值编译在二进制里、公开仓库可见，追加串才是保密部分。**改动基值、追加串或清空追加串，都会导致旧 `data` 目录的数据无法解密**，请谨慎并保持部署配置稳定。
>
> 提醒二：注册授权码密钥同样为「基值 + ini 追加串」拼接，留空追加串即 `sdwl88`。改动基值或追加串会使旧注册链接失效，但不影响已注册账号登录。同步位置：`internal/config.go` 常量与本文档的注册示例。

## 功能

- 多用户注册 / 登录，注册需授权码 `md5(账号+密码+内置密钥)` 校验；注册后自动生成唯一 Token；**用户名不可修改**，可自行修改密码
- 邮箱验证码找回密码：仅当 `config.ini` 配置了发信邮箱才启用，未配置时接口返回 `MAIL_NOT_CONFIGURED`，前端自动隐藏找回入口
- 登录失败后强制图形验证码，同一 IP 连续失败 N 次锁定该 IP（不锁账号，换 IP 仍可登录）
- 设备 ID 全局唯一，设备归属校验，越权访问返回“设备不存在”
- 设备心跳：仅需 `token` + `id`，20 秒内有请求即在线；短信上报也自动视为活跃
- 短信上报接口：明文仅在内存中，落盘前加密；自动解析「号码 / 正文 / SIM / SubId / 时间」多行格式为结构化字段，非标准格式回退为纯文本
- 后台：设备会话列表（在线绿点 / 最后活跃高亮）+ 短信**列表框**视图（发件人、正文、SIM、SubId、时间，点击条目展开原始报文），PC 双栏 / 手机单栏自适应，3 秒自动刷新
- **独立登录页**：登录 / 注册 / 找回密码在单独页面 `login.html`，登录成功后跳转到后台页 `index.html`
- **前端接口整包加密**：除设备端短信上报/心跳外的所有接口（含登录/注册/验证码/找回密码）请求与响应都是 `{"payload":"<密文>"}` 信封，账号密码不再明文传输；认证阶段密钥由后端注入的 `client_key` 派生，后台阶段再叠加 `dx_session`，每次请求 JS 都不同
- 安全：Token 鉴权、会话 Cookie、PBKDF2 密码哈希（同样加密落盘）、图形验证码、按 IP 锁定（不锁账号）、多层限流、CSRF 防护、请求体限制、安全响应头；找回密码统一响应防邮箱枚举，邮箱查找走 HMAC 索引，内部错误不外泄
- 持久化：`data/meta.json`（用户/设备；Token、登录凭证、用户名、邮箱、设备 ID、设备名称均只存内置密钥密文 + 不可逆 HMAC 索引，无明文）+ `data/messages/<设备ID哈希>.jsonl`（密文短信，发送方号码 `from` 亦加密为 `sender_enc`，文件名为设备 ID 的 HMAC，同步 fsync）

## 快速开始

```bash
# 编译（Windows）
go build -o dx-server.exe .

# 运行（默认监听 :8080，数据保存在 ./data，默认启用 HTTPS）
dx-server.exe
```

浏览器打开 `https://localhost:8080/sdwl/` 进入**登录页**（`login.html`），登录 / 注册成功后跳转到后台页 `index.html`，即可创建设备并查看 Token。直接打开后台页而未登录时会自动跳回登录页。

> **HTTP 自动跳 HTTPS**：内置 HTTPS 开启时，同一个端口同时接受 HTTP 与 HTTPS——用 `http://` 访问首页会收到 301 自动跳转到同主机同路径的 `https://`，无需手动改地址，也不会再出现 `crypto.subtle.digest` 报错。

> **自签证书**：默认自动生成自签 HTTPS 证书（保存在 `data/tls_cert.pem` 与 `data/tls_key.pem`，重启复用，SAN 含 localhost、127.0.0.1 及本机所有网卡 IP，可用局域网 IP 访问）。浏览器首次访问会提示证书不受信任，选择"继续访问"即可——接受后页面即为安全上下文，前端 `crypto.subtle` 可用，登录不再报 `digest` 错误。正式环境请在 `config.ini [tls]` 填写 `cert`/`key` 指向受信任证书（Let's Encrypt 等）。

**隐藏入口**：服务只响应 `/sdwl` 及其子路径，其他一切路径（含根路径 `/`、旧 `/api/...`）一律返回 404，用于隐藏后台存在。入口前缀在后端 `internal/server.go` 的 `entryPrefix` 常量中唯一定义；前端页面用相对路径（`api/...`、`style.css`、`app.js`、`login.js`），由浏览器基于 `/sdwl/` 自动解析，JS 中无需再写前缀。设备端接口需使用带前缀的完整路径 `/sdwl/api/...`（页面「设备接口」示例中会自动生成）。

## 前端接口加密

登录页与后台页分离，且**除设备端上报外所有 HTTP 接口都整包加密**，账号、密码、验证码等不再明文出现在报文或日志里。流程如下：

1. **随机 key 由后端下发**：浏览器每次请求 `login.js` / `app.js` 时，后端生成一个随机 `client_key`，注入到 JS 顶部变量 `window.__DX_CK__`，同时写入 HttpOnly Cookie `dx_ck` 记住（响应 `Cache-Control: no-store`，**每次请求都不同**）。前端只读取注入变量，不生成、不存储，key 不出现在前端存储或请求头/请求体里。
2. **认证阶段**（登录 / 注册 / 验证码 / 找回密码 / public config / 登出）：密钥 = `SHA256("dx-auth-v1:" + client_key)`，请求体与响应都是 `{"payload":"<密文>"}` 信封——账号、密码、授权码、邮箱全在密文里。后端从 `dx_ck` Cookie 读同一 key 解密，在登录/注册响应的密文里返回 `data.dx_session`，前端存入 `sessionStorage`。
3. **后台阶段**（设备、短信查看、账号设置、Token）：密钥 = `SHA256("dx-api-v1:" + dx_session + ":" + client_key)`，后端从 `dx_session`、`dx_ck` 两个 Cookie 读取，前端用注入变量 + sessionStorage 里的 dx_session 计算；同样整包密文。缺少信封的请求被 `BAD_REQUEST` / `DECRYPT_FAILED` 拒绝。
4. **设备接口**（短信上报 `/api/sms/receive`、心跳 `/api/device/heartbeat`）保持明文——设备端接口，不参与浏览器加密，报文格式不变。

> 关于"防中间人"：服务默认内置 HTTPS（自签证书开箱即用，正式环境换受信任证书），`SecureCookie` 默认随 HTTPS 开启。密钥材料全部经 HttpOnly Cookie 与后端注入的脚本传递，不再明文出现在请求头或请求体。若改由 Nginx/Caddy 终止 TLS，设 `DX_TLS_ENABLED=false` 关闭内置 HTTPS，并显式开启 `DX_SECURE_COOKIE=true`、`DX_TRUSTED_PROXY=true`。在 TLS 之上，本层加密保证业务数据即使经过反向代理日志等旁观渠道也不以明文出现。
>
> 兼容性：不带 `dx_ck` Cookie 的请求（curl / 脚本 / 集成测试）保持明文可用，方便自动化；浏览器则全程密文。`crypto.subtle` 仅在安全上下文可用，内置 HTTPS 或 `localhost` 均满足。自签证书在局域网 IP 下同样构成安全上下文，只是浏览器会提示证书不受信任，需手动信任一次。

可选：启动时创建初始管理员（已存在则跳过）：

```powershell
$env:DX_INIT_ADMIN_USER = "admin"
$env:DX_INIT_ADMIN_PASS = "强密码"
$env:DX_INIT_ADMIN_TOKEN = "可选的固定Token"   # 留空则自动生成并打印在日志
.\dx-server.exe
```

跨平台编译见 `build.bat` / `build.sh`。

## 配置

通用配置通过环境变量设置：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DX_ADDR` | `:8080` | 监听地址 |
| `DX_DATA_DIR` | `./data` | 数据目录（需可写，建议定期备份） |
| `DX_SESSION_TTL_MIN` | `720` | 后台会话有效期（分钟） |
| `DX_API_RATE_LIMIT` | `120` | 短信上报接口每 Token 每分钟上限 |
| `DX_AUTH_RATE_LIMIT` | `20` | 登录/注册每 IP 每分钟上限 |
| `DX_MAX_BODY_BYTES` | `1048576` | 请求体最大字节数 |
| `DX_SECURE_COOKIE` | `false` | 使用 HTTPS 时设为 `true` |
| `DX_TRUSTED_PROXY` | `false` | 位于可信反向代理后时设为 `true`（启用 X-Forwarded-For） |
| `DX_CONFIG` | `config.ini` | 配置文件路径（邮箱配置、注册密钥与数据主密钥追加串，不含内置基值） |
| `DX_MAIL_DEBUG` | `false` | 仅调试：验证码打印到日志而不发信（需已配置 `[smtp]`） |
| `DX_LOGIN_MAX_FAIL` | `5` | 同一 IP 连续登录失败多少次后锁定该 IP |
| `DX_LOGIN_LOCK_MIN` | `15` | IP 锁定时长（分钟） |

发信邮箱配置**只从 `config.ini` 读取**（默认当前工作目录，可用 `DX_CONFIG` 指定路径）：

```ini
[smtp]
host = smtp.example.com
port = 587
user = your@example.com
pass = your-password
from = your@example.com
; tls 可选：starttls（默认）/ implicit / none
tls = starttls

; 数据主密钥追加串：拼接在内置基值 sdwl88 之后，留空则只用基值。
; 一旦设置，改动或清空会导致旧 data 无法解密。
[security]
appKey =

; 注册授权码密钥追加串：拼接在内置基值 sdwl88 之后，留空则只用基值。
[auth]
secret =
```

`host` 或 `from` 为空、文件不存在、或没有 `[smtp]` 节时，邮件功能禁用：找回密码与邮箱绑定接口返回 `MAIL_NOT_CONFIGURED`，后台自动隐藏相关入口。

**数据主密钥 = 内置基值 + 可选 ini 追加串**：基值 `sdwl88` 编译在二进制中；`[security] appKey` 若填写会拼接在后一起派生，为空则只用基值。旧版 `meta.json` 中的明文 `token`、`password_hash`、`salt`、`username`、`email`，以及设备的明文 `id`、`name`，首次启动会自动迁移为密文并清除明文；`data/messages/<明文设备ID>.jsonl` 会自动重命名为哈希文件名。迁移需能正常启动新版程序。

## API

以下路径均省略统一前缀 `/sdwl`，实际请求需加前缀，例如 `POST /sdwl/api/sms/receive`。不带前缀访问返回 404。

统一响应格式：

```json
{ "code": "OK", "message": "success", "data": { } }
```

### 1. 短信上报（设备端，无需登录）

`POST /api/sms/receive`（JSON body）或 `GET /api/sms/receive?token=...&id=...&text=...&from=...`

```json
{
  "token": "用户唯一Token",
  "id": "phone-01",
  "text": "您的验证码是 123456",
  "from": "+8613800000000"
}
```

- `token`、`id`、`text` 必填；`from` 可选（发送方号码）；GET 方式参数需 URL 编码
- GET 示例：`curl -G http://127.0.0.1:8080/sdwl/api/sms/receive --data-urlencode "token=你的TOKEN" --data-urlencode "id=phone-01" --data-urlencode "text=测试短信"`
- 安全提示：GET 方式短信明文会出现在 URL、访问日志与代理日志中，建议优先使用 POST

设备上报的标准文本格式（自动解析，非标准文本整段作为正文）：

```text
19999999999
【测试通道】恭喜您，该发送通道测试成功，请继续添加转发规则！
SIM1_测试运营商_18888888888
SubId：0
2026-11-17 02:24:18
```

解析结果：`sender=19999999999`、`body=【测试通道】...`、`sim=SIM1`、`carrier=测试运营商`、`sim_number=18888888888`、`sub_id=0`、`sms_time=2026-11-17 02:24:18`。这些字段连同原文会**整体加密后落盘**，仍不产生明文。
- 成功返回 `{ "code": "OK", "data": { "id": "...", "received_at": "..." } }`
- 数据使用 `SHA256("dx-sms-key-v1:" + token)` 作为 AES-256-GCM 密钥加密，nonce 与密文均以 base64 存储；明文不落盘

错误码：

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `BAD_REQUEST` | 参数缺失或超长 |
| 401 | `INVALID_TOKEN` | Token 无效 |
| 404 | `DEVICE_NOT_FOUND` | 设备不存在（或不属于该 Token） |
| 429 | `RATE_LIMITED` | 请求过于频繁 |

示例：

```bash
curl -X POST http://127.0.0.1:8080/sdwl/api/sms/receive \
  -H "Content-Type: application/json" \
  -d '{"token":"你的TOKEN","id":"phone-01","text":"测试短信"}'
```

### 2. 设备心跳（设备端，无需登录）

`POST /api/device/heartbeat`（JSON body）或 `GET /api/device/heartbeat?token=...&id=...`

```json
{ "token": "用户唯一Token", "id": "phone-01" }
```

- 只需 `token` + `id`；建议设备每 10 秒请求一次
- 20 秒内有任意请求（心跳或短信上报）即判定在线，后台设备列表显示绿点并高亮最后活跃时间
- 在线状态保存在内存中，服务重启后需设备重新上报

### 3. 注册（自动生成 Token，需授权码）

`POST /api/auth/register` — `{"username":"alice","password":"secret123","auth_code":"..."}`

- `auth_code` 必须等于 `md5(用户名 + 密码 + 注册密钥)` 的 32 位十六进制结果（大小写不敏感）；注册密钥 = 内置基值 `sdwl88` + `config.ini [auth] secret` 追加串（留空则仅 `sdwl88`）。不一致返回 `INVALID_AUTH_CODE`
- 返回 `data.token`。注册后自动登录。

示例（PowerShell）：

```powershell
$secret = "sdwl88"   # 注册密钥基值；若 config.ini [auth] secret 有值，需在其后拼接
$md5 = [Security.Cryptography.MD5]::Create()
$code = -join ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes("alice" + "secret123" + $secret)) | ForEach-Object { $_.ToString("x2") })
```

### 4. 登录 / 登出 / 当前用户

- `POST /api/auth/login` — `{"username":"alice","password":"secret123"}`
  - 失败一次后必须附带验证码：`{"username":"alice","password":"...","captcha_id":"...","captcha_text":"ABC234"}`
  - 验证码通过 `GET /api/auth/captcha` 获取，返回 `{ "id": "...", "image": "data:image/png;base64,..." }`
  - 同一 IP 连续失败达到 `DX_LOGIN_MAX_FAIL` 后锁定该 IP（不锁账号），返回 `IP_LOCKED`；换 IP 仍可正常登录
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/token` — 查看自己的 Token

### 5. 设备管理（需登录）

- `GET /api/devices` — 设备列表（含短信数、最后活跃时间、在线状态）
- `POST /api/devices` — `{"id":"phone-01","name":"主手机"}`，ID 全局唯一
- `DELETE /api/devices/{id}` — 删除设备及其短信

### 6. 短信查看（需登录）

- `GET /api/devices/{id}/messages?page=1&size=20` — 按时间倒序分页，返回解密后的结构化短信：`sender`、`body`、`raw`、`sim`、`carrier`、`sim_number`、`sub_id`、`sms_time`、`created_at`（`size` 最大 100）
- `DELETE /api/devices/{id}/messages` — 清空短信

### 7. 账号设置与找回密码

- `POST /api/account/password` — `{"old_password":"...","new_password":"..."}`（需登录），成功后仅保留当前会话。**用户名注册后不可修改**
- `POST /api/account/email/code` — `{"email":"a@b.com"}` 发送绑定验证码，60 秒限一次（需登录）
- `POST /api/account/email` — `{"email":"a@b.com","code":"123456"}` 完成绑定（需登录）
- `POST /api/auth/forgot-password` — `{"email":"a@b.com"}` 发送找回验证码；邮箱未绑定任何用户时返回 404 `USER_NOT_FOUND`，前端提示"该邮箱未绑定任何用户"；发信失败返回 500 `MAIL_FAILED`
- `POST /api/auth/reset-password` — `{"email":"a@b.com","code":"123456","new_password":"..."}` 重置密码并使该用户所有会话失效

邮箱验证码 5 分钟有效，最多尝试 5 次，60 秒限发一次。**以上邮箱相关接口仅在 `config.ini` 配置了 `[smtp]` 后可用**，否则返回 `MAIL_NOT_CONFIGURED`。本地调试可在已配置 `[smtp]` 的前提下设置 `DX_MAIL_DEBUG=true`，验证码只打印到日志不发信。

## 安全说明

- **传输**：内置 HTTP，生产环境请在前面部署 Nginx/Caddy 并启用 HTTPS，同时设置 `DX_SECURE_COOKIE=true`、`DX_TRUSTED_PROXY=true`。
- **鉴权**：设备上报用高熵 Token（32 字节随机数，URL-safe base64）；后台用 HttpOnly + SameSite=Lax 会话 Cookie，服务端保存会话，退出即失效。
- **加密**：短信密文用用户 Token 派生的 AES-256-GCM 密钥加密，不同用户密钥不同；`meta.json` 不存明文 Token，只存 SHA-256 哈希（鉴权查找）+ 主密钥密文（后台解密短信用）。**用户名、邮箱、设备 ID、设备名称**同样以主密钥加密落盘（`*_enc`），另存 HMAC 索引（`*_hash`）用于查找与消息文件命名，**无明文**。短信**发送方号码 `from`** 也加密为 `sender_enc`（绑定设备 ID），消息文件名用设备 ID 的 HMAC。主密钥 = 二进制内基值 `sdwl88` + `config.ini [security] appKey` 追加串（拼接）派生；基值不落盘、追加串可选写在配置里。只拿到 `data` 目录但拿不到配置追加串时无法解密 Token 或短信。
- **密码**：PBKDF2-SHA256（210000 次迭代）+ 每用户随机盐，常量时间比较；哈希与盐本身也用内置密钥做 AES-256-GCM 加密，并以「用户 ID + 用户名」为附加认证数据，落盘只有 `cred_enc`。因此改 `meta.json` 里的字段、或把别人的 `cred_enc` 整段复制过来都无法伪造登录，密文被改动则直接认证失败。
- **密钥边界**：内置基值无法防住能反编译/拿到二进制源码的人；真正保密的是 `config.ini [security] appKey` 追加串，勿与 `data` 目录一起备份或提交。防护目标是“服务器数据文件泄露但配置与程序未泄露”的场景；若追加串为空，仅靠公开基值加密，拿到 `data` 目录者无法直接解密但可结合源码分析。
- **登录防护**：失败一次后强制一次性图形验证码（自绘点阵 PNG，无第三方依赖）；同一 IP 连续失败达到阈值后锁定该 IP 15 分钟（锁 IP 不锁账号，避免有人恶意锁死他人账号；反代后须设 `DX_TRUSTED_PROXY=true` 才会按 `X-Forwarded-For` 区分 IP）；验证码与邮件验证码均常量时间比较。
- **邮箱验证**：绑定邮箱与找回密码均需邮箱验证码；验证码 5 分钟有效、最多 5 次尝试、60 秒发送间隔；找回接口对未绑定邮箱返回 `USER_NOT_FOUND`（按需求不再隐藏账号是否存在）。发信配置只从 `config.ini` 读取，未配置则整个邮箱功能禁用（前端隐藏入口，接口返回 `MAIL_NOT_CONFIGURED`）。
- **设备接口**：`token` 同时用于鉴权与短信解密密钥；GET 方式虽已支持，但明文短信会留在 URL 与日志中，生产环境建议使用 POST。
- **防护**：按 IP / Token / 接口多层固定窗口限流；CSRF Origin 校验；请求体 1 MiB 限制；CSP、nosniff、frame-ancestors 等安全响应头；设备 ID 严格白名单防止路径穿越；越权统一返回“设备不存在”避免信息泄露。
- **审计**：生产环境建议记录上报日志并监控 `RATE_LIMITED`、`INVALID_TOKEN` 频次；备份时请同时保存 `data` 目录与 `config.ini` 的 `[security] appKey` 追加串（二者缺一不可解密）。改动基值、追加串或清空追加串都会导致旧数据无法解密，部署后请保持配置稳定。

## 测试

```bash
go test ./...
```

集成测试覆盖加解密往返、Token 与登录凭证不明文落盘、旧数据迁移、篡改或跨用户复制 `cred_enc` 后无法登录、数据主密钥由 ini 追加串拼接派生、注册授权码校验与 ini 覆盖、设备唯一性、设备不存在/越权、短信明文正确返回及明文不落盘、多行短信格式解析与结构化返回、修改密码（且用户名不可修改）、邮箱绑定与找回密码、图形验证码与按 IP 锁定（锁 IP 不锁账号）、设备心跳在线判定、GET 方式接口、INI 配置解析、邮件未配置时禁用、后台 API 整包密文信封往返（含明文请求被拒）、认证接口密文往返（账号密码不明文，明文请求被拒，不带 cookie 的兼容）、JS 动态注入随机 key（每次不同且与 Cookie 一致、禁止缓存）、短信接口仍明文等流程。
