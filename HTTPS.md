# HTTPS 与 HTTP 自动跳转说明

服务默认启用内置 HTTPS，解决浏览器在 HTTP 非安全上下文下无法使用 `crypto.subtle`（登录报 `Cannot read properties of undefined (reading 'digest')`）的问题。

## 一、默认行为（开箱即用）

- 启动后监听 `DX_ADDR`（默认 `:8080`），同时接受 HTTP 与 HTTPS：
  - **HTTPS 请求**：TLS 握手后交给正常服务。
  - **HTTP 请求**：同一端口返回 **301**，自动跳转到同主机同路径的 `https://`，无需手动改地址。
- 首次启动在 `data/` 下自动生成自签证书：
  - `data/tls_cert.pem`、`data/tls_key.pem`（ECDSA P-256，有效期 10 年）
  - SAN 含 `localhost`、`127.0.0.1`、`::1` 及本机所有网卡 IP，因此局域网 IP 访问也构成安全上下文。
  - 证书仅生成一次，重启复用。
- `SecureCookie` 默认随 HTTPS 开启。

浏览器访问 `https://localhost:8080/sdwl/`（或直接输 `http://` 会自动跳转）。

## 二、关于浏览器"证书不受信任"提示

自签证书不在浏览器信任根列表里，首次访问会提示"连接不是私密连接"，日志里可能出现：

```
http: TLS handshake error from ...: remote error: tls: unknown certificate
```

含义是客户端不信任证书而在握手阶段断开，**服务本身正常**。处理方式任选：

1. 在警告页点 **高级 → 继续前往**，信任一次即可（之后登录正常）。
2. 将 `data/tls_cert.pem` 导入系统/浏览器受信任根证书，永久消除警告。
3. 正式环境改用受信任证书（见下节）。
4. 命令行测试用 `curl -k` 忽略校验。

## 三、使用正式证书

在 `config.ini` 配置（或用环境变量 `DX_TLS_CERT` / `DX_TLS_KEY`，环境变量优先）：

```ini
[tls]
enabled = true
cert = /path/to/fullchain.pem
key  = /path/to/privkey.pem
```

两项必须同时填写。填了正式证书后不再使用自签证书，浏览器正常信任、无警告。

## 四、由反向代理终止 TLS

若由 Nginx/Caddy 终止 TLS、后端只跑 HTTP，关闭内置 HTTPS：

```ini
[tls]
enabled = false
```

关闭后服务仅监听 HTTP，不再做 301 跳转（跳转交给反代）。此时如需 Secure Cookie，显式设置环境变量 `DX_SECURE_COOKIE=true`；若信任 `X-Forwarded-For` 取客户端 IP，设 `DX_TRUSTED_PROXY=true`。

环境变量优先级高于 `config.ini`：

| 变量 | 说明 | 默认 |
|---|---|---|
| `DX_TLS_ENABLED` | 是否启用内置 HTTPS | `true` |
| `DX_TLS_CERT` | 自定义证书路径 | 空（自签） |
| `DX_TLS_KEY` | 自定义私钥路径 | 空（自签） |
| `DX_SECURE_COOKIE` | Cookie 是否带 Secure | 随 HTTPS 开启 |

## 五、设备端接口

短信上报 `/sdwl/api/sms/receive` 与心跳 `/sdwl/api/device/heartbeat` 保持原有明文报文格式不变，仅传输层变为 HTTPS；设备端需用 `https://` 访问，若用自签证书，设备端需信任该证书或跳过校验。

## 六、验证

- `go test ./...` 覆盖自签证书生成/复用、SAN、HTTP→HTTPS 跳转与协议分流。
- Linux 产物：`dx-server-linux-amd64`、`dx-server-linux-arm64`（静态编译，无 libc 依赖）。
