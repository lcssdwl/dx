# 云讯短信中心

多用户短信接收 API + 单二进制后台，内置 HTTPS，零第三方依赖。

## 本次版本

- 内置 HTTPS（自签证书开箱即用，支持正式证书），HTTP 访问自动跳转 HTTPS
- 新消息铃声与设备列表未读「新消息」红标，查看后自动消除
- 前端接口整包 AES-GCM 加密，账号密码不明文传输
- 独立登录页、设备/短信管理、心跳在线判定、多重安全防护

## 下载

- `dx-server-windows-amd64.exe` — Windows x86_64
- `dx-server-linux-amd64` — Linux x86_64
- `dx-server-linux-arm64` — Linux ARM64

静态编译，无 libc 依赖，前端资源已内嵌。首次运行默认在 `https://localhost:8080/sdwl/` 访问；自签证书浏览器提示时选「继续访问」即可。

详细配置与说明见仓库 README.md、HTTPS.md。
