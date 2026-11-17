# Relay Console

独立 sing-box 中转管理面板：固定域名入口、每条 SOCKS5 落地对应 Reality / Hysteria2 / TUIC、实时流量、二维码、批量导入、延迟检测及备用服务器同步。

## 安装

支持 Debian 12+ / Ubuntu 22.04+，amd64 / arm64。需要 root。安装程序拒绝覆盖已有配置及同名服务。

先将域名的 A 记录指向新服务器（仅 DNS），确保 TCP 80、18443 可达。执行：

```bash
curl -fsSL https://raw.githubusercontent.com/lkyoh/relay-console/main/relay-panel-install.sh -o /tmp/relay-panel-install.sh && sudo bash /tmp/relay-panel-install.sh --domain relay.example.com
```

请将 relay.example.com 换成自己的域名。安装器输出临时密码，首次登录设置正式密码、域名、节点协议，可批量导入 SOCKS5 或稍后添加。

不传 --domain 时仅开放本机回环初始化，通过安装器提示的 SSH 隧道访问。安装器不自动更改云安全组或现有防火墙规则。

Reality 使用 TCP 32001 起；HY2 使用 UDP 33001 起；TUIC 使用 UDP 34001 起。实际端口见节点列表。

完整说明见 [INSTALL.zh-CN.md](INSTALL.zh-CN.md)。

## 迁移

独立安装生成新的密钥与节点身份。保持旧链接的服务器迁移请在原面板“服务器管理”部署 / 同步备用服务器，再切换 DNS。DNS 缓存消失前需要客户端重新连接。没有提供自动切换 SLA。

安装包仅包含代码，不包含任何生产节点、密码、密钥、数据库或订阅 Token。sing-box 固定版本下载并校验 SHA256；二维码本地生成。没有任何协议能保证不会封禁。

## 前端

Vue 3 + TypeScript + Vite 8 + Naive UI，使用 @lucide/vue 图标和本地二维码生成。浏览器资源已构建到根目录 app.js / app.css / index.html，服务器不需要 Node.js，不依赖外部 CDN。

开发环境需要 Node.js 22.12+（建议当前受支持的 LTS）。前端源码位于 frontend/，依赖由 package-lock.json 固定。

## 前端

Vue 3 + TypeScript + Vite 8 + Naive UI，使用 @lucide/vue 图标和本地二维码生成。浏览器资源已构建到根目录 app.js / app.css / index.html，服务器不需要 Node.js，不依赖外部 CDN。

开发环境需要 Node.js 22.12+（建议当前受支持的 LTS）。前端源码位于 frontend/，依赖由 package-lock.json 固定。

## 开发与验证

运行时 Python 3.10+，python3-paramiko / python3-cryptography、certbot、nftables，由安装器安装。

```bash
python3 -m unittest discover -s . -p 'test_*.py'
cd frontend
npm ci
npm test
npm run build
cd ..
python3 build_installer.py
```

已做单元测试、Linux 配置校验和现有服务升级验证。尚未在全新云服务器执行整机安装验收；建议新机先验证再承载业务。

本项目为独立实现；初始化流程参考 Hiddify 的分步配置方式，不是 Hiddify 官方项目。

## License

MIT。qrcode.js 使用 Kazuhiko Arase 的 MIT 许可，原文件保留其声明。
