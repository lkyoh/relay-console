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

## UI 更新策略

表格采用可视区域虚拟渲染；实时数值使用独立组件与稳定快照，避免无变化的轮询结果触发整表更新。主题配置预先复用并使用 CSS 主题类，切换期间暂停颜色过渡；支持减少动画的系统偏好。代码资源支持 gzip 和 ETag/304；登录、API、订阅和 HTML 仍禁止缓存。

## 落地国家 / 地区

节点列表支持落地 IP 的国家 / 地区显示、搜索和排序。使用 ipwho.is 的中文 IP 归属地数据，服务器在后台限速查询、按落地地址去重，并将成功结果在本机缓存 7 天。查询失败退避重试，不阻塞列表，也不改变代理路由。该字段描述落地端点 IP 的数据库归属地，不等同于通过 SOCKS5 实测的出口位置。仅查询公网 IP，不发送节点账号或密码。

## 初始化协议与可选落地

新安装的网页初始化支持 VLESS Reality、Hysteria2、TUIC v5、Trojan TLS、Shadowsocks 2022（2022-blake3-aes-256-gcm）。初始 SOCKS5 落地可以留空，点击“跳过，稍后添加”，完成空节点初始化后再批量导入。Trojan 和 Shadowsocks 2022 使用每条线路基础端口 +3000/+4000；现有服务器升级不会自动启用新协议。SS2022 链接按 SIP002 使用百分号编码。
