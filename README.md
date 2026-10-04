# jiakuangate — VPN Gate SSTP 节点检测流水线

![check](https://github.com/ArbiterJade/jiakuangate/actions/workflows/check.yml/badge.svg)

自动抓取 [VPN Gate](https://www.vpngate.net/) 公开中继节点，筛选 SSTP 可用节点并检测可用性，按国家分组生成节点清单，供 edgetunnel 做链式代理。GitHub Actions 每 30 分钟自动运行一次，结果发布到 GitHub Pages。

## 功能特性

- **自动抓取**：三层数据源链（官方 API → jsDelivr CDN 镜像 → GitHub 镜像），每层失败自动重试 3 次再换下一层
- **SSTP 筛选**：只保留带 TCP 入口的中继（可走 SSTP/xray 链），UDP-only 节点直接丢弃
- **可用性检测**：并发调用 Cloudflare Worker 实际拨测每个节点，以 Worker 返回的 `success` 为准
- **住宅/机房分类**：按可信度三级判定——Worker 返回的真实 `is_datacenter` 标志 → 出口 ASN 组织名关键词 → host 前缀启发式
- **住宅二次校验**：对初判为住宅的节点，用 ip-api.com 免费接口复查出口 IP 的 `hosting` 标志，`hosting=true` 的误判节点会被踢回"机房"分类
- **多格式输出**：节点清单（chains.txt）、edgetunnel 优选 IP 清单（hosts.txt）、完整 vless 订阅（sub.txt）、网页数据（data.json）

## 工作流程

```
1. 获取 VPN Gate 原始节点（三层链：官方 api/iphone CSV → jsDelivr 镜像 CSV → GitHub 镜像 JSON，每层 3 次重试）
2. 筛选 SSTP 节点（OpenVPN 配置中 proto tcp + remote 端口）
3. 按 host+port+protocol 去重
4. 并发调用 Cloudflare Worker 检测（GET /check?proxyip=host:port）
4.5 住宅节点二次校验（ip-api.com 查出口 IP hosting 标志，误判改判机房）
5. 按国家分组，生成 public/ 下的 data.json / index.html / chains.txt / hosts.txt / sub.txt
6. GitHub Pages 自动部署
```

## 输出文件

| 文件 | 说明 | 用法 |
|---|---|---|
| `chains.txt` | 按国家分组的链式代理清单，`名字$sstp://vpn:vpn@host:port` | 粘贴到 edgetunnel 节点备注 |
| `hosts.txt` | `入口地址#名字$sstp://...` 格式 | 粘贴到 edgetunnel 后台「自定义优选IP」 |
| `sub.txt` | 完整 vless:// 订阅（链式代理编码在 path） | 填入 edgetunnel 后台「订阅链接」 |
| `data.json` | 全量检测数据 | 供网页端展示 |
| `index.html` | 节点展示页 | GitHub Pages 访问 |

> 账号密码固定为 `vpn:vpn`；节点名字（国家-住宅/机房-编号）固定不变，只有 `$sstp://` 后面的地址每 30 分钟自动更换。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `CHECK_WORKER` | `https://jiakuan.yorons.com/check?sstp=vpn:vpn@` | 主检测 Worker 地址 |
| `CHECK_WORKER_FALLBACK` | `https://check.helei.kdns.fr/check?sstp=vpn:vpn@` | 备用 Worker；主 Worker 自身故障（连接失败/非 200/坏 JSON）时自动切换，节点本身不可用不触发 |
| `FETCH_RETRIES` | `3` | 每个数据源失败后的重试次数 |
| `FETCH_BACKOFF` | `3,8` | 重试等待秒数（逗号分隔，依次取用） |
| `HOSTS_URL` | `https://arbiterjade.github.io/jiakuangate/hosts.txt` | hosts.txt 头部注释里的固定地址 |
| `CHECK_CONCURRENCY` | `32` | 检测并发数 |
| `CHECK_TIMEOUT` | `90` | 单节点检测超时（秒） |
| `MAX_CHECK_NODES` | `0`（不限） | 限制检测节点数，本地测试可用小值 |
| `VERIFY_RESIDENTIAL` | `1` | 住宅二次校验开关，设为 `0` 关闭 |
| `VERIFY_MIN_INTERVAL` | `1.5` | 校验调用间隔（秒），遵守 ip-api 45次/分钟限流 |
| `VERIFY_TIMEOUT` | `15` | 单次校验超时（秒） |
| `EDT_UUID` / `EDT_DOMAIN` / `EDT_FINGERPRINT` | 见代码 | edgetunnel 订阅的 UUID / 域名 / TLS 指纹 |
| `EDGE_HOSTS` | 见代码 | hosts.txt 的入口地址池（逗号分隔可覆盖） |

## 本地运行

```bash
pip install -r requirements.txt
python vpngate.py
# 输出在 public/ 目录
```

## 注意事项

- **"住宅"标签是估算**：最可信的是 Worker 返回的 `is_datacenter` 和二次校验结果，host 前缀启发式仅供参考；`data.json` 中每个节点的 `verify` 字段记录了校验详情
- **节点公开且不稳定**：VPN Gate 是全球共享的公开节点池，志愿者随时上下线，IP 可能已被各大平台标记；延迟、可用性每 30 分钟重新检测
- **退出码**：`0` = 正常完成（允许部分节点检测失败）；`1` = 硬性失败（数据源全挂 / 解析不出节点 / Worker 完全不可达），绝不生成"假成功"的空结果
