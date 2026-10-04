#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
流程:
  1. 获取 VPN Gate 原始节点 (官方 api/iphone CSV, 失败时回退 GitHub 预解析镜像)
  2. 只保留「带 TCP 入口」的中继 = SSTP 可用节点
     (OpenVPN 配置里 proto tcp + remote <ip> <port>; UDP-only 中继无法走 SSTP/xray 链, 直接丢弃)
  3. 按 host+port+protocol 去重
  4. 并发调用已部署的 Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (单节点 HTTP 成功 != 节点可用; 以 Worker 返回 JSON 的 success 字段为准)
  4.5 对初判为「住宅」的节点做二次校验: 用 ip-api.com 免费接口查出口 IP 的
      hosting/proxy 标志, hosting=true 的踢回「机房」(误判修正);
      校验失败(限流/网络异常)时保留原分类, 绝不让校验拖垮主流程
  5. 保留 success=true 的节点, 按国家分组, 生成 public/data.json + public/index.html
  6. 网页端 (GitHub Pages) 读取 data.json 展示

退出码:
  0 = 正常完成 (允许部分节点检测失败)
  1 = 硬性失败 (数据源全挂 / 解析不出 SSTP 节点 / Worker 完全不可达 / 程序异常)
     这些情况绝不允许"假成功"
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
# 回退链 (按顺序尝试, 三者基础设施互相独立):
#  1) jsDelivr CDN 镜像: 每 30 分钟快照, 与官方 API 同 CSV 格式
VPNGATE_MIRROR_CSV = os.environ.get(
    "VPNGATE_MIRROR_CSV",
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
)
#  2) GitHub raw JSON 镜像: 每日多次更新 (字段与官方 CSV 同源)
VPNGATE_MIRROR_JSON = os.environ.get(
    "VPNGATE_MIRROR",  # 兼容旧环境变量名
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 已部署的 Cloudflare Worker 检测接口 (GET /check?proxyip=host:port, 实测确认)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://jiakuan.yorons.com/check?sstp=vpn:vpn@")
# 备用检测 Worker: 主 Worker 自身故障 (连接失败/非 200/坏 JSON) 时自动切换;
# 节点本身不可用 (Worker 正常返回 success=false) 不会触发切换
WORKER_CHECK_URL_FALLBACK = os.environ.get(
    "CHECK_WORKER_FALLBACK",
    "https://check.helei.kdns.fr/check?sstp=vpn:vpn@",
)
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))   # 与 Worker 网页端一致的并发模型
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))          # 单请求客户端超时 (秒)
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))         # 0=不限; 本地测试可设小值
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))              # 拉取数据源超时
# --- 住宅二次校验 (ip-api.com 免费接口, 无需 key; 免费版限流 45 次/分钟) ---
VERIFY_RESIDENTIAL = os.environ.get("VERIFY_RESIDENTIAL", "1") == "1"  # 设为 0 可关闭二次校验
VERIFY_MIN_INTERVAL = float(os.environ.get("VERIFY_MIN_INTERVAL", "1.5"))  # 串行调用间隔(秒), 保证不触发限流
VERIFY_TIMEOUT = float(os.environ.get("VERIFY_TIMEOUT", "15"))            # 单次校验超时(秒)
VERIFY_API = os.environ.get(
    "VERIFY_API",
    "http://ip-api.com/json/{ip}?fields=status,message,hosting,proxy,isp,org,as,query",
)  # 注意: 免费版只支持 http, https 是付费功能
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# 出口数据中心的关键词启发 (判断"是否住宅 IP"用, 页面标注为估算)
DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
# 常见住宅宽带运营商关键词
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

# ISO 国家码 -> 中文名 (edgetunnel 清单展示用; 未收录则回退英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志 (用户要求的分区格式)
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    """硬性失败: 明确报错并退出非 0, 绝不允许假成功。"""
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 第 1 步: 获取 VPN Gate 原始节点
# ---------------------------------------------------------------------------
FETCH_RETRIES = max(1, int(os.environ.get("FETCH_RETRIES", "3")))  # 每个数据源重试次数
FETCH_BACKOFF = os.environ.get("FETCH_BACKOFF", "3,8")              # 重试等待秒数 (逗号分隔)


def _get_with_retries(url, timeout, headers, label):
    """带重试的 GET: runner 侧偶发网络抖动时多试几次, 避免一次失败就整轮作废。
    返回 response; 全部失败则抛出最后一个异常。"""
    backoffs = [float(x) for x in FETCH_BACKOFF.split(",") if x.strip()]
    last_exc = None
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            resp.raise_for_status()
            return resp
        except Exception as exc:  # noqa: BLE001 - 任何网络/HTTP异常都重试
            last_exc = exc
            log("VPN GATE", f"{label} 请求失败 (第{attempt}/{FETCH_RETRIES}次): {exc}")
            if attempt < FETCH_RETRIES:
                wait = backoffs[min(attempt - 1, len(backoffs) - 1)] if backoffs else 3
                log("VPN GATE", f"{wait:g} 秒后重试…")
                time.sleep(wait)
    raise last_exc


def fetch_vpngate():
    """返回 (rows, source)。rows: [{host, ip, country_long, country_short, config_b64}]
    按顺序尝试三个数据源 (官方 API -> jsDelivr CSV 镜像 -> GitHub JSON 镜像),
    每个源自带重试; 全部失败 -> 直接 die (exit 1)。"""
    sources = [
        # (展示名, URL, 格式, 来源标记, 请求头)
        ("官方 API", VPNGATE_API, "csv", "vpngate.net/api/iphone",
         {"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"}),
        ("jsDelivr 镜像", VPNGATE_MIRROR_CSV, "csv", "jsdelivr/vpngate-list-mirror",
         {"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"}),
        ("GitHub 镜像", VPNGATE_MIRROR_JSON, "json", "github-mirror",
         {"User-Agent": "Mozilla/5.0"}),
    ]
    last_exc = None
    for label, url, fmt, tag, headers in sources:
        try:
            log("VPN GATE", f"获取{label}: {url}")
            resp = _get_with_retries(url, timeout=HTTP_TIMEOUT, headers=headers, label=label)
            rows = parse_csv(resp.text) if fmt == "csv" else parse_mirror_json(resp.json())
            if rows:
                log("VPN GATE", f"{label} 获取到 {len(rows)} 个原始节点")
                return rows, tag
            raise RuntimeError(f"{label} 返回 0 行数据")
        except Exception as exc:
            last_exc = exc
            log("VPN GATE", f"{label} 获取失败: {exc}")
    die("全部数据源均不可用 (官方 API / jsDelivr 镜像 / GitHub 镜像), "
        f"数据源完全失败 (不生成空结果, 本次运行判定失败): {last_exc}")


def parse_csv(text):
    """解析官方 CSV。表头行含 'HostName'; 按列名映射, 列名缺失时用固定位置回退。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    # 列名映射 (不假设固定位置, 列名变化时自动适配; 全缺失时回退到已知位置)
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    """解析 GitHub 镜像 JSON: [ { "servers": [ {hostname, ip, countrylong, countryshort, openvpn_configdata_base64} ] } ]"""
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 筛选 SSTP 节点 (只保留带 TCP 入口的中继)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp_nodes(rows):
    """把原始行转成 SSTP 节点: 解码 OpenVPN 配置, 仅保留 proto tcp + remote 端口。
    host 统一为 <short>.opengw.net 形式; 返回去重前的节点列表。"""
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue  # 无 TCP 入口 -> 不是 SSTP 可用节点, 丢弃
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes


def dedupe(nodes):
    """按 host+port+protocol 去重。"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


# ---------------------------------------------------------------------------
# 第 3 步: 并发调用 Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """住宅/机房分类, 按可信度排序:
    1) Worker 返回的真实 is_datacenter 标志 (IP 情报库);
    2) 出口 ASN 组织名关键词;
    3) host 前缀启发式 (最后兜底, 属估算)。"""
    # 1) 真实数据中心标志 (SSTP 版 Worker 顶层 exit 直接给出)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) 出口组织名关键词
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host 前缀启发式 (估算)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate 官方公共中继 (机房/托管)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # 数字编号 = 注册的家用宽带中继 (家宽, 估算)
    return "unknown"


def _check_via_worker(node, session, worker_url):
    """用单个 Worker 检测单节点。返回 out dict。
    worker_error=True 表示 Worker 自身故障 (网络错误/非 200/坏 JSON);
    节点不可用时 success=False 但 worker_error 不置位。"""
    url = worker_url + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        # SSTP 版 Worker: 顶层直接返回 exit, 含真实 is_datacenter 标志 + 嵌套 asn 对象
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_one(node, session):
    """调用 Worker 检测单节点。主 Worker 自身故障时自动切备用 Worker 再试一次;
    两个都故障才记 worker_error。单节点失败不会抛出, 统一记 success=False。"""
    out = _check_via_worker(node, session, WORKER_CHECK_URL)
    out["worker_via"] = "primary"
    if out.get("worker_error") and WORKER_CHECK_URL_FALLBACK \
            and WORKER_CHECK_URL_FALLBACK != WORKER_CHECK_URL:
        log("CLOUDFLARE WORKER", f"主 Worker 故障 ({out.get('error')}), 切换备用 Worker 重试: "
            f"{node['host']}:{node['port']}")
        fb = _check_via_worker(node, session, WORKER_CHECK_URL_FALLBACK)
        if not fb.get("worker_error"):
            fb["worker_via"] = "fallback"
            return fb
        out["error"] = f"{out.get('error')} | 备用 Worker 也失败: {fb.get('error')}"
        out["worker_via"] = "primary+fallback-failed"
    return out


def check_all(nodes, session):
    """32 并发 (与网页端一致)。单节点失败不影响整体; 但区分'节点不可用'与'Worker 异常'。"""
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# 第 3.5 步: 住宅节点二次校验 (ip-api.com 免费接口)
# ---------------------------------------------------------------------------
def verify_exit_ip(ip, session):
    """用 ip-api.com 查出口 IP 的 hosting/proxy 标志。
    返回 (hosting, proxy, isp, org, error):
      hosting=True  -> 机房/托管 IP (初判住宅 = 误判, 调用方负责改判)
      proxy=True    -> 已知代理/VPN 出口 (仅标注不改判; VPN Gate 公开节点大量命中属正常)
      出错/限流     -> 前四项为 None + error, 调用方保留原分类。"""
    try:
        r = session.get(VERIFY_API.format(ip=ip), timeout=VERIFY_TIMEOUT,
                        headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code == 429:
            return None, None, None, None, "rate-limited(429)"
        if r.status_code != 200:
            return None, None, None, None, f"HTTP {r.status_code}"
        j = r.json()
        if j.get("status") != "success":
            return None, None, None, None, j.get("message") or "api-fail"
        return (bool(j.get("hosting")), bool(j.get("proxy")),
                j.get("isp"), j.get("org"), None)
    except Exception as exc:
        return None, None, None, None, f"{type(exc).__name__}"


def verify_residential_nodes(results, session):
    """对初判 residential 的成功节点逐个二次校验。
    hosting=True -> 改判 datacenter (误判修正); 其余保留原分类并记录校验详情。
    串行 + 间隔调用, 遵守 ip-api 免费版 45 次/分钟限流; 任何单点失败都不抛异常。"""
    targets = [r for r in results
               if r.get("success") and r.get("residential") == "residential"
               and (r.get("exit") or {}).get("ip")]
    verified = 0
    reclassified = 0
    skipped = 0
    for i, r in enumerate(targets):
        ip = r["exit"]["ip"]
        if i:
            time.sleep(VERIFY_MIN_INTERVAL)
        hosting, proxy, isp, org, err = verify_exit_ip(ip, session)
        v = {"checked": err is None, "hosting": hosting, "proxy": proxy,
             "isp": isp, "org": org}
        if err:
            v["error"] = err
            skipped += 1
            log("VERIFY", f"[{i + 1}/{len(targets)}] {ip} 校验跳过({err}), 保留原分类")
        elif hosting:
            r["residential"] = "datacenter"
            v["reclassified"] = True
            reclassified += 1
            log("VERIFY", f"[{i + 1}/{len(targets)}] {ip} hosting=true -> 改判机房 (原住宅为误判)")
        else:
            r["verified_residential"] = True
            verified += 1
            suffix = " (proxy=true, 已知代理出口, 仅标注)" if proxy else ""
            log("VERIFY", f"[{i + 1}/{len(targets)}] {ip} hosting=false -> 住宅确认{suffix}")
        r["verify"] = v
    log("VERIFY", f"完成: 住宅确认 {verified} / 改判机房 {reclassified} / 跳过 {skipped}")
    return {"verified": verified, "reclassified": reclassified, "skipped": skipped}


# ---------------------------------------------------------------------------
# 第 4 步: 生成网页数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source, verify_stats=None):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
        "verified_residential": sum(1 for n in available if n.get("verified_residential")),
        "verify_reclassified": (verify_stats or {}).get("reclassified", 0),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["verified"] = sum(1 for n in grp["nodes"] if n.get("verified_residential"))
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "worker_fallback": WORKER_CHECK_URL_FALLBACK or None,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", "https://jerylihub.github.io/gate/chains.txt")


def build_chains_text(data):
    """生成 edgetunnel 链式代理清单: 按国家分组, 每国编号固定, 住宅优先, 延迟升序。
    每行 = 「名字 + $sstp://vpn:vpn@host:port」, 名字不变, 指令每 30 分钟自动换。"""
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不变, 只有 $sstp:// 后面的地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("verified_residential") else (1 if n.get("residential") == "residential" else 2),
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']}, 已验证 {grp.get('verified', 0)} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 入口地址池: 客户端直连 Cloudflare 的优选 IP:端口 (循环分配给每个国家节点当入口)
# 可通过环境变量 EDGE_HOSTS 覆盖 (逗号分隔)
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "japan.com:443,icook.tw:443,www.visa.com.tw:443,www.glassdoor.com:443,www.okcupid.com:443",
    ).split(",")
    if h.strip()
]

HOSTS_URL = os.environ.get("HOSTS_URL", "https://arbiterjade.github.io/jiakuangate/hosts.txt")


def build_hosts_text(data):
    """生成可直接粘贴到 edgetunnel 后台「自定义优选IP」框的清单。
    每行 = 入口地址#名字$sstp://... ; 名字固定, 底下 SSTP 节点每 30 分钟自动换。"""
    countries = data["countries"]
    # 入口: 默认用 7 个实测可用优选域名循环分配; 可用 HOSTS_ENTRY 覆盖(逗号分隔)
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 入口用 7 个实测可用优选域名循环分配",
        "# 名字 = 国家-住宅/机房-编号, 直接区分住宅与机房",
        "# 名字固定; 只有 $sstp:// 后面的节点地址每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("verified_residential") else (1 if n.get("residential") == "residential" else 2),
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']}, 已验证 {grp.get('verified', 0)} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 完整订阅 (vless://) 配置
EDT_UUID = os.environ.get("EDT_UUID", "f779ff9b-433c-44ba-a65a-fd1aa9e64587")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "cm001.yorons.com")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", "https://jerylihub.github.io/gate/sub.txt")


def _b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """复刻 edgetunnel 的 获取SOCKS5账号: user:pass@host:port -> {username,password,hostname,port}。"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    """生成 edgetunnel 完整 vless:// 订阅 (链式代理编码在 path)。
    填进 edgetunnel 后台「订阅链接」URL, 客户端定时拉取即可自动轮换。"""
    countries = data["countries"]
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (每 30 分钟重新检测)",
        f"# 固定地址: {SUB_URL}",
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字固定; $sstp:// 链式代理(编码在 path)每 30 分钟自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("verified_residential") else (1 if n.get("residential") == "residential" else 2),
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            chain_json = json.dumps(chain, separators=(",", ":"))
            enc = _b64_secret_encode(chain_json, EDT_UUID)
            path = quote("/video/" + enc, safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    # 固定网页: 始终用 web/index.html 模板生成同一个 index.html (数据来自 data.json)
    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # edgetunnel 链式代理清单 (固定 URL, 方案一: 名字不变、指令自动换)
    chains_path = os.path.join(PUBLIC_DIR, "chains.txt")
    with open(chains_path, "w", encoding="utf-8") as f:
        f.write(build_chains_text(data))

    # 可直接粘贴进后台「自定义优选IP」框的清单 (入口地址#名字$sstp://...)
    hosts_path = os.path.join(PUBLIC_DIR, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(build_hosts_text(data))

    # 完整 vless:// 订阅 (填进后台「订阅链接」URL, 客户端自动轮换)
    sub_path = os.path.join(PUBLIC_DIR, "sub.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write(build_sub_text(data))

    # 测速页: web/speedtest.html 是纯静态页, 直接复制到 public/ 发布
    speedtest_src = os.path.join(REPO_DIR, "web", "speedtest.html")
    if os.path.exists(speedtest_src):
        with open(speedtest_src, "r", encoding="utf-8") as f:
            speedtest_html = f.read()
        with open(os.path.join(PUBLIC_DIR, "speedtest.html"), "w", encoding="utf-8") as f:
            f.write(speedtest_html)

    return data_path, html_path, chains_path, hosts_path, sub_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    # 2) SSTP 筛选 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    # 3) 并发检测
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # 硬性失败: Worker 完全不可达 (没有任何一个请求拿到正常响应)
    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    # 3.5) 住宅二次校验 (只改判误判节点; 任何失败都不影响主流程)
    verify_stats = {"verified": 0, "reclassified": 0, "skipped": 0}
    if VERIFY_RESIDENTIAL:
        log("VERIFY", "住宅节点二次校验开始 (ip-api.com)")
        verify_stats = verify_residential_nodes(results, session)
    else:
        log("VERIFY", "二次校验已禁用 (VERIFY_RESIDENTIAL=0)")

    # 4) 结果 + 网页
    data = build_outputs(results, raw_count, sstp_count, source, verify_stats)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")
    log("RESULT", f"住宅确认: {verify_stats['verified']} / 改判机房: {verify_stats['reclassified']}")

    data_path, html_path, chains_path, hosts_path, sub_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(chains_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(hosts_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(sub_path, REPO_DIR)}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
