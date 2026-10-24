#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xray 多端口代理管理器（精简版）

单文件、仅标准库。一个 xray.exe 进程开启多个本地 SOCKS5 端口，
每个端口对应一个节点；支持订阅、链接解析、测延迟/测速、排序、
进程守护、配置持久化与 Xray-core 自动下载。

用法:
    python xray_multi_port.py
    python xray_multi_port.py --selftest
"""

import base64
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# 常量 / 路径
# ---------------------------------------------------------------------------

APP_NAME = "Xray 多端口代理管理器"
APP_VERSION = "v0.1.3"
APP_DIR = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)
SETTINGS_PATH = os.path.join(APP_DIR, "xmp_lite_settings.json")
CONFIG_PATH = os.path.join(APP_DIR, "xray_config.json")
DEFAULT_XRAY_PATH = os.path.join(APP_DIR, "xray.exe")
ICON_PATH = os.path.join(APP_DIR, "app.ico")

DEFAULT_BASE_PORT = 10808

# 内网/保留地址（RFC1918/环回/链路本地/组播保留/CGNAT/测试网段 + IPv6 私有段），
# 与 v2fly geoip private 一致，直接内嵌避免依赖 geoip.dat
PRIVATE_CIDRS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/3",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
USER_AGENT = "v2rayN/6.23"
LATENCY_HOST = "www.gstatic.com"
LATENCY_PATH = "/generate_204"
SPEED_HOST = "cachefly.cachefly.net"
SPEED_PATH = "/10mb.test"
SPEED_MAX_BYTES = 10 * 1024 * 1024
LATENCY_TIMEOUT = 5.0
SPEED_TIMEOUT = 12.0
SUB_TIMEOUT = 20.0
MAX_LOG_LINES = 1500

NODE_DEFAULTS = {
    "nid": "",
    "name": "",
    "proto": "",
    "server": "",
    "port": 0,
    "uuid": "",
    "alter_id": 0,
    "security": "auto",
    "flow": "",
    "password": "",
    "method": "",
    "network": "tcp",
    "header_type": "",
    "host": "",
    "path": "",
    "service_name": "",
    "tls": "",
    "sni": "",
    "fp": "",
    "pbk": "",
    "sid": "",
    "link": "",
    "sub": "",
    "local_port": None,
    "enabled": False,
    "latency": None,
    "speed": None,
}

# tkinter 延迟导入（--selftest 不加载）
tk = None
ttk = None
filedialog = None
messagebox = None
simpledialog = None


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def to_int(value, default=None):
    """宽松转 int；bool / 非法值返回 default。"""
    if isinstance(value, bool):
        return default
    try:
        if value is None:
            return default
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def is_valid_port(value):
    p = to_int(value)
    return p is not None and 1 <= p <= 65535


def gen_nid():
    return "n" + uuid.uuid4().hex[:12]


def decode_bytes(data):
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def b64_decode_text(text):
    """宽松 base64 解码：去空白、urlsafe 转换、补齐 =、兼容 UTF-8/GBK。"""
    if not text:
        return ""
    s = "".join(str(text).split())
    if not s:
        return ""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    try:
        data = base64.b64decode(s, validate=False)
    except Exception:
        return ""
    if not data:
        return ""
    return decode_bytes(data)


def redact(text):
    """日志脱敏：隐藏分享链接与 http(s) URL 的路径/凭据。"""
    s = str(text)

    def _http_repl(match):
        try:
            parts = urllib.parse.urlsplit(match.group(0))
            if parts.netloc:
                return parts.scheme + "://" + parts.netloc + "/***"
        except Exception:
            pass
        return "***"

    s = re.sub(r"(?i)\b(?:vmess|vless|trojan|ss)://[^\s\"']+", "***", s)
    s = re.sub(r"(?i)\bhttps?://[^\s\"']+", _http_repl, s)
    return s


def format_speed(bps):
    try:
        v = float(bps)
    except (TypeError, ValueError):
        return str(bps) if bps else ""
    if v >= 1024.0 * 1024.0:
        return "%.2f MB/s" % (v / (1024.0 * 1024.0))
    if v >= 1024.0:
        return "%.1f KB/s" % (v / 1024.0)
    return "%.0f B/s" % v


# ---------------------------------------------------------------------------
# 持久化
# ---------------------------------------------------------------------------


def atomic_write_json(path, data):
    """临时文件 + os.replace 原子写 JSON。"""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".xmp_", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def normalize_node(raw):
    """加载时补默认字段、校验基本字段。"""
    if not isinstance(raw, dict):
        return None
    proto = str(raw.get("proto") or "").strip().lower()
    if proto == "shadowsocks":
        proto = "ss"
    if proto not in ("vmess", "vless", "trojan", "ss"):
        return None
    server = str(raw.get("server") or "").strip()
    port = to_int(raw.get("port"))
    if not server or not is_valid_port(port):
        return None

    node = dict(NODE_DEFAULTS)
    node.update(raw)
    node["proto"] = proto
    node["server"] = server
    node["port"] = port
    node["name"] = str(node.get("name") or "").strip() or ("%s:%s" % (server, port))
    node["nid"] = str(node.get("nid") or "").strip() or gen_nid()
    node["uuid"] = str(node.get("uuid") or "").strip()
    node["password"] = str(node.get("password") or "")
    node["method"] = str(node.get("method") or "").strip()
    node["alter_id"] = max(0, to_int(node.get("alter_id"), 0) or 0)
    node["security"] = str(node.get("security") or "auto").strip() or "auto"
    node["flow"] = str(node.get("flow") or "").strip()
    node["network"] = _normalize_network(node.get("network"))
    node["header_type"] = str(node.get("header_type") or "").strip().lower()
    if node["header_type"] == "none":
        node["header_type"] = ""
    node["host"] = str(node.get("host") or "").strip()
    node["path"] = str(node.get("path") or "").strip()
    node["service_name"] = str(node.get("service_name") or "").strip()
    node["tls"] = _normalize_security(node.get("tls"))
    node["sni"] = str(node.get("sni") or "").strip()
    node["fp"] = str(node.get("fp") or "").strip()
    node["pbk"] = str(node.get("pbk") or "").strip()
    node["sid"] = str(node.get("sid") or "").strip()
    node["link"] = str(node.get("link") or "")
    node["sub"] = str(node.get("sub") or "")

    lp = to_int(node.get("local_port"))
    node["local_port"] = lp if is_valid_port(lp) else None
    node["enabled"] = to_bool(node.get("enabled"))

    lat = node.get("latency")
    if isinstance(lat, bool) or not isinstance(lat, (int, float)):
        node["latency"] = "超时" if lat == "超时" else None
    spd = node.get("speed")
    if isinstance(spd, bool) or not isinstance(spd, (int, float)):
        node["speed"] = "超时" if spd == "超时" else None
    return node


def load_settings(path=SETTINGS_PATH):
    """读取设置；损坏/缺字段时安全回退，并修复重复 id。"""
    settings = {
        "xray_path": DEFAULT_XRAY_PATH,
        "base_port": DEFAULT_BASE_PORT,
        "lan_access": False,
        "mixed_port": False,
        "subs": [],
        "nodes": [],
    }
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return settings
    if not isinstance(data, dict):
        return settings

    xray_path = data.get("xray_path")
    if isinstance(xray_path, str) and xray_path.strip():
        settings["xray_path"] = xray_path.strip()
    base_port = to_int(data.get("base_port"))
    if is_valid_port(base_port):
        settings["base_port"] = base_port
    settings["lan_access"] = bool(data.get("lan_access"))
    settings["mixed_port"] = bool(data.get("mixed_port"))

    subs = []
    seen_urls = set()
    if isinstance(data.get("subs"), list):
        for item in data["subs"]:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            url = str(item.get("url") or "").strip()
            if not name or not url or url in seen_urls:
                continue
            seen_urls.add(url)
            subs.append({"name": name, "url": url})
    settings["subs"] = subs

    nodes = []
    seen_ids = set()
    seen_keys = set()
    if isinstance(data.get("nodes"), list):
        for raw in data["nodes"]:
            node = normalize_node(raw)
            if node is None:
                continue
            while node["nid"] in seen_ids:
                node["nid"] = gen_nid()
            key = node_key(node)
            if key in seen_keys:
                continue
            seen_ids.add(node["nid"])
            seen_keys.add(key)
            nodes.append(node)
    settings["nodes"] = nodes
    return settings


# ---------------------------------------------------------------------------
# 编解码 / 链接解析
# ---------------------------------------------------------------------------


def _normalize_network(value):
    v = str(value or "").strip().lower()
    if v in ("", "tcp", "raw"):
        return "tcp"
    if v in ("ws", "websocket"):
        return "ws"
    if v == "grpc":
        return "grpc"
    if v in ("h2", "http"):
        return "h2"
    if v == "httpupgrade":
        return "httpupgrade"
    return "tcp"


def _normalize_security(value):
    v = str(value or "").strip().lower()
    if v in ("tls", "xtls"):
        return "tls"
    if v == "reality":
        return "reality"
    return ""


def split_host_port(text):
    """解析 host:port / [IPv6]:port，返回 (host, int port)。"""
    text = (text or "").strip()
    text = text.split("/", 1)[0].split("?", 1)[0]
    if not text:
        raise ValueError("地址为空")
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("IPv6 地址缺少 ]")
        host = text[1:end].strip()
        rest = text[end + 1:]
        if not rest.startswith(":"):
            raise ValueError("缺少端口")
        port = to_int(rest[1:])
    else:
        if ":" not in text:
            raise ValueError("缺少端口")
        host, port_text = text.rsplit(":", 1)
        host = host.strip()
        port = to_int(port_text)
    if not host or not is_valid_port(port):
        raise ValueError("主机或端口无效")
    return host, port


def node_key(node):
    proto = str(node.get("proto") or "").strip().lower()
    identity = node.get("uuid") if proto in ("vmess", "vless") else node.get("password")
    return "%s|%s|%s|%s" % (
        proto,
        node.get("server") or "",
        to_int(node.get("port"), 0),
        identity or "",
    )


def _new_node(**kwargs):
    node = dict(NODE_DEFAULTS)
    node.update(kwargs)
    node["nid"] = node.get("nid") or gen_nid()
    return node


def _finish_parsed_node(node):
    if not node:
        return None
    node["name"] = str(node.get("name") or "").strip() or (
        "%s:%s" % (node.get("server"), node.get("port"))
    )
    node["network"] = _normalize_network(node.get("network"))
    node["tls"] = _normalize_security(node.get("tls"))
    node["header_type"] = str(node.get("header_type") or "").strip().lower()
    if node["header_type"] == "none":
        node["header_type"] = ""
    node["local_port"] = None
    node["enabled"] = False
    node["latency"] = None
    node["speed"] = None
    node["sub"] = ""
    return node


def _parse_vmess(link):
    rest = link[len("vmess://"):]
    body, _, frag = rest.partition("#")
    body = urllib.parse.unquote(body.strip())
    raw = b64_decode_text(body)
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    server = str(obj.get("add") or "").strip()
    port = to_int(obj.get("port"))
    uid = str(obj.get("id") or "").strip()
    if not server or not uid or not is_valid_port(port):
        return None
    name = str(obj.get("ps") or "").strip()
    if not name and frag:
        name = urllib.parse.unquote(frag.strip())
    node = _new_node(
        name=name,
        proto="vmess",
        server=server,
        port=port,
        uuid=uid,
        alter_id=max(0, to_int(obj.get("aid"), 0) or 0),
        security=str(obj.get("scy") or obj.get("security") or "auto").strip() or "auto",
        network=obj.get("net"),
        header_type=obj.get("type"),
        host=str(obj.get("host") or "").strip(),
        path=str(obj.get("path") or "").strip(),
        service_name=str(obj.get("path") or "").strip(),
        tls=obj.get("tls"),
        sni=str(obj.get("sni") or "").strip(),
        fp=str(obj.get("fp") or "").strip(),
        pbk=str(obj.get("pbk") or "").strip(),
        sid=str(obj.get("sid") or "").strip(),
    )
    return _finish_parsed_node(node)


def _parse_vless(link):
    rest = link[len("vless://"):]
    body, _, frag = rest.partition("#")
    core, _, query = body.partition("?")
    if "@" not in core:
        return None
    userinfo, hostport = core.rsplit("@", 1)
    uid = urllib.parse.unquote(userinfo).strip()
    if not uid:
        return None
    server, port = split_host_port(hostport)
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    name = urllib.parse.unquote(frag.strip())
    node = _new_node(
        name=name,
        proto="vless",
        server=server,
        port=port,
        uuid=uid,
        network=params.get("type", "tcp"),
        header_type=params.get("headerType", ""),
        host=str(params.get("host") or "").strip(),
        path=str(params.get("path") or "").strip(),
        service_name=str(
            params.get("serviceName") or params.get("service_name") or ""
        ).strip(),
        tls=params.get("security", ""),
        sni=str(params.get("sni") or params.get("serverName") or "").strip(),
        fp=str(params.get("fp") or "").strip(),
        pbk=str(params.get("pbk") or "").strip(),
        sid=str(params.get("sid") or "").strip(),
        flow=str(params.get("flow") or "").strip(),
    )
    return _finish_parsed_node(node)


def _parse_trojan(link):
    rest = link[len("trojan://"):]
    body, _, frag = rest.partition("#")
    core, _, query = body.partition("?")
    if "@" not in core:
        return None
    password, hostport = core.rsplit("@", 1)
    password = urllib.parse.unquote(password)
    if not password:
        return None
    server, port = split_host_port(hostport)
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    sec_raw = params.get("security")
    if sec_raw is None or str(sec_raw).strip() == "":
        security = "tls"
    else:
        security = _normalize_security(sec_raw)
    name = urllib.parse.unquote(frag.strip())
    node = _new_node(
        name=name,
        proto="trojan",
        server=server,
        port=port,
        password=password,
        network=params.get("type", "tcp"),
        header_type=params.get("headerType", ""),
        host=str(params.get("host") or "").strip(),
        path=str(params.get("path") or "").strip(),
        service_name=str(
            params.get("serviceName") or params.get("service_name") or ""
        ).strip(),
        tls=security,
        sni=str(params.get("sni") or params.get("peer") or "").strip(),
        fp=str(params.get("fp") or "").strip(),
        pbk=str(params.get("pbk") or "").strip(),
        sid=str(params.get("sid") or "").strip(),
        flow=str(params.get("flow") or "").strip(),
    )
    return _finish_parsed_node(node)


def _parse_ss(link):
    rest = link[len("ss://"):]
    body, _, frag = rest.partition("#")
    name = urllib.parse.unquote(frag.strip())
    body = body.strip()
    # 去掉 SIP002 的 plugin 查询串（在 host:port 之后）
    if "?" in body:
        body = body.split("?", 1)[0]
    method = ""
    password = ""
    hostport = ""
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            decoded = b64_decode_text(userinfo)
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)
    else:
        decoded = b64_decode_text(urllib.parse.unquote(body))
        if "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)
    method = method.strip()
    if not method:
        return None
    server, port = split_host_port(hostport)
    node = _new_node(
        name=name,
        proto="ss",
        server=server,
        port=port,
        method=method,
        password=password,
        network="tcp",
        tls="",
    )
    return _finish_parsed_node(node)


def parse_share_link(link):
    """解析 vmess/vless/trojan/ss 分享链接；失败返回 None。"""
    if not isinstance(link, str):
        return None
    link = link.strip().lstrip("\ufeff")
    if not link or "://" not in link:
        return None
    scheme = link.split("://", 1)[0].strip().lower()
    try:
        if scheme == "vmess":
            node = _parse_vmess(link)
        elif scheme == "vless":
            node = _parse_vless(link)
        elif scheme == "trojan":
            node = _parse_trojan(link)
        elif scheme == "ss":
            node = _parse_ss(link)
        else:
            return None
    except Exception:
        return None
    if not node:
        return None
    node["link"] = link
    return node


def parse_subscription_text(text):
    """解析订阅文本/多行链接，返回 (nodes, failed_count)。"""
    if not text or not str(text).strip():
        return [], 0
    raw = str(text).strip().lstrip("\ufeff")
    if "://" not in raw:
        decoded = b64_decode_text(raw)
        if decoded and "://" in decoded:
            raw = decoded
        else:
            return [], 1

    nodes = []
    failed = 0
    for line in raw.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        node = parse_share_link(line)
        if node is None:
            failed += 1
            continue
        nodes.append(node)

    unique = []
    seen = set()
    for node in nodes:
        key = node_key(node)
        if key in seen:
            continue
        seen.add(key)
        unique.append(node)
    return unique, failed


def merge_subscription_nodes(old_nodes, sub_url, new_nodes):
    """按 key 合并订阅节点，保留旧节点的端口/勾选/测速结果。

    返回 (merged_nodes, added, removed, skipped_duplicates)。
    """
    old_for_sub = [n for n in old_nodes if n.get("sub") == sub_url]
    old_by_key = {}
    for node in old_for_sub:
        old_by_key.setdefault(node_key(node), node)

    kept = [n for n in old_nodes if n.get("sub") != sub_url]
    keys = set(node_key(n) for n in kept)
    matched = set()
    added = 0
    skipped = 0

    for node in new_nodes:
        key = node_key(node)
        if key in keys:
            skipped += 1
            continue
        previous = old_by_key.get(key)
        if previous:
            node["nid"] = previous.get("nid") or node.get("nid") or gen_nid()
            for field in ("local_port", "enabled", "latency", "speed"):
                node[field] = previous.get(field)
            matched.add(key)
        else:
            added += 1
        node["sub"] = sub_url
        kept.append(node)
        keys.add(key)

    removed = len(old_for_sub) - len(matched)
    return kept, added, removed, skipped


# ---------------------------------------------------------------------------
# 订阅拉取
# ---------------------------------------------------------------------------


def fetch_subscription(url, timeout=SUB_TIMEOUT):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()
        charset = response.headers.get_content_charset()
    if charset:
        try:
            return data.decode(charset, "replace")
        except Exception:
            pass
    return decode_bytes(data)


# ---------------------------------------------------------------------------
# 端口 / 配置生成
# ---------------------------------------------------------------------------


def is_port_free(port):
    p = to_int(port)
    if not is_valid_port(p):
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def next_free_port(nodes=None, base_port=DEFAULT_BASE_PORT, extra_used=None):
    """从 base_port 起找未被节点占用且可 bind 的端口。"""
    used = set()
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        p = to_int(node.get("local_port"))
        if is_valid_port(p):
            used.add(p)
    if extra_used:
        for value in extra_used:
            p = to_int(value)
            if is_valid_port(p):
                used.add(p)
    start = to_int(base_port)
    if not is_valid_port(start):
        start = DEFAULT_BASE_PORT
    p = start
    while p <= 65535:
        if p not in used and is_port_free(p):
            return p
        p += 1
    return None


def assign_missing_ports(nodes, base_port=DEFAULT_BASE_PORT):
    """给没有有效本地端口的节点补端口，返回补了多少个。"""
    used = set()
    for node in nodes:
        p = to_int(node.get("local_port"))
        if is_valid_port(p):
            used.add(p)
    start = to_int(base_port)
    if not is_valid_port(start):
        start = DEFAULT_BASE_PORT
    cursor = start
    changed = 0
    for node in nodes:
        p = to_int(node.get("local_port"))
        if is_valid_port(p):
            continue
        while cursor <= 65535 and (cursor in used or not is_port_free(cursor)):
            cursor += 1
        if cursor > 65535:
            break
        node["local_port"] = cursor
        used.add(cursor)
        cursor += 1
        changed += 1
    return changed


def prepare_nodes_for_config(nodes, base_port=DEFAULT_BASE_PORT):
    """启动前整理节点：补端口、跳过冲突/被占用端口并返回告警。"""
    warnings = []
    valid = []
    used = set()
    for node in nodes:
        if not isinstance(node, dict) or not node.get("enabled", True):
            continue
        name = node.get("name") or node.get("server") or "未命名"
        p = to_int(node.get("local_port"))
        if not is_valid_port(p):
            p = next_free_port(nodes, base_port, used)
            if p is None:
                warnings.append("节点「%s」没有可用本地端口，已跳过" % name)
                continue
            node["local_port"] = p
        if p in used:
            warnings.append("节点「%s」本地端口 %s 冲突，已跳过" % (name, p))
            continue
        if not is_port_free(p):
            warnings.append("节点「%s」本地端口 %s 已被占用，已跳过" % (name, p))
            continue
        used.add(p)
        valid.append(node)
    return valid, warnings


def build_stream_settings(node):
    network = _normalize_network(node.get("network"))
    host = str(node.get("host") or "").strip()
    path = str(node.get("path") or "").strip()
    if network in ("ws", "h2", "httpupgrade") and not path:
        path = "/"

    stream = {"network": network}
    if network == "ws":
        ws = {"path": path or "/"}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": str(node.get("service_name") or path or "").strip()
        }
    elif network == "h2":
        h2 = {"path": path or "/"}
        if host:
            h2["host"] = [item.strip() for item in host.split(",") if item.strip()]
        stream["httpSettings"] = h2
    elif network == "httpupgrade":
        hu = {"path": path or "/"}
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu
    elif network == "tcp" and str(node.get("header_type") or "").lower() == "http":
        request = {
            "version": "1.1",
            "method": "GET",
            "path": [path or "/"],
            "headers": {},
        }
        if host:
            request["headers"]["Host"] = [host]
        stream["tcpSettings"] = {"header": {"type": "http", "request": request}}

    security = str(node.get("tls") or "").strip().lower()
    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": str(node.get("sni") or node.get("server") or "").strip(),
            "fingerprint": str(node.get("fp") or "chrome").strip() or "chrome",
            "publicKey": str(node.get("pbk") or "").strip(),
            "shortId": str(node.get("sid") or "").strip(),
            "spiderX": "/",
        }
    elif security in ("tls", "xtls"):
        stream["security"] = "tls"
        tls_settings = {
            "serverName": str(node.get("sni") or node.get("server") or "").strip()
        }
        fp = str(node.get("fp") or "").strip()
        if fp:
            tls_settings["fingerprint"] = fp
        stream["tlsSettings"] = tls_settings
    else:
        stream["security"] = "none"
    return stream


def build_outbound(node, tag):
    proto = str(node.get("proto") or "").strip().lower()
    if proto == "shadowsocks":
        proto = "ss"
    server = str(node.get("server") or "").strip()
    port = to_int(node.get("port"))
    if not server or not is_valid_port(port):
        return None
    stream = build_stream_settings(node)

    if proto == "vmess":
        uid = str(node.get("uuid") or "").strip()
        if not uid:
            return None
        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": server,
                        "port": port,
                        "users": [
                            {
                                "id": uid,
                                "alterId": max(0, to_int(node.get("alter_id"), 0) or 0),
                                "security": str(node.get("security") or "auto").strip()
                                or "auto",
                                "level": 0,
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream,
        }

    if proto == "vless":
        uid = str(node.get("uuid") or "").strip()
        if not uid:
            return None
        user = {"id": uid, "encryption": "none", "level": 0}
        flow = str(node.get("flow") or "").strip()
        if flow:
            user["flow"] = flow
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"address": server, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }

    if proto == "trojan":
        password = str(node.get("password") or "")
        if not password:
            return None
        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {"address": server, "port": port, "password": password, "level": 0}
                ]
            },
            "streamSettings": stream,
        }

    if proto == "ss":
        method = str(node.get("method") or "").strip()
        password = str(node.get("password") or "")
        if not method:
            return None
        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {"address": server, "port": port, "method": method, "password": password}
                ]
            },
            "streamSettings": stream,
        }
    return None


def get_lan_ip():
    """探测本机局域网 IP（UDP connect 不会实际发包）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def parse_traffic_payload(text):
    """解析 xray api statsquery 的 JSON 输出 → {本地端口: {"up":..,"down":..}}。"""
    result = {}
    try:
        data = json.loads(text)
    except Exception:
        return result
    if not isinstance(data, dict):
        return result
    for stat in data.get("stat") or []:
        if not isinstance(stat, dict):
            continue
        name = str(stat.get("name") or "")
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "inbound" or parts[2] != "traffic":
            continue
        tag = parts[1]
        if not tag.startswith("in"):
            continue
        try:
            port = int(tag[2:])
        except ValueError:
            continue
        if not is_valid_port(port):
            continue
        value = to_int(stat.get("value"), 0) or 0
        slot = result.setdefault(port, {"up": 0, "down": 0})
        if parts[3] == "uplink":
            slot["up"] = value
        elif parts[3] == "downlink":
            slot["down"] = value
    return result


def fmt_bytes(size):
    try:
        size = float(size)
    except (TypeError, ValueError):
        return "0B"
    negative = size < 0
    size = abs(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            text = ("%d" % int(size)) if unit == "B" else ("%.2f" % size)
            return ("-" if negative else "") + text + unit
        size /= 1024.0
    return "0B"


def fmt_traffic(up, down, per_second=False):
    suffix = "/s" if per_second else ""
    return "↑%s%s ↓%s%s" % (fmt_bytes(up), suffix, fmt_bytes(down), suffix)


def build_xray_config(
    enabled_nodes,
    base_port=DEFAULT_BASE_PORT,
    listen="127.0.0.1",
    mixed=False,
    api_port=None,
):
    """一个进程、每节点一个 inbound + outbound + routing 规则。"""
    nodes = list(enabled_nodes or [])
    explicit_ports = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        p = to_int(node.get("local_port"))
        if is_valid_port(p):
            explicit_ports.add(p)

    inbounds = []
    outbounds = []
    rules = []
    used = set()
    start = to_int(base_port)
    if not is_valid_port(start):
        start = DEFAULT_BASE_PORT
    cursor = start
    index = 0

    for node in nodes:
        if not isinstance(node, dict) or not node.get("enabled", True):
            continue
        proto = str(node.get("proto") or "").strip().lower()
        if proto == "shadowsocks":
            proto = "ss"
        if proto not in ("vmess", "vless", "trojan", "ss"):
            continue
        server = str(node.get("server") or "").strip()
        remote_port = to_int(node.get("port"))
        if not server or not is_valid_port(remote_port):
            continue

        local_port = to_int(node.get("local_port"))
        if not is_valid_port(local_port):
            while cursor <= 65535 and (cursor in used or cursor in explicit_ports):
                cursor += 1
            if cursor > 65535:
                break
            local_port = cursor
            node["local_port"] = local_port
        if local_port in used:
            continue
        used.add(local_port)

        in_tag = "in%d" % local_port
        out_tag = "p%d" % local_port
        outbound = build_outbound(node, out_tag)
        if outbound is None:
            continue

        inbounds.append(
            {
                "tag": in_tag,
                "listen": listen if listen in ("127.0.0.1", "0.0.0.0") else "127.0.0.1",
                "port": local_port,
                "protocol": "mixed" if mixed else "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        )
        outbounds.append(outbound)
        rules.append(
            {
                "type": "field",
                "inboundTag": [in_tag],
                "outboundTag": out_tag,
            }
        )
        index += 1

    if not inbounds:
        raise ValueError("没有可启用的有效节点")

    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if api_port and is_valid_port(api_port):
        config["stats"] = {}
        config["api"] = {"tag": "api", "services": ["StatsService"]}
        config["policy"] = {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        }
        config["inbounds"].append(
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            }
        )
        config["routing"]["rules"].insert(
            0, {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
        )
    # 内网/保留地址一律直连：置于 api 规则之后、各节点规则之前。
    # 直接内嵌保留地址 CIDR（等价 geoip:private），无需 geoip.dat 文件依赖
    private_rule = {
        "type": "field",
        "ip": list(PRIVATE_CIDRS),
        "outboundTag": "direct",
    }
    node_rules = config["routing"]["rules"]
    if api_port and is_valid_port(api_port):
        # api 规则必须在最前，避免 api 流量(127.0.0.1)被 private 规则截走
        api_rule, node_rules = node_rules[0], node_rules[1:]
        config["routing"]["rules"] = [api_rule, private_rule] + node_rules
    else:
        config["routing"]["rules"] = [private_rule] + node_rules
    return config


# ---------------------------------------------------------------------------
# SOCKS5 极简客户端 / 测速
# ---------------------------------------------------------------------------


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("连接已被对方关闭")
        data += chunk
    return data


def socks5_connect(local_port, host, remote_port, timeout=5.0):
    """经本地 SOCKS5 端口 CONNECT 到目标，返回已连通的 socket。"""
    if not is_valid_port(local_port):
        raise ValueError("本地端口无效")
    if not is_valid_port(remote_port):
        raise ValueError("目标端口无效")

    sock = socket.create_connection(("127.0.0.1", int(local_port)), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        head = recv_exact(sock, 2)
        if head != b"\x05\x00":
            raise OSError("SOCKS5 握手失败（不支持无认证）")

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                name = host.encode("idna")
            except UnicodeError:
                name = host.encode("utf-8")
            if not name or len(name) > 255:
                raise OSError("目标域名过长")
            address = b"\x03" + bytes([len(name)]) + name
        else:
            if ip.version == 4:
                address = b"\x01" + ip.packed
            else:
                address = b"\x04" + ip.packed

        sock.sendall(
            b"\x05\x01\x00" + address + struct.pack("!H", int(remote_port))
        )
        reply = recv_exact(sock, 4)
        if reply[0] != 0x05:
            raise OSError("SOCKS5 响应版本错误")
        if reply[1] != 0x00:
            raise OSError("SOCKS5 连接失败（代码 %d）" % reply[1])
        atyp = reply[3]
        if atyp == 0x01:
            recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
        elif atyp == 0x04:
            recv_exact(sock, 16 + 2)
        else:
            raise OSError("SOCKS5 未知地址类型")
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def test_latency(local_port, timeout=LATENCY_TIMEOUT):
    """经本地端口请求 generate_204，返回毫秒（收到 HTTP 响应头即计时）。"""
    started = time.perf_counter()
    sock = socks5_connect(local_port, LATENCY_HOST, 80, timeout)
    try:
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
            % (LATENCY_PATH, LATENCY_HOST, USER_AGENT)
        )
        sock.sendall(request.encode("ascii"))
        buffer = b""
        deadline = started + timeout
        while b"HTTP/" not in buffer:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise socket.timeout("延迟测试超时")
            sock.settimeout(remaining)
            chunk = sock.recv(1024)
            if not chunk:
                break
            buffer += chunk
        if not buffer.startswith(b"HTTP/"):
            raise OSError("未收到 HTTP 响应")
        return max(1, int(round((time.perf_counter() - started) * 1000.0)))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_download(local_port, timeout=SPEED_TIMEOUT, max_bytes=SPEED_MAX_BYTES):
    """经本地端口下载测速文件，返回字节/秒。"""
    started = time.perf_counter()
    sock = socks5_connect(local_port, SPEED_HOST, 80, timeout)
    try:
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
            % (SPEED_PATH, SPEED_HOST, USER_AGENT)
        )
        sock.sendall(request.encode("ascii"))
        buffer = b""
        deadline = started + timeout
        while b"\r\n\r\n" not in buffer:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise socket.timeout("下载测速超时")
            sock.settimeout(remaining)
            chunk = sock.recv(65536)
            if not chunk:
                break
            buffer += chunk
        if b"\r\n\r\n" not in buffer:
            raise OSError("测速响应头不完整")
        body = buffer.split(b"\r\n\r\n", 1)[1]
        total = len(body)
        while total < max_bytes:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            sock.settimeout(min(5.0, remaining))
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            total += len(chunk)
        elapsed = time.perf_counter() - started
        if total <= 0 or elapsed <= 0:
            raise OSError("未收到测速数据")
        return float(total) / elapsed
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Xray 进程守护
# ---------------------------------------------------------------------------


class XrayService(object):
    def __init__(self, on_log, on_exit):
        self._on_log = on_log
        self._on_exit = on_exit
        self._proc = None
        self._lock = threading.Lock()

    def is_running(self):
        with self._lock:
            proc = self._proc
        return bool(proc is not None and proc.poll() is None)

    def start(self, exe_path, config_path):
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                raise RuntimeError("Xray 已在运行")
            if not os.path.isfile(exe_path):
                raise RuntimeError("找不到 xray.exe：%s" % exe_path)
            if not os.path.isfile(config_path):
                raise RuntimeError("找不到 Xray 配置文件：%s" % config_path)
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.Popen(
                [exe_path, "run", "-c", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=flags,
                bufsize=0,
            )
            self._proc = proc
        thread = threading.Thread(target=self._reader_loop, args=(proc,), daemon=True)
        thread.start()

    def _reader_loop(self, proc):
        try:
            if proc.stdout is not None:
                for raw in iter(proc.stdout.readline, b""):
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if line.strip():
                        try:
                            self._on_log(line)
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            try:
                if proc.stdout is not None:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                code = proc.wait()
            except Exception:
                code = -1
            with self._lock:
                if self._proc is proc:
                    self._proc = None
            try:
                self._on_exit(code)
            except Exception:
                pass

    def stop(self):
        with self._lock:
            proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
            return
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------


def _ensure_tk():
    global tk, ttk, filedialog, messagebox, simpledialog
    if tk is not None:
        return
    import tkinter as _tk
    from tkinter import filedialog as _filedialog
    from tkinter import messagebox as _messagebox
    from tkinter import simpledialog as _simpledialog
    from tkinter import ttk as _ttk

    tk = _tk
    ttk = _ttk
    filedialog = _filedialog
    messagebox = _messagebox
    simpledialog = _simpledialog


def _enable_dpi_awareness():
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            import ctypes

            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class App(object):
    def __init__(self, root):
        self.root = root
        self.root.title("%s %s" % (APP_NAME, APP_VERSION))
        self.root.geometry("1020x700")
        self.root.minsize(860, 560)
        try:
            if os.path.isfile(ICON_PATH):
                self.root.iconbitmap(ICON_PATH)
        except Exception:
            pass

        self.q = queue.Queue()
        self.settings = load_settings()
        self.nodes = self.settings.get("nodes", [])
        self.subs = self.settings.get("subs", [])

        self.busy_test = False
        self.busy_start = False
        self.busy_stop = False
        self.busy_subs = False
        self.busy_download = False
        self._traffic_rates = {}
        self._traffic_cum = {}
        self._traffic_stop = threading.Event()
        self._api_port = None

        self.sub_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.xray_var = tk.StringVar(value=self.settings.get("xray_path") or DEFAULT_XRAY_PATH)
        self.lan_var = tk.BooleanVar(value=bool(self.settings.get("lan_access")))
        self.mixed_var = tk.BooleanVar(value=bool(self.settings.get("mixed_port")))
        self.base_port_var = tk.StringVar(
            value=str(self.settings.get("base_port") or DEFAULT_BASE_PORT)
        )

        self.service = XrayService(
            lambda line: self.q.put(("xray_log", line)),
            lambda code: self.q.put(("service_exit", code)),
        )

        self._setup_style()
        self._build_ui()
        self._refresh_sub_combo()
        changed = assign_missing_ports(self.nodes, self._base_port())
        self._refresh_tree()
        self._update_buttons()
        self._set_status("未运行", "#666666")
        if changed:
            self.save()
        self.log("程序已启动，配置文件：%s" % SETTINGS_PATH, "sys")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._pump_queue)

    # ----- 样式 / 布局 ---------------------------------------------------

    def _setup_style(self):
        self.root.option_add("*Font", ("Microsoft YaHei UI", 9))
        style = ttk.Style(self.root)
        try:
            if "vista" in style.theme_names():
                style.theme_use("vista")
        except Exception:
            pass
        try:
            style.configure(".", font=("Microsoft YaHei UI", 9))
            style.configure(
                "Treeview", rowheight=24, font=("Microsoft YaHei UI", 9)
            )
            style.configure(
                "Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold")
            )
            style.configure(
                "TLabelframe.Label", font=("Microsoft YaHei UI", 9, "bold")
            )
        except Exception:
            pass

    def _build_ui(self):
        parent = self.root

        # 1. 订阅管理
        sub_frame = ttk.LabelFrame(parent, text="订阅管理", padding=(8, 4))
        sub_frame.pack(fill="x", padx=8, pady=(8, 0))
        sub_row = ttk.Frame(sub_frame)
        sub_row.pack(fill="x")
        ttk.Label(sub_row, text="订阅:").pack(side="left")
        self.sub_combo = ttk.Combobox(
            sub_row, textvariable=self.sub_var, state="readonly", width=18
        )
        self.sub_combo.pack(side="left", padx=(4, 8))
        self.sub_combo.bind("<<ComboboxSelected>>", self._on_sub_selected)
        ttk.Label(sub_row, text="URL:").pack(side="left")
        self.url_entry = ttk.Entry(sub_row, textvariable=self.url_var)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
        ttk.Button(sub_row, text="添加订阅", command=self._add_sub).pack(
            side="left", padx=2
        )
        self.btn_update_subs = ttk.Button(
            sub_row, text="更新全部订阅", command=self._update_all_subs
        )
        self.btn_update_subs.pack(side="left", padx=2)
        ttk.Button(sub_row, text="删除选中订阅", command=self._delete_sub).pack(
            side="left", padx=2
        )

        # 2. 节点操作
        node_frame = ttk.LabelFrame(parent, text="节点操作", padding=(8, 4))
        node_frame.pack(fill="x", padx=8, pady=(6, 0))
        node_row = ttk.Frame(node_frame)
        node_row.pack(fill="x")
        ttk.Button(node_row, text="导入节点链接", command=self._open_import).pack(
            side="left", padx=2
        )
        ttk.Button(node_row, text="全选", command=lambda: self._set_all_enabled(True)).pack(
            side="left", padx=2
        )
        ttk.Button(node_row, text="清空", command=lambda: self._set_all_enabled(False)).pack(
            side="left", padx=2
        )
        self.btn_latency = ttk.Button(
            node_row, text="测延迟", command=lambda: self._run_tests("latency")
        )
        self.btn_latency.pack(side="left", padx=2)
        self.btn_speed = ttk.Button(
            node_row, text="测下载速度", command=lambda: self._run_tests("speed")
        )
        self.btn_speed.pack(side="left", padx=2)
        ttk.Button(
            node_row, text="按延迟排序", command=lambda: self._sort_nodes("latency", False)
        ).pack(side="left", padx=2)
        ttk.Button(
            node_row, text="按速度排序", command=lambda: self._sort_nodes("speed", True)
        ).pack(side="left", padx=2)
        ttk.Button(node_row, text="删除选中节点", command=self._delete_selected_nodes).pack(
            side="left", padx=2
        )

        # 3. Xray 核心控制
        xray_frame = ttk.LabelFrame(parent, text="Xray 核心控制", padding=(8, 4))
        xray_frame.pack(fill="x", padx=8, pady=(6, 0))
        xray_row1 = ttk.Frame(xray_frame)
        xray_row1.pack(fill="x")
        ttk.Label(xray_row1, text="xray.exe路径:").pack(side="left")
        self.xray_entry = ttk.Entry(xray_row1, textvariable=self.xray_var)
        self.xray_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
        self.xray_entry.bind("<FocusOut>", lambda _e: self.save())
        ttk.Button(xray_row1, text="浏览...", command=self._browse_xray).pack(
            side="left", padx=2
        )
        self.btn_download = ttk.Button(
            xray_row1, text="自动下载 xray.exe", command=self._download_xray
        )
        self.btn_download.pack(side="left", padx=2)

        xray_row2 = ttk.Frame(xray_frame)
        xray_row2.pack(fill="x", pady=(4, 0))
        ttk.Label(xray_row2, text="起始SOCKS5端口:").pack(side="left")
        self.base_port_entry = ttk.Entry(
            xray_row2, textvariable=self.base_port_var, width=7, justify="center"
        )
        self.base_port_entry.pack(side="left", padx=(4, 10))
        self.base_port_entry.bind("<FocusOut>", lambda _e: self.save())
        self.base_port_entry.bind("<Return>", lambda _e: self.save())
        self.lan_check = ttk.Checkbutton(
            xray_row2,
            text="允许局域网访问 (0.0.0.0)",
            variable=self.lan_var,
            command=self.save,
        )
        self.lan_check.pack(side="left", padx=(8, 2))
        self.mixed_check = ttk.Checkbutton(
            xray_row2,
            text="混合端口 (HTTP+SOCKS)",
            variable=self.mixed_var,
            command=self._on_mixed_toggle,
        )
        self.mixed_check.pack(side="left", padx=(8, 2))
        self.btn_start = ttk.Button(
            xray_row2, text="▶ 启动所选节点", command=self._start_selected
        )
        self.btn_start.pack(side="left", padx=2)
        self.btn_stop = ttk.Button(
            xray_row2, text="■ 停止", command=self._stop_xray, state="disabled"
        )
        self.btn_stop.pack(side="left", padx=2)
        self.status_label = tk.Label(
            xray_row2,
            text="状态: 未运行",
            fg="#666666",
            font=("Microsoft YaHei UI", 9, "bold"),
        )
        self.status_label.pack(side="left", padx=(12, 2))

        # 4. 节点表格
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=(6, 0))
        columns = (
            "chk", "name", "proto", "server", "port", "lport",
            "latency", "speed", "rt", "total",
        )
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="extended"
        )
        specs = [
            ("chk", "☑", 34, "center", False),
            ("name", "节点名称", 190, "w", True),
            ("proto", "协议", 70, "center", False),
            ("server", "服务器地址", 150, "w", False),
            ("port", "远程端口", 65, "center", False),
            ("lport", "本地SOCKS5", 80, "center", False),
            ("latency", "延迟", 76, "center", False),
            ("speed", "下载速度", 88, "center", False),
            ("rt", "实时流量", 120, "center", False),
            ("total", "累计流量", 112, "center", False),
        ]
        for cid, title, width, anchor, stretch in specs:
            self.tree.heading(cid, text=title)
            self.tree.column(cid, width=width, anchor=anchor, stretch=stretch)
        self.tree.tag_configure("off", foreground="#999999")
        self._refresh_lport_header()
        tree_scroll = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self._on_tree_double)
        self.tree.bind("<Button-3>", self._on_tree_right)

        self.root.bind("<Control-l>", lambda _e: self._show_log_window())
        self.root.bind("<Control-L>", lambda _e: self._show_log_window())

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="复制分享链接", command=self._copy_link)
        self.menu.add_command(label="复制 SOCKS5 地址", command=self._copy_socks)
        self.menu.add_separator()
        self.menu.add_command(label="删除选中节点", command=self._delete_selected_nodes)

        # 5. 底部状态栏：日志按钮 + 全部端口实时总流量
        bottom_bar = ttk.Frame(parent)
        bottom_bar.pack(fill="x", padx=8, pady=(6, 8))
        ttk.Button(bottom_bar, text="运行日志", command=self._show_log_window).pack(
            side="left"
        )
        self.traffic_var = tk.StringVar(value="")
        traffic_label = tk.Label(
            bottom_bar,
            textvariable=self.traffic_var,
            fg="#28A745",
            font=("Consolas", 9, "bold"),
        )
        traffic_label.pack(side="right")

        self._build_log_window()

    def _build_log_window(self):
        """运行日志弹窗（常驻隐藏，保证关闭弹窗后日志仍在累积）。"""
        win = tk.Toplevel(self.root)
        win.title("运行日志 - %s %s" % (APP_NAME, APP_VERSION))
        win.geometry("880x460")
        win.withdraw()
        self.log_win = win
        body = ttk.Frame(win, padding=(6, 6))
        body.pack(fill="both", expand=True)
        self.log_text = tk.Text(
            body,
            height=20,
            font=("Consolas", 9),
            bg="#1E1E1E",
            fg="#D4D4D4",
            state="disabled",
            wrap="none",
            relief="flat",
            borderwidth=0,
        )
        log_scroll = ttk.Scrollbar(
            body, orient="vertical", command=self.log_text.yview
        )
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        self.log_text.tag_configure("err", foreground="#F44747")
        self.log_text.tag_configure("ok", foreground="#4EC9B0")
        self.log_text.tag_configure("sys", foreground="#888888")
        bar = ttk.Frame(win, padding=(6, 0, 6, 6))
        bar.pack(fill="x")
        ttk.Label(
            bar, text="提示：日志上限 1500 行，超出自动丢弃最早内容", foreground="#666666"
        ).pack(side="left")
        ttk.Button(bar, text="保存日志", command=self._save_log).pack(
            side="right", padx=4
        )
        ttk.Button(bar, text="清空", command=self._clear_log).pack(
            side="right", padx=4
        )
        ttk.Button(bar, text="关闭", command=win.withdraw).pack(side="right", padx=4)
        win.protocol("WM_DELETE_WINDOW", win.withdraw)

    def _show_log_window(self):
        try:
            self.log_win.deiconify()
            self.log_win.lift()
            self.log_text.see("end")
        except Exception:
            pass

    def _save_log(self):
        try:
            content = self.log_text.get("1.0", "end").strip("\n")
        except Exception:
            return
        filename = filedialog.asksaveasfilename(
            title="保存运行日志",
            defaultextension=".log",
            initialfile="xray_log_%s.log" % time.strftime("%Y%m%d_%H%M%S"),
            filetypes=[
                ("日志文件", "*.log"),
                ("文本文件", "*.txt"),
                ("所有文件", "*.*"),
            ],
        )
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as fh:
                fh.write(content + "\n")
            self.log("日志已保存：%s" % filename, "ok")
        except Exception as exc:
            self.log("保存日志失败：%s" % exc, "err")

    def _clear_log(self):
        try:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass

    # ----- 通用 UI 辅助 --------------------------------------------------

    def _base_port(self):
        port = to_int(self.base_port_var.get())
        if not is_valid_port(port):
            port = DEFAULT_BASE_PORT
            self.base_port_var.set(str(port))
        return port

    def _set_status(self, text, color):
        self.status_label.configure(
            text="状态: " + text,
            fg=color,
            font=("Microsoft YaHei UI", 9, "bold"),
        )

    def _update_buttons(self):
        running = self.service.is_running()
        self.btn_start.configure(
            state="disabled" if (running or self.busy_start) else "normal"
        )
        self.btn_stop.configure(
            state="normal" if (running and not self.busy_stop) else "disabled"
        )
        test_state = "disabled" if self.busy_test else "normal"
        self.btn_latency.configure(state=test_state)
        self.btn_speed.configure(state=test_state)
        self.btn_update_subs.configure(
            state="disabled" if self.busy_subs else "normal"
        )
        self.btn_download.configure(
            state="disabled" if self.busy_download else "normal"
        )

    def log(self, message, tag="sys"):
        self.q.put(("log", message, tag))

    def _auto_tag(self, line):
        low = str(line).lower()
        if any(
            word in low
            for word in ("error", "failed", "fail", "fatal", "warning", "refused", "invalid")
        ):
            return "err"
        if any(word in low for word in ("started", "listening", "ok")):
            return "ok"
        return "sys"

    def _append_log(self, message, tag="sys"):
        try:
            self.log_text.configure(state="normal")
            timestamp = time.strftime("%H:%M:%S")
            self.log_text.insert(
                "end", "[%s] %s\n" % (timestamp, redact(message)), tag
            )
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > MAX_LOG_LINES:
                self.log_text.delete("1.0", "%d.0" % (lines - MAX_LOG_LINES))
            self.log_text.configure(state="disabled")
            self.log_text.see("end")
        except Exception:
            pass

    def _pump_queue(self):
        try:
            while True:
                event = self.q.get_nowait()
                try:
                    self._handle_event(event)
                except Exception as exc:
                    self._append_log("处理事件失败：%s" % exc, "err")
        except queue.Empty:
            pass
        except Exception:
            pass
        try:
            self.root.after(80, self._pump_queue)
        except Exception:
            pass

    def _handle_event(self, event):
        kind = event[0]
        if kind == "log":
            self._append_log(event[1], event[2] if len(event) > 2 else "sys")
        elif kind == "xray_log":
            line = event[1]
            self._append_log(line, self._auto_tag(line))
        elif kind == "service_exit":
            self.busy_start = False
            self.busy_stop = False
            code = event[1]
            self._set_status("已停止（退出码 %s）" % code, "#666666")
            self._append_log(
                "Xray 进程已退出，退出码 %s" % code, "sys" if code == 0 else "err"
            )
            self._reset_traffic_display()
            self._update_buttons()
        elif kind == "started":
            self.busy_start = False
            if self.service.is_running():
                self._set_status("运行中（%d 个节点）" % event[1], "#28A745")
                self._append_log("Xray 启动成功，共 %d 个代理端口" % event[1], "ok")
            else:
                self._set_status("未运行", "#666666")
                self._append_log("Xray 启动后立即退出，请检查日志", "err")
            self._update_buttons()
        elif kind == "start_failed":
            self.busy_start = False
            self._set_status("未运行", "#666666")
            self._append_log("启动失败：%s" % event[1], "err")
            self._reset_traffic_display()
            self._update_buttons()
            messagebox.showerror("启动失败", str(event[1]))
        elif kind == "stopped":
            self.busy_stop = False
            if not self.service.is_running():
                self._set_status("未运行", "#666666")
            self._reset_traffic_display()
            self._update_buttons()
        elif kind == "traffic":
            rates, cum, total_rate = event[1], event[2], event[3]
            self._traffic_rates = rates
            self._traffic_cum = cum
            self.traffic_var.set(
                "全部端口实时流量  ↑%s/s ↓%s/s"
                % (fmt_bytes(total_rate["up"]), fmt_bytes(total_rate["down"]))
            )
            changed = set(rates) | set(cum)
            for node in self.nodes:
                if node.get("local_port") in changed:
                    self._update_row(node)
        elif kind == "subs_done":
            self.busy_subs = False
            self._apply_sub_updates(event[1])
            self._update_buttons()
        elif kind == "test_result":
            mode, nid, value = event[1], event[2], event[3]
            node = self._node_by_nid(nid)
            if node is not None:
                if value is None:
                    node["latency" if mode == "latency" else "speed"] = "超时"
                elif mode == "latency":
                    node["latency"] = int(value)
                else:
                    node["speed"] = float(value)
                self._update_row(node)
        elif kind == "test_done":
            mode, ok, fail = event[1], event[2], event[3]
            self.busy_test = False
            self.save()
            self._append_log(
                "%s完成：成功 %d，超时/失败 %d"
                % ("延迟测试" if mode == "latency" else "下载测速", ok, fail),
                "ok" if ok else "err",
            )
            self._update_buttons()
        elif kind == "download_done":
            self.busy_download = False
            self.xray_var.set(event[1])
            self.save()
            self._update_buttons()
            self._append_log("xray.exe 已下载到：%s" % event[1], "ok")
            messagebox.showinfo("下载完成", "xray.exe 已保存到程序目录。")
        elif kind == "download_failed":
            self.busy_download = False
            self._update_buttons()
            self._append_log("自动下载失败：%s" % event[1], "err")
            messagebox.showerror(
                "下载失败",
                "自动下载失败：%s\n\n请手动打开\n"
                "https://github.com/XTLS/Xray-core/releases\n"
                "下载 Xray-windows-64.zip，解压出 xray.exe 放到程序目录。" % event[1],
            )

    # ----- 数据 / 表格 ---------------------------------------------------

    def _reset_traffic_display(self):
        self._traffic_stop.set()
        self._traffic_rates = {}
        self._traffic_cum = {}
        try:
            self.traffic_var.set("")
        except Exception:
            pass
        for node in self.nodes:
            self._update_row(node)

    def _start_traffic_poller(self, xray_path, api_port):
        self._traffic_stop.set()
        self._traffic_stop = threading.Event()
        threading.Thread(
            target=self._traffic_worker,
            args=(xray_path, int(api_port)),
            daemon=True,
        ).start()

    def _traffic_worker(self, xray_path, api_port):
        """每秒查询一次 Xray stats API，计算各端口实时速率与累计流量。"""
        last = {}
        last_time = time.time()
        while not self._traffic_stop.is_set():
            time.sleep(1.0)
            if self._traffic_stop.is_set() or not self.service.is_running():
                break
            try:
                cmd = [
                    xray_path,
                    "api",
                    "statsquery",
                    "--server=127.0.0.1:%d" % api_port,
                    "-pattern",
                    "",
                ]
                run = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                cur = parse_traffic_payload(run.stdout.decode("utf-8", "replace"))
            except Exception:
                continue
            now = time.time()
            interval = max(0.3, now - last_time)
            last_time = now
            rates = {}
            for port, item in cur.items():
                prev = last.get(port)
                if prev:
                    rates[port] = {
                        "up": max(0.0, (item["up"] - prev["up"]) / interval),
                        "down": max(0.0, (item["down"] - prev["down"]) / interval),
                    }
                else:
                    rates[port] = {"up": 0.0, "down": 0.0}
            last = cur
            total_rate = {
                "up": sum(item["up"] for item in rates.values()),
                "down": sum(item["down"] for item in rates.values()),
            }
            self.q.put(("traffic", rates, cur, total_rate))

    def _node_by_nid(self, nid):
        for node in self.nodes:
            if node.get("nid") == nid:
                return node
        return None

    def _selected_nodes(self):
        result = []
        for iid in self.tree.selection():
            node = self._node_by_nid(iid)
            if node is not None:
                result.append(node)
        return result

    def _row_values(self, node):
        latency = node.get("latency")
        if isinstance(latency, bool) or not isinstance(latency, (int, float)):
            latency_text = str(latency) if latency else ""
        else:
            latency_text = "%d ms" % int(latency)
        speed = node.get("speed")
        if isinstance(speed, bool) or not isinstance(speed, (int, float)):
            speed_text = str(speed) if speed else ""
        else:
            speed_text = format_speed(speed)
        local_port = node.get("local_port")
        rates = self._traffic_rates.get(local_port)
        cum = self._traffic_cum.get(local_port)
        if rates and (rates["up"] or rates["down"]):
            rt_text = fmt_traffic(rates["up"], rates["down"], per_second=True)
        else:
            rt_text = "—"
        if cum and (cum["up"] or cum["down"]):
            total_text = fmt_traffic(cum["up"], cum["down"])
        else:
            total_text = "—"
        return (
            "☑" if node.get("enabled") else "☐",
            node.get("name") or "",
            node.get("proto") or "",
            node.get("server") or "",
            str(node.get("port") or ""),
            str(local_port) if local_port else "",
            latency_text,
            speed_text,
            rt_text,
            total_text,
        )

    def _refresh_tree(self):
        selected = set(self.tree.selection())
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        for node in self.nodes:
            tags = () if node.get("enabled") else ("off",)
            self.tree.insert(
                "",
                "end",
                iid=node["nid"],
                values=self._row_values(node),
                tags=tags,
            )
        for iid in selected:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)

    def _update_row(self, node):
        iid = node.get("nid")
        if not iid or not self.tree.exists(iid):
            return
        tags = () if node.get("enabled") else ("off",)
        self.tree.item(iid, values=self._row_values(node), tags=tags)

    def _refresh_sub_combo(self):
        names = [sub.get("name") for sub in self.subs]
        self.sub_combo.configure(values=names)
        current = self.sub_var.get()
        if current not in names:
            if self.subs:
                self.sub_var.set(self.subs[0]["name"])
                self.url_var.set(self.subs[0]["url"])
            else:
                self.sub_var.set("")
                self.url_var.set("")

    def _on_sub_selected(self, _event=None):
        name = self.sub_var.get()
        for sub in self.subs:
            if sub.get("name") == name:
                self.url_var.set(sub.get("url") or "")
                break

    # ----- 订阅管理 ------------------------------------------------------

    def _add_sub(self):
        url = self.url_var.get().strip()
        try:
            parsed = urllib.parse.urlparse(url)
            valid = parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)
        except Exception:
            valid = False
        if not valid:
            messagebox.showwarning("订阅地址无效", "订阅 URL 必须以 http:// 或 https:// 开头。")
            return
        if any(sub.get("url") == url for sub in self.subs):
            messagebox.showinfo("提示", "该订阅已存在。")
            return
        base_name = (parsed.hostname or "订阅").strip() or "订阅"
        name = base_name
        index = 2
        while any(sub.get("name") == name for sub in self.subs):
            name = "%s-%d" % (base_name, index)
            index += 1
        self.subs.append({"name": name, "url": url})
        self._refresh_sub_combo()
        self.sub_var.set(name)
        self.url_var.set(url)
        self.save()
        self.log("已添加订阅「%s」，请点击 [更新全部订阅] 拉取节点。" % name, "ok")

    def _delete_sub(self):
        name = self.sub_var.get().strip()
        sub = None
        for item in self.subs:
            if item.get("name") == name:
                sub = item
                break
        if sub is None:
            messagebox.showinfo("提示", "请先在下拉框中选择要删除的订阅。")
            return
        if not messagebox.askyesno(
            "删除订阅", "确定删除订阅「%s」及其全部节点吗？" % name
        ):
            return
        url = sub.get("url")
        self.subs = [item for item in self.subs if item is not sub]
        before = len(self.nodes)
        self.nodes = [node for node in self.nodes if node.get("sub") != url]
        removed = before - len(self.nodes)
        self._refresh_sub_combo()
        self._refresh_tree()
        self.save()
        self.log("已删除订阅「%s」及 %d 个节点" % (name, removed), "ok")

    def _update_all_subs(self):
        if self.busy_subs:
            return
        if not self.subs:
            messagebox.showinfo("提示", "还没有订阅，请先添加。")
            return
        self.busy_subs = True
        self._update_buttons()
        snapshot = [dict(sub) for sub in self.subs]
        self.log("开始更新 %d 个订阅..." % len(snapshot), "sys")
        thread = threading.Thread(target=self._subs_worker, args=(snapshot,), daemon=True)
        thread.start()

    def _subs_worker(self, subs):
        results = []
        try:
            for sub in subs:
                name = sub.get("name") or sub.get("url")
                url = sub.get("url") or ""
                self.q.put(("log", "正在更新订阅「%s」..." % name, "sys"))
                try:
                    text = fetch_subscription(url)
                    nodes, failed = parse_subscription_text(text)
                    results.append((sub, nodes, failed, None))
                    if nodes:
                        self.q.put(
                            (
                                "log",
                                "订阅「%s」解析到 %d 个节点%s"
                                % (
                                    name,
                                    len(nodes),
                                    "，跳过 %d 行" % failed if failed else "",
                                ),
                                "ok",
                            )
                        )
                    else:
                        self.q.put(
                            ("log", "订阅「%s」没有解析到节点，保留原节点" % name, "err")
                        )
                except Exception as exc:
                    results.append((sub, [], 0, str(exc)))
                    self.q.put(("log", "订阅「%s」更新失败：%s" % (name, exc), "err"))
        finally:
            self.q.put(("subs_done", results))

    def _apply_sub_updates(self, results):
        total_added = 0
        total_removed = 0
        total_skipped = 0
        for sub, new_nodes, failed, error in results:
            if error or not new_nodes:
                continue
            url = sub.get("url") or ""
            self.nodes, added, removed, skipped = merge_subscription_nodes(
                self.nodes, url, new_nodes
            )
            total_added += added
            total_removed += removed
            total_skipped += skipped
        assign_missing_ports(self.nodes, self._base_port())
        self._refresh_tree()
        self.save()
        if results:
            self.log(
                "订阅更新完成：新增 %d，移除 %d，重复跳过 %d"
                % (total_added, total_removed, total_skipped),
                "ok",
            )

    # ----- 节点操作 ------------------------------------------------------

    def _open_import(self):
        win = tk.Toplevel(self.root)
        win.title("导入节点链接")
        win.geometry("640x420")
        win.minsize(480, 320)
        win.transient(self.root)
        win.grab_set()

        # 按钮栏先打包（side=bottom），避免被 expand 的文本区挤出窗口外
        buttons = ttk.Frame(win)
        buttons.pack(side="bottom", fill="x", padx=8, pady=(0, 8))
        ttk.Label(
            buttons, text="每行一个分享链接，也支持整段 Base64 订阅内容；按回车导入"
        ).pack(side="left")

        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        text = tk.Text(
            frame, wrap="word", font=("Consolas", 9), undo=True, height=12
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        def do_import(event=None):
            raw = text.get("1.0", "end")
            added, skipped, failed = self._import_links_text(raw)
            if added > 0:
                win.destroy()
            return "break"

        ttk.Button(buttons, text="关闭", command=win.destroy).pack(
            side="right", padx=4
        )
        ttk.Button(buttons, text="导入", command=do_import).pack(
            side="right", padx=4
        )
        text.bind("<Return>", do_import)
        win.bind("<Escape>", lambda event: win.destroy())
        text.focus_set()

    def _import_links_text(self, raw):
        nodes, failed = parse_subscription_text(raw)
        if not nodes:
            messagebox.showwarning(
                "导入失败", "没有解析到有效节点，请检查链接格式。"
            )
            self.log("导入失败：没有解析到有效节点", "err")
            return 0, 0, failed

        keys = set(node_key(node) for node in self.nodes)
        added = 0
        skipped = 0
        base_port = self._base_port()
        for node in nodes:
            key = node_key(node)
            if key in keys:
                skipped += 1
                continue
            port = next_free_port(self.nodes, base_port)
            if port is None:
                self.log("没有可用的本地端口，停止导入", "err")
                break
            node["local_port"] = port
            node["enabled"] = False
            node["sub"] = ""
            self.nodes.append(node)
            keys.add(key)
            added += 1

        if added:
            self._refresh_tree()
            self.save()
        self.log(
            "导入完成：新增 %d，重复跳过 %d，解析失败 %d"
            % (added, skipped, failed),
            "ok" if added else "sys",
        )
        return added, skipped, failed

    def _set_all_enabled(self, enabled):
        for node in self.nodes:
            node["enabled"] = bool(enabled)
        self._refresh_tree()
        self.save()
        self.log("已%s全部节点" % ("勾选" if enabled else "取消勾选"), "sys")

    def _delete_selected_nodes(self):
        selected = self._selected_nodes()
        if not selected:
            messagebox.showinfo("提示", "请先在列表中选中节点。")
            return
        if not messagebox.askyesno(
            "删除节点", "确定删除选中的 %d 个节点吗？" % len(selected)
        ):
            return
        ids = set(node["nid"] for node in selected)
        self.nodes = [node for node in self.nodes if node.get("nid") not in ids]
        self._refresh_tree()
        self.save()
        self.log("已删除 %d 个节点" % len(ids), "ok")

    def _sort_nodes(self, field, reverse):
        def sort_key(node):
            value = node.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return (1, 0.0)
            number = float(value)
            return (0, -number if reverse else number)

        self.nodes.sort(key=sort_key)
        self._refresh_tree()
        self.save()
        self.log(
            "已按%s排序" % ("延迟升序" if field == "latency" else "速度降序"), "sys"
        )

    # ----- 表格交互 ------------------------------------------------------

    def _on_tree_click(self, event):
        try:
            if self.tree.identify_region(event.x, event.y) != "cell":
                return None
            if self.tree.identify_column(event.x) != "#1":
                return None
            iid = self.tree.identify_row(event.y)
            node = self._node_by_nid(iid)
            if node is None:
                return None
            node["enabled"] = not bool(node.get("enabled"))
            self._update_row(node)
            self.save()
            return "break"
        except Exception:
            return None

    def _on_tree_double(self, event):
        try:
            if self.tree.identify_column(event.x) != "#6":
                return None
            iid = self.tree.identify_row(event.y)
            node = self._node_by_nid(iid)
            if node is None:
                return None
            current = node.get("local_port") or ""
            value = simpledialog.askstring(
                "修改本地端口",
                "请输入 1-65535 的本地 SOCKS5 端口：",
                initialvalue=str(current),
                parent=self.root,
            )
            if value is None:
                return "break"
            port = to_int(value)
            if not is_valid_port(port):
                messagebox.showwarning("端口无效", "端口必须是 1-65535 的整数。")
                return "break"
            for other in self.nodes:
                if other is node:
                    continue
                if to_int(other.get("local_port")) == port:
                    messagebox.showwarning(
                        "端口冲突", "端口 %d 已被节点「%s」占用。" % (port, other.get("name"))
                    )
                    return "break"
            node["local_port"] = port
            self._update_row(node)
            self.save()
            self.log(
                "节点「%s」本地端口已改为 %d%s"
                % (
                    node.get("name"),
                    port,
                    "（需重启 Xray 生效）" if self.service.is_running() else "",
                ),
                "sys",
            )
        except Exception as exc:
            self.log("修改端口失败：%s" % exc, "err")
        return "break"

    def _on_tree_right(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return "break"
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            try:
                self.menu.grab_release()
            except Exception:
                pass
        return "break"

    def _copy_link(self):
        nodes = self._selected_nodes()
        if not nodes:
            return
        node = nodes[0]
        link = node.get("link") or ""
        if not link:
            self.log("节点「%s」没有原始分享链接" % node.get("name"), "err")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(link)
        self.root.update_idletasks()
        self.log("已复制节点「%s」的分享链接" % node.get("name"), "ok")

    def _copy_socks(self):
        nodes = self._selected_nodes()
        if not nodes:
            return
        node = nodes[0]
        port = to_int(node.get("local_port"))
        if not is_valid_port(port):
            self.log("节点「%s」还没有本地端口" % node.get("name"), "err")
            return
        address = "127.0.0.1:%d" % port
        self.root.clipboard_clear()
        self.root.clipboard_append(address)
        self.root.update_idletasks()
        self.log("已复制 SOCKS5 地址 %s" % address, "ok")

    # ----- 核心控制 ------------------------------------------------------

    def _browse_xray(self):
        path = filedialog.askopenfilename(
            title="选择 xray.exe",
            filetypes=[
                ("Xray 核心", "xray.exe"),
                ("可执行文件", "*.exe"),
                ("所有文件", "*.*"),
            ],
        )
        if path:
            self.xray_var.set(path)
            self.save()
            self.log("已选择 xray.exe：%s" % path, "sys")

    def _start_selected(self):
        if self.busy_start or self.service.is_running():
            return
        enabled = [node for node in self.nodes if node.get("enabled")]
        if not enabled:
            messagebox.showwarning("提示", "请先勾选要启动的节点（点击行首 ☐）。")
            return
        base_port = self._base_port()
        listen = "0.0.0.0" if self.lan_var.get() else "127.0.0.1"
        mixed = bool(self.mixed_var.get())
        valid, warnings = prepare_nodes_for_config(enabled, base_port)
        api_port = None
        if valid:
            try:
                api_port = next_free_port(valid, base_port)
            except Exception:
                api_port = None
            if api_port is None:
                self.log("未能为流量统计分配 API 端口，本次启动不显示流量", "err")
        self._api_port = api_port
        for warning in warnings:
            self.log(warning, "err")
        if not valid:
            messagebox.showerror(
                "无法启动", "没有可用节点：本地端口冲突或被其它程序占用。"
            )
            return
        xray_path = self.xray_var.get().strip() or DEFAULT_XRAY_PATH
        if not os.path.isfile(xray_path):
            messagebox.showerror(
                "找不到 xray.exe",
                "未找到：%s\n\n请点 [自动下载 xray.exe]，或手动把 xray.exe 放到程序目录。"
                % xray_path,
            )
            return
        self.save()
        self._refresh_tree()
        snapshot = [dict(node) for node in valid]
        self.busy_start = True
        self._update_buttons()
        self.log("正在启动 Xray，共 %d 个节点..." % len(snapshot), "sys")
        thread = threading.Thread(
            target=self._start_worker,
            args=(snapshot, base_port, xray_path, listen, mixed, api_port),
            daemon=True,
        )
        thread.start()

    def _start_worker(
        self,
        snapshot,
        base_port,
        xray_path,
        listen="127.0.0.1",
        mixed=False,
        api_port=None,
    ):
        try:
            if not os.path.isfile(xray_path):
                raise RuntimeError("找不到 xray.exe：%s" % xray_path)
            busy_ports = [
                node.get("local_port")
                for node in snapshot
                if not is_port_free(node.get("local_port"))
            ]
            if busy_ports:
                raise RuntimeError(
                    "本地端口已被占用：%s" % ", ".join(str(p) for p in busy_ports)
                )
            config = build_xray_config(snapshot, base_port, listen, mixed, api_port)
            atomic_write_json(CONFIG_PATH, config)
            self.service.start(xray_path, CONFIG_PATH)
            time.sleep(0.35)
            if not self.service.is_running():
                raise RuntimeError("Xray 启动后立即退出，请查看日志")
            for node in snapshot:
                scheme = "mixed socks5+http" if mixed else "socks5"
                self.q.put(
                    (
                        "log",
                        "%s://%s:%s ← %s"
                        % (scheme, listen, node.get("local_port"), node.get("name")),
                        "ok",
                    )
                )
            if listen == "0.0.0.0":
                lan_ip = get_lan_ip()
                self.q.put(
                    (
                        "log",
                        "已允许局域网访问：局域网设备请使用 socks5://%s:端口"
                        % (lan_ip or "<本机局域网IP>"),
                        "ok",
                    )
                )
                self.q.put(
                    (
                        "log",
                        "提示：如局域网设备无法连接，请在 Windows 防火墙放行 xray.exe 入站",
                        "sys",
                    )
                )
            if api_port and is_valid_port(api_port):
                self._start_traffic_poller(xray_path, api_port)
            self.q.put(("started", len(snapshot)))
        except Exception as exc:
            self.q.put(("start_failed", str(exc)))

    def _stop_xray(self):
        if self.busy_stop or not self.service.is_running():
            return
        self.busy_stop = True
        self._update_buttons()
        self.log("正在停止 Xray...", "sys")
        thread = threading.Thread(target=self._stop_worker, daemon=True)
        thread.start()

    def _stop_worker(self):
        try:
            self.service.stop()
        except Exception as exc:
            self.q.put(("log", "停止失败：%s" % exc, "err"))
        finally:
            self.q.put(("stopped",))

    # ----- 测试 ----------------------------------------------------------

    @staticmethod
    def _test_one(mode, port):
        try:
            if mode == "latency":
                return test_latency(port)
            return test_download(port)
        except Exception:
            return None

    def _run_tests(self, mode):
        if self.busy_test:
            return
        if not self.service.is_running():
            messagebox.showwarning(
                "提示", "请先启动 Xray（勾选节点后点 [▶ 启动所选节点]）。"
            )
            return
        targets = []
        for node in self.nodes:
            if not node.get("enabled"):
                continue
            port = to_int(node.get("local_port"))
            if is_valid_port(port):
                targets.append((node["nid"], port))
        if not targets:
            messagebox.showinfo("提示", "没有已勾选且端口有效的节点。")
            return
        self.busy_test = True
        self._update_buttons()
        self.log(
            "开始%s，共 %d 个节点..."
            % ("延迟测试" if mode == "latency" else "下载测速", len(targets)),
            "sys",
        )
        thread = threading.Thread(
            target=self._test_worker, args=(mode, targets), daemon=True
        )
        thread.start()

    def _test_worker(self, mode, targets):
        ok = 0
        fail = 0
        try:
            workers = min(6, max(1, len(targets)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {}
                for nid, port in targets:
                    futures[pool.submit(self._test_one, mode, port)] = nid
                for future in as_completed(futures):
                    nid = futures[future]
                    try:
                        value = future.result()
                    except Exception:
                        value = None
                    if value is None:
                        fail += 1
                    else:
                        ok += 1
                    self.q.put(("test_result", mode, nid, value))
        except Exception as exc:
            self.q.put(("log", "测速任务异常：%s" % exc, "err"))
        finally:
            self.q.put(("test_done", mode, ok, fail))

    # ----- 下载 xray.exe -------------------------------------------------

    def _download_xray(self):
        if self.busy_download:
            return
        self.busy_download = True
        self._update_buttons()
        self.log("正在获取 Xray-core 最新版本信息...", "sys")
        thread = threading.Thread(target=self._download_worker, daemon=True)
        thread.start()

    def _download_worker(self):
        zip_tmp = os.path.join(APP_DIR, ".xray_download.zip")
        exe_tmp = os.path.join(APP_DIR, ".xray_download.exe")
        target = os.path.join(APP_DIR, "xray.exe")
        try:
            api = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
            request = urllib.request.Request(
                api,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(request, timeout=SUB_TIMEOUT) as response:
                release = json.loads(decode_bytes(response.read()))

            asset = None
            for item in release.get("assets") or []:
                name = str(item.get("name") or "").lower()
                if "windows-64" in name and name.endswith(".zip"):
                    asset = item
                    break
            if asset is None:
                raise RuntimeError("最新版本中没有 windows-64 的 zip 资产")
            url = asset.get("browser_download_url")
            if not url:
                raise RuntimeError("下载地址为空")

            self.q.put(("log", "正在下载 %s ..." % asset.get("name"), "sys"))
            last_report = 0.0
            downloaded = 0
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=SUB_TIMEOUT) as response:
                total = to_int(response.headers.get("Content-Length"), 0) or 0
                with open(zip_tmp, "wb") as fh:
                    while True:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        fh.write(chunk)
                        downloaded += len(chunk)
                        now = time.time()
                        if now - last_report >= 1.0:
                            last_report = now
                            if total:
                                message = "下载中 %.1f / %.1f MB" % (
                                    downloaded / 1048576.0,
                                    total / 1048576.0,
                                )
                            else:
                                message = "下载中 %.1f MB" % (
                                    downloaded / 1048576.0
                                )
                            self.q.put(("log", message, "sys"))
            if downloaded <= 0:
                raise RuntimeError("下载内容为空")

            with zipfile.ZipFile(zip_tmp) as archive:
                member = None
                for name in archive.namelist():
                    if name.lower().endswith("xray.exe"):
                        member = name
                        break
                if member is None:
                    raise RuntimeError("压缩包中未找到 xray.exe")
                with archive.open(member) as source:
                    with open(exe_tmp, "wb") as dest:
                        shutil.copyfileobj(source, dest, 1024 * 1024)
            os.replace(exe_tmp, target)
            self.q.put(("download_done", target))
        except Exception as exc:
            self.q.put(("download_failed", str(exc)))
        finally:
            for path in (zip_tmp, exe_tmp):
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass

    # ----- 持久化 / 关窗 -------------------------------------------------

    def _on_mixed_toggle(self):
        self.save()
        self._refresh_lport_header()

    def _refresh_lport_header(self):
        try:
            mixed = bool(self.mixed_var.get())
        except Exception:
            mixed = False
        try:
            self.tree.heading(
                "lport", text="本地端口(HTTP+SOCKS)" if mixed else "本地SOCKS5"
            )
        except Exception:
            pass

    def save(self):
        data = {
            "xray_path": self.xray_var.get().strip() or DEFAULT_XRAY_PATH,
            "base_port": self._base_port(),
            "lan_access": bool(self.lan_var.get()),
            "mixed_port": bool(self.mixed_var.get()),
            "subs": [dict(sub) for sub in self.subs],
            "nodes": self.nodes,
        }
        try:
            atomic_write_json(SETTINGS_PATH, data)
        except Exception as exc:
            try:
                self.log("保存配置失败：%s" % exc, "err")
            except Exception:
                pass

    def _on_close(self):
        try:
            if self.service.is_running():
                self.log("正在停止 Xray 并保存配置...", "sys")
                self.service.stop()
        except Exception:
            pass
        self.save()
        try:
            self.root.destroy()
        except Exception:
            pass


def run_gui():
    _ensure_tk()
    _enable_dpi_awareness()
    try:
        root = tk.Tk()
    except Exception as exc:
        print("无法创建窗口：%s" % exc, file=sys.stderr)
        return 1
    App(root)
    root.mainloop()
    return 0


# ---------------------------------------------------------------------------
# 自检 / 入口
# ---------------------------------------------------------------------------


def _expect(condition, message):
    if not condition:
        raise AssertionError(message)


def selftest():
    """纯逻辑自测：不联网、不加载 tkinter。"""
    checks = []

    def check(name):
        def decorator(func):
            checks.append((name, func))
            return func

        return decorator

    vm_uuid = "11111111-2222-3333-4444-555555555555"
    vl_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    vm_obj = {
        "v": "2",
        "ps": "VMess-测试",
        "add": "vm.example.com",
        "port": "443",
        "id": vm_uuid,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "cdn.example.com",
        "fp": "chrome",
    }
    vm_link = "vmess://" + base64.b64encode(
        json.dumps(vm_obj, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    vl_link = (
        "vless://%s@[2001:db8::1]:443?encryption=none&security=reality"
        "&sni=www.example.com&fp=chrome&pbk=PUBKEY123&sid=abcd"
        "&flow=xtls-rprx-vision&type=tcp#VLESS%%20REALITY" % vl_uuid
    )
    tr_link = (
        "trojan://p%40ss%3Aword@trojan.example.com:443?sni=t.example.com"
        "&type=ws&path=%2Ftr#TROJAN%20%2B"
    )
    ss_legacy_raw = "aes-256-gcm:p@ss@1.2.3.4:8388"
    ss_legacy = "ss://" + base64.urlsafe_b64encode(
        ss_legacy_raw.encode("utf-8")
    ).decode("ascii").rstrip("=") + "#SS%20Legacy"
    ss_userinfo = base64.urlsafe_b64encode(
        "chacha20-ietf-poly1305:p@ss".encode("utf-8")
    ).decode("ascii").rstrip("=")
    ss_sip = "ss://%s@ss.example.com:8443#SS%%20SIP002" % ss_userinfo

    @check("vmess 链接解析")
    def _check_vmess():
        node = parse_share_link(vm_link)
        _expect(node is not None, "vmess 解析失败")
        _expect(node["proto"] == "vmess", "协议错误")
        _expect(node["server"] == "vm.example.com", "服务器错误")
        _expect(node["port"] == 443, "端口错误")
        _expect(node["uuid"] == vm_uuid, "uuid 错误")
        _expect(node["alter_id"] == 0, "alterId 错误")
        _expect(node["network"] == "ws", "network 错误")
        _expect(node["tls"] == "tls", "tls 错误")
        _expect(node["sni"] == "cdn.example.com", "sni 错误")
        _expect(node["link"] == vm_link, "原始链接未保存")

    @check("vless REALITY / IPv6 链接解析")
    def _check_vless():
        node = parse_share_link(vl_link)
        _expect(node is not None, "vless 解析失败")
        _expect(node["server"] == "2001:db8::1", "IPv6 主机错误")
        _expect(node["tls"] == "reality", "reality 未识别")
        _expect(node["pbk"] == "PUBKEY123", "publicKey 错误")
        _expect(node["sid"] == "abcd", "shortId 错误")
        _expect(node["fp"] == "chrome", "fingerprint 错误")
        _expect(node["flow"] == "xtls-rprx-vision", "flow 错误")
        _expect(node["name"] == "VLESS REALITY", "fragment 解码错误")

    @check("trojan 百分号编码密码解析")
    def _check_trojan():
        node = parse_share_link(tr_link)
        _expect(node is not None, "trojan 解析失败")
        _expect(node["password"] == "p@ss:word", "密码解码错误")
        _expect(node["tls"] == "tls", "trojan 默认 TLS 错误")
        _expect(node["network"] == "ws", "network 错误")
        _expect(node["path"] == "/tr", "path 解码错误")
        _expect(node["name"] == "TROJAN +", "fragment 解码错误")

    @check("ss legacy / SIP002 解析")
    def _check_ss():
        legacy = parse_share_link(ss_legacy)
        _expect(legacy is not None, "ss legacy 解析失败")
        _expect(legacy["method"] == "aes-256-gcm", "legacy method 错误")
        _expect(legacy["password"] == "p@ss", "legacy password 错误")
        _expect(legacy["server"] == "1.2.3.4", "legacy host 错误")
        _expect(legacy["port"] == 8388, "legacy port 错误")
        _expect(legacy["name"] == "SS Legacy", "legacy 名称错误")

        sip = parse_share_link(ss_sip)
        _expect(sip is not None, "ss SIP002 解析失败")
        _expect(sip["method"] == "chacha20-ietf-poly1305", "SIP002 method 错误")
        _expect(sip["password"] == "p@ss", "SIP002 password 错误")
        _expect(sip["server"] == "ss.example.com", "SIP002 host 错误")
        _expect(sip["port"] == 8443, "SIP002 port 错误")

    @check("整份 Base64 订阅 / 失败计数 / 去重")
    def _check_subscription():
        text = "\n".join([vm_link, vl_link, tr_link, ss_legacy, ss_sip])
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        nodes, failed = parse_subscription_text(encoded)
        _expect(len(nodes) == 5, "整份 base64 订阅节点数错误：%d" % len(nodes))
        _expect(failed == 0, "整份 base64 订阅失败计数错误")

        nodes2, failed2 = parse_subscription_text(
            "not-a-link\n" + vm_link + "\n" + vm_link
        )
        _expect(len(nodes2) == 1, "去重失败")
        _expect(failed2 == 1, "失败行计数错误：%d" % failed2)

        bad = parse_share_link("vmess://not-base64!!!")
        _expect(bad is None, "非法 vmess 应返回 None")

    @check("订阅更新按 key 合并并保留旧字段")
    def _check_merge():
        old_node = parse_share_link(vm_link)
        _expect(old_node is not None, "vmess 解析失败")
        old_node["sub"] = "http://example.com/sub"
        old_node["local_port"] = 20001
        old_node["enabled"] = True
        old_node["latency"] = 12
        old_node["speed"] = 345.6
        old_nid = old_node["nid"]

        new_nodes, _ = parse_subscription_text(vm_link)
        merged, added, removed, skipped = merge_subscription_nodes(
            [old_node], "http://example.com/sub", new_nodes
        )
        _expect(len(merged) == 1, "合并后节点数错误")
        _expect(added == 0 and removed == 0 and skipped == 0, "合并计数错误")
        _expect(merged[0]["nid"] == old_nid, "稳定 id 未保留")
        _expect(merged[0]["local_port"] == 20001, "local_port 未保留")
        _expect(merged[0]["enabled"] is True, "enabled 未保留")
        _expect(merged[0]["latency"] == 12, "latency 未保留")
        _expect(merged[0]["speed"] == 345.6, "speed 未保留")
        _expect(merged[0]["sub"] == "http://example.com/sub", "订阅归属丢失")

    @check("build_xray_config 结构与协议/传输层")
    def _check_config():
        parsed = {}
        for proto, link in (
            ("vmess", vm_link),
            ("vless", vl_link),
            ("trojan", tr_link),
            ("ss", ss_sip),
            ("legacy", ss_legacy),
        ):
            node = parse_share_link(link)
            _expect(node is not None, "%s 解析失败" % proto)
            parsed[proto] = node

        nodes = []
        for index, proto in enumerate(("vmess", "vless", "trojan", "ss", "legacy")):
            node = dict(parsed[proto])
            node["enabled"] = True
            node["local_port"] = 10801 + index
            nodes.append(node)
        nodes[4]["network"] = "kcp"  # 未知 network 应归一化为 tcp

        config = build_xray_config(nodes)
        _expect(len(config["inbounds"]) == 5, "inbound 数量错误")
        _expect(len(config["outbounds"]) == 7, "outbound 数量错误")
        _expect(len(config["routing"]["rules"]) == 6, "routing 规则数量错误")
        _expect(
            config["routing"]["rules"][0]["outboundTag"] == "direct"
            and "10.0.0.0/8" in config["routing"]["rules"][0]["ip"]
            and "fc00::/7" in config["routing"]["rules"][0]["ip"],
            "内网直连规则缺失",
        )

        inbound_tags = set(item["tag"] for item in config["inbounds"])
        _expect(
            inbound_tags
            == {"in10801", "in10802", "in10803", "in10804", "in10805"},
            "inbound tag 错误",
        )
        ports = [item["port"] for item in config["inbounds"]]
        _expect(len(ports) == len(set(ports)), "本地端口不唯一")
        _expect(sorted(ports) == [10801, 10802, 10803, 10804, 10805], "端口分配错误")
        for item in config["inbounds"]:
            _expect(item["listen"] == "127.0.0.1", "inbound listen 错误")
            _expect(item["protocol"] == "socks", "inbound 协议错误")
            _expect(item["settings"]["auth"] == "noauth", "auth 错误")
            _expect(item["settings"]["udp"] is True, "udp 未开启")
            _expect(
                item["sniffing"]["destOverride"] == ["http", "tls"],
                "sniffing 错误",
            )

        protocols = [item["protocol"] for item in config["outbounds"]]
        for proto in ("vmess", "vless", "trojan", "shadowsocks", "freedom", "blackhole"):
            _expect(proto in protocols, "缺少 %s 出站" % proto)

        rules = {}
        for rule in config["routing"]["rules"][1:]:
            rules[rule["inboundTag"][0]] = rule["outboundTag"]
        outbound_tags = set(item["tag"] for item in config["outbounds"])
        for index in range(5):
            in_tag = "in%d" % (10801 + index)
            out_tag = "p%d" % (10801 + index)
            _expect(rules.get(in_tag) == out_tag, "routing 未一一对应")
            _expect(out_tag in outbound_tags, "routing 指向不存在的 outbound")

        api_cfg = build_xray_config(nodes, api_port=19999)
        _expect(
            api_cfg["inbounds"][-1]["tag"] == "api"
            and api_cfg["inbounds"][-1]["protocol"] == "dokodemo-door",
            "api 入站缺失",
        )
        _expect(
            "stats" in api_cfg and "policy" in api_cfg and "api" in api_cfg,
            "stats/api/policy 配置缺失",
        )
        _expect(
            api_cfg["routing"]["rules"][0].get("outboundTag") == "api"
            and api_cfg["routing"]["rules"][1].get("outboundTag") == "direct"
            and "192.168.0.0/16" in (api_cfg["routing"]["rules"][1].get("ip") or []),
            "api/private 规则顺序错误",
        )

        payload = json.dumps(
            {
                "stat": [
                    {"name": "inbound>>>in10801>>>traffic>>>uplink", "value": 100},
                    {"name": "inbound>>>in10801>>>traffic>>>downlink", "value": "456"},
                    {"name": "inbound>>>api>>>traffic>>>uplink", "value": 7},
                    {"name": "garbage", "value": 1},
                ]
            }
        )
        got = parse_traffic_payload(payload)
        _expect(got == {10801: {"up": 100, "down": 456}}, "stats 解析错误")
        _expect(parse_traffic_payload("not-json") == {}, "stats 解析容错失败")
        _expect(fmt_bytes(2097281) == "2.00MB", "fmt_bytes 错误")
        _expect(fmt_bytes(0) == "0B", "fmt_bytes 零值错误")
        _expect(
            fmt_traffic(2048, 1048576, per_second=True) == "↑2.00KB/s ↓1.00MB/s",
            "fmt_traffic 错误",
        )

        vm_out = next(item for item in config["outbounds"] if item["protocol"] == "vmess")
        vm_user = vm_out["settings"]["vnext"][0]["users"][0]
        _expect(isinstance(vm_user["alterId"], int), "alterId 不是 int")
        _expect(vm_out["streamSettings"]["network"] == "ws", "vmess network 错误")
        _expect(vm_out["streamSettings"]["security"] == "tls", "vmess TLS 错误")

        vl_out = next(item for item in config["outbounds"] if item["protocol"] == "vless")
        _expect(vl_out["streamSettings"]["security"] == "reality", "reality 缺失")
        _expect(
            vl_out["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY123",
            "reality publicKey 错误",
        )
        _expect(
            vl_out["settings"]["vnext"][0]["users"][0]["flow"]
            == "xtls-rprx-vision",
            "vless flow 错误",
        )

        tr_out = next(item for item in config["outbounds"] if item["protocol"] == "trojan")
        _expect(
            tr_out["settings"]["servers"][0]["password"] == "p@ss:word",
            "trojan 密码错误",
        )

        ss_out = next(
            item for item in config["outbounds"] if item["protocol"] == "shadowsocks"
        )
        _expect(
            ss_out["settings"]["servers"][0]["method"]
            == "chacha20-ietf-poly1305",
            "shadowsocks method 错误",
        )

        legacy_out = config["outbounds"][4]
        _expect(
            legacy_out["streamSettings"]["network"] == "tcp",
            "未知 network 未归一化为 tcp",
        )

        try:
            build_xray_config([])
        except ValueError:
            pass
        else:
            raise AssertionError("空节点应拒绝生成配置")

    @check("端口/格式化辅助函数")
    def _check_helpers():
        _expect(is_valid_port(10808), "合法端口误判")
        _expect(not is_valid_port(0), "0 端口误判")
        _expect(not is_valid_port(70000), "超范围端口误判")
        _expect("KB/s" in format_speed(2048), "速度格式化错误")
        _expect(
            node_key({"proto": "vmess", "server": "a", "port": 1, "uuid": "u"})
            == "vmess|a|1|u",
            "node_key 错误",
        )
        _expect(
            redact("vless://secret@example.com:443") == "***",
            "日志脱敏失败",
        )

    failures = 0
    for name, func in checks:
        try:
            func()
        except Exception as exc:
            failures += 1
            print("[FAIL] %s: %s" % (name, exc))
            traceback.print_exc()
        else:
            print("[OK] %s" % name)

    if failures:
        print("SELFTEST FAILED：%d/%d 项失败" % (failures, len(checks)))
        return 1
    print("SELFTEST OK（%d 项检查通过）" % len(checks))
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in args:
        return selftest()
    if "--help" in args or "-h" in args:
        print("用法: python xray_multi_port.py [--selftest]")
        return 0
    try:
        return run_gui()
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
