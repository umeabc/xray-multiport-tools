# -*- coding: utf-8 -*-
"""SOCKS5 节点链路端到端测试（开发用）：
   xray(本机 inbound 10999) --socks5--> 本地上游 SOCKS5 --TCP--> 本地 HTTP 目标
   覆盖「无认证」与「用户名/密码」两种上游。

运行：python test_socks_chain.py
"""
import importlib.util
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

spec = importlib.util.spec_from_file_location(
    "xmp", r"D:\harness\xray-multi-port-lite\xray_multi_port.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

BODY = b"OK-SOCKS-CHAIN-1234"


# ---------- 本地 HTTP 目标 ----------
class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(65536)
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(BODY)
                + BODY
            )
        except Exception:
            pass


http_srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), HttpHandler)
http_srv.daemon_threads = True
http_port = http_srv.server_address[1]
threading.Thread(target=http_srv.serve_forever, daemon=True).start()


# ---------- 本地 SOCKS5 上游（支持无认证 + 用户名密码） ----------
class Socks5Upstream(socketserver.BaseRequestHandler):
    expect_auth = None  # None=仅无认证; ("u","p")=要求用户名密码

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                raise OSError("eof")
            buf += chunk
        return buf

    def handle(self):
        try:
            ver, nmethods = self.recv_exact(2)
            methods = self.recv_exact(nmethods)
            if self.expect_auth:
                if 2 not in methods:
                    self.request.sendall(b"\x05\xff")
                    return
                self.request.sendall(b"\x05\x02")
                ver, ulen = self.recv_exact(2)
                user = self.recv_exact(ulen).decode()
                plen = self.recv_exact(1)[0]
                pwd = self.recv_exact(plen).decode()
                want_u, want_p = self.expect_auth
                if (user, pwd) != (want_u, want_p):
                    self.request.sendall(b"\x01\x01")
                    return
                self.request.sendall(b"\x01\x00")
            else:
                self.request.sendall(b"\x05\x00")
            # CONNECT 请求
            ver, cmd, rsv, atyp = self.recv_exact(4)
            if atyp == 1:
                host = socket.inet_ntoa(self.recv_exact(4))
            elif atyp == 3:
                ln = self.recv_exact(1)[0]
                host = self.recv_exact(ln).decode()
            else:
                self.request.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            port = struct.unpack("!H", self.recv_exact(2))[0]
            upstream = socket.create_connection((host, port), timeout=5)
            try:
                self.request.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                # 双向转发
                self.request.settimeout(10)
                upstream.settimeout(10)
                while True:
                    data = self.request.recv(65536)
                    if not data:
                        break
                    upstream.sendall(data)
                    resp = upstream.recv(65536)
                    if not resp:
                        break
                    self.request.sendall(resp)
                    break
            finally:
                upstream.close()
        except Exception:
            pass


def make_upstream(auth):
    cls = type("Upstream", (Socks5Upstream,), {"expect_auth": auth})
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


srv_noauth, port_noauth = make_upstream(None)
srv_auth, port_auth = make_upstream(("u1", "p1"))

# ---------- 生成两个 SOCKS5 节点并启动 xray ----------
node_a = m.normalize_node({
    "proto": "socks", "server": "127.0.0.1", "port": port_noauth,
    "name": "上游-无认证", "enabled": True, "local_port": 10999,
})
node_b = m.normalize_node({
    "proto": "socks", "server": "127.0.0.1", "port": port_auth,
    "user": "u1", "password": "p1", "name": "上游-带认证", "enabled": True,
    "local_port": 10998,
})
assert node_a and node_b, "socks 节点归一化失败"
print("node_a link:", m.build_share_link(node_a))
print("node_b link:", m.build_share_link(node_b))

cfg = m.build_xray_config([node_a, node_b], 10808, "127.0.0.1", False, None)
cfg_path = r"D:\harness\xray-multi-port-lite\.tmp_socks_e2e.json"
with open(cfg_path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)

proc = subprocess.Popen(
    [r"D:\harness\xray-multi-port-lite\xray.exe", "-config", cfg_path],
    cwd=r"D:\harness\xray-multi-port-lite",
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
time.sleep(2.0)
if proc.poll() is not None:
    print("xray 启动失败:", proc.stdout.read().decode("utf-8", "replace"))
    sys.exit(1)


def fetch_via(port):
    sock = m.socks5_connect(port, "127.0.0.1", http_port, 5.0)
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


ok = 0
try:
    for port, label in ((10999, "无认证"), (10998, "用户名密码")):
        try:
            resp = fetch_via(port)
            if BODY in resp:
                print("[OK] %s SOCKS5 节点链路可用（本地端口 %d）" % (label, port))
                ok += 1
            else:
                print("[FAIL] %s 响应异常: %r" % (label, resp[:120]))
        except Exception as exc:
            print("[FAIL] %s 链路失败: %s" % (label, exc))
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    http_srv.shutdown()
    srv_noauth.shutdown()
    srv_auth.shutdown()
    os.remove(cfg_path)

print("SOCKS5 e2e:", "OK (%d/2)" % ok if ok == 2 else "FAILED (%d/2)" % ok)
sys.exit(0 if ok == 2 else 1)
