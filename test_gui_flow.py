# -*- coding: utf-8 -*-
"""端到端功能测试：通过真实控件走「添加/编辑节点」与「全局设置」流程。

ttk.Combobox 是 ttk.Entry 的子类，因此用精确类型 + grid 行号定位控件；
messagebox 替换为记录型桩（模拟用户点确定），避免模态阻塞。
"""
import importlib.util
import tkinter as tk
from tkinter import ttk

spec = importlib.util.spec_from_file_location("xmp", "xray_multi_port.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m._ensure_tk()

MESSAGES = []


def _stub(name):
    def record(title=None, message=None, **kw):
        MESSAGES.append("%s:%s" % (name, title))
        return "ok"  # 模拟用户点击确定
    return record


m.messagebox.showwarning = _stub("warning")
m.messagebox.showinfo = _stub("info")
m.messagebox.showerror = _stub("error")

root = tk.Tk()
root.withdraw()
app = m.App(root)
# 预清理：移除上次测试可能遗留的节点
app.nodes = [n for n in app.nodes if "manual.example.com" not in str(n.get("server"))]
app.nodes = [n for n in app.nodes if "ss.example.com" not in str(n.get("server"))]
app.nodes = [n for n in app.nodes if "r.example.com" not in str(n.get("server"))]
app._refresh_tree()
before = len(app.nodes)


def walk(w):
    yield w
    for c in w.winfo_children():
        yield from walk(c)


def find_dialog(title):
    for w in root.winfo_children():
        if isinstance(w, tk.Toplevel) and title in str(w.title()):
            return w
    raise AssertionError("对话框未打开: " + title)


def close_dialog(title):
    for w in list(root.winfo_children()):
        if isinstance(w, tk.Toplevel) and title in str(w.title()):
            w.destroy()


def field_map(win):
    """返回 {label文本: 控件}，仅取编辑对话框的 form 区。"""
    form = win.winfo_children()[0]
    out = {}
    for w in form.grid_slaves():
        info = w.grid_info()
        if info["column"] == 0:
            label = str(w.cget("text")).rstrip(":")
            for other in form.grid_slaves(row=info["row"], column=1):
                out[label] = other
    return out


def set_field(fields, win, label, value):
    w = fields[label]
    if isinstance(w, ttk.Combobox):
        w.set(value)
        w.event_generate("<<ComboboxSelected>>")  # 触发联动 rebuild
    else:
        w.delete(0, "end")
        w.insert(0, value)
    win.update()
    return field_map(win)  # rebuild 后控件会被重建，返回新映射


def click_save(win):
    """点击保存；返回触发的 messagebox 提示（无则 None）。"""
    before_n = len(MESSAGES)
    for w in walk(win):
        if isinstance(w, ttk.Button) and w.cget("text") == "保存":
            w.invoke()
            break
    else:
        raise AssertionError("找不到保存按钮")
    return MESSAGES[before_n] if len(MESSAGES) > before_n else None


def last_message():
    return MESSAGES[-1] if MESSAGES else None


# ---- 1. 添加 vless 节点 ----------------------------------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
f = set_field(f, win, "别名 (名称)", "测试-手动")
f = set_field(f, win, "地址 (服务器)", "manual.example.com")
f = set_field(f, win, "端口", "443")
f = set_field(f, win, "用户 ID (UUID)", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
assert click_save(win) is None, "添加节点被误拦截: %s" % last_message()
assert len(app.nodes) == before + 1, "节点未新增"
node = app.nodes[-1]
assert node["proto"] == "vless" and node["server"] == "manual.example.com"
assert node["local_port"], "未分配本地端口"
assert node["link"].startswith("vless://"), "未生成分享链接"
back = m.parse_share_link(node["link"])
assert back is not None and back["server"] == "manual.example.com", "链接无法回环解析"
print("[OK] 添加 vless 节点: 端口=%s link=%s..." % (node["local_port"], node["link"][:48]))

# ---- 2. 重复添加应被拦截 ----------------------------------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
f = set_field(f, win, "地址 (服务器)", "manual.example.com")
f = set_field(f, win, "端口", "443")
f = set_field(f, win, "用户 ID (UUID)", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
msg = click_save(win)
assert msg == "warning:节点重复", "重复节点未被拦截: %r" % msg
close_dialog("添加节点")
print("[OK] 重复节点被拦截（提示: %s）" % msg)

# ---- 3. 缺 UUID 应被拦截 ----------------------------------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
f = set_field(f, win, "地址 (服务器)", "manual2.example.com")
f = set_field(f, win, "端口", "8443")
msg = click_save(win)
assert msg == "warning:缺少用户 ID", "缺 UUID 未被拦截: %r" % msg
close_dialog("添加节点")
print("[OK] 缺少 UUID 被拦截")

# ---- 4. 编辑节点：改名并生成新链接 ------------------------------------------
app._open_node_editor(node)
win = find_dialog("编辑节点")
f = field_map(win)
assert f["地址 (服务器)"].get() == "manual.example.com", "编辑对话框未预填"
f = set_field(f, win, "别名 (名称)", "测试-手动-改名")
assert click_save(win) is None, "编辑被拦截: %s" % last_message()
assert node["name"] == "测试-手动-改名", "编辑未生效"
back = m.parse_share_link(node["link"])
assert back is not None and back["name"] == "测试-手动-改名", "编辑后链接未更新"
print("[OK] 编辑节点改名并更新链接")

# ---- 5. 协议切换联动：ss 表单 ------------------------------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
proto_label = [k for k in f if k.startswith("协议")][0]
f = set_field(f, win, proto_label, "ss")
assert "加密方式 (method)" in f, "切换 ss 后未显示加密方式"
f = set_field(f, win, "别名 (名称)", "ss-测试")
f = set_field(f, win, "加密方式 (method)", "aes-256-gcm")
f = set_field(f, win, "地址 (服务器)", "ss.example.com")
f = set_field(f, win, "端口", "8388")
f = set_field(f, win, "密码", "p@ss")
assert click_save(win) is None, "添加 ss 被拦截: %s" % last_message()
ss_node = app.nodes[-1]
assert ss_node["proto"] == "ss" and ss_node["method"] == "aes-256-gcm"
assert ss_node["link"].startswith("ss://"), "ss 链接未生成"
print("[OK] ss 协议表单联动与添加")

# ---- 6. REALITY 联动：显示 PublicKey/ShortId ---------------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
tls_label = [k for k in f if k.startswith("底层传输安全")][0]
f = set_field(f, win, tls_label, "reality")
assert any("PublicKey" in k for k in f), "切换 REALITY 后未显示 PublicKey"
f = set_field(f, win, "地址 (服务器)", "r.example.com")
f = set_field(f, win, "端口", "443")
f = set_field(f, win, "用户 ID (UUID)", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
f = set_field(f, win, "SNI", "www.example.com")
msg = click_save(win)
assert msg == "warning:缺少 PublicKey", "REALITY 缺 PublicKey 未被拦截: %r" % msg
close_dialog("添加节点")
print("[OK] REALITY 表单联动与 PublicKey 校验")

# ---- 6.5 SOCKS5 节点：表单 / 保存 / 出站配置 --------------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
proto_label = [k for k in f if k.startswith("协议")][0]
f = set_field(f, win, proto_label, "socks")
assert "用户名 (可选)" in f and "密码 (可选)" in f, "切到 socks 后未显示用户名/密码"
assert not any("传输协议" in k for k in f), "socks 不应显示传输协议"
assert not any("底层传输安全" in k for k in f), "socks 不应显示 TLS 设置"
f = set_field(f, win, "别名 (名称)", "socks-上游")
f = set_field(f, win, "地址 (服务器)", "socks.example.com")
f = set_field(f, win, "端口", "1080")
assert click_save(win) is None, "添加 socks 被拦截: %s" % last_message()
socks_node = app.nodes[-1]
assert socks_node["proto"] == "socks", "socks 协议未保存"
assert socks_node["link"].startswith("socks://"), "socks 链接未生成"
back = m.parse_share_link(socks_node["link"])
assert back is not None and back["proto"] == "socks", "socks 链接无法回环解析"
out = m.build_outbound(socks_node, "p1")
assert out["protocol"] == "socks" and "streamSettings" not in out, "socks 出站结构错误"
print("[OK] SOCKS5 节点表单、保存与出站配置")

# ---- 6.6 带认证的 socks 节点：密码无用户名应被拦截 --------------------------
app._open_node_editor()
win = find_dialog("添加节点")
f = field_map(win)
proto_label = [k for k in f if k.startswith("协议")][0]
f = set_field(f, win, proto_label, "socks")
f = set_field(f, win, "地址 (服务器)", "socks2.example.com")
f = set_field(f, win, "端口", "1081")
f = set_field(f, win, "密码 (可选)", "only-pass")
msg = click_save(win)
assert msg == "warning:缺少用户名", "有密码无用户名未被拦截: %r" % msg
close_dialog("添加节点")
print("[OK] SOCKS5 密码缺用户名被拦截")

# ---- 7. 全局设置：保存延迟参数 ----------------------------------------------
app._open_settings()
win = find_dialog("全局设置")
entries = {}
form = win.winfo_children()[0]
for w in form.grid_slaves(column=1):
    if type(w) is ttk.Entry:
        entries[w.grid_info()["row"]] = w
# 行号: 4=延迟超时, 5=并发数, 6=日志上限 (0-3 是 xray路径/端口/两个勾选)
entries[4].delete(0, "end")
entries[4].insert(0, "3")
entries[5].delete(0, "end")
entries[5].insert(0, "12")
entries[6].delete(0, "end")
entries[6].insert(0, "800")
for w in walk(win):
    if isinstance(w, ttk.Button) and w.cget("text") == "保存":
        w.invoke()
        break
assert abs(app.settings["latency_timeout"] - 3.0) < 1e-9, "延迟超时未保存"
assert app.settings["latency_threads"] == 12, "并发数未保存"
assert app.settings["max_log_lines"] == 800, "日志上限未保存"
assert app._latency_timeout() == 3.0 and app._latency_threads() == 12
print("[OK] 全局设置保存并生效")

# ---- 8. 取消设置应还原 -------------------------------------------------------
orig_base = app.base_port_var.get()
app._open_settings()
win = find_dialog("全局设置")
# 改起始端口后取消
entries2 = {}
form2 = win.winfo_children()[0]
for w in form2.grid_slaves(column=1):
    if type(w) is ttk.Entry:
        entries2[w.grid_info()["row"]] = w
entries2[1].delete(0, "end")
entries2[1].insert(0, "20000")
for w in walk(win):
    if isinstance(w, ttk.Button) and w.cget("text") == "取消":
        w.invoke()
        break
assert app.base_port_var.get() == orig_base, "取消设置未还原"
print("[OK] 全局设置取消还原")

# ---- 9. 清理：删除测试节点 --------------------------------------------------
keep = []
for n in app.nodes:
    server = str(n.get("server") or "")
    if "example.com" in server:
        continue
    keep.append(n)
app.nodes = keep
app._refresh_tree()
app.save()
print("GUI functional test OK; nodes =", len(app.nodes))
root.destroy()
