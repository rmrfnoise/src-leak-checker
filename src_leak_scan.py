#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SRC LEAK CHECKER 1.0.0

根目录备份 / 源码压缩包泄露自查工具（仅限授权目标）。

用法:
    python src_leak_scan.py -u https://example.com
    python src_leak_scan.py -u https://example.com -t 20
    python src_leak_scan.py -u https://example.com -k

依赖: pip install -r requirements.txt
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import sys
import threading
import time
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.exceptions import InsecureRequestWarning
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    sys.stderr.write("[!] missing dependency: pip install requests\n")
    raise SystemExit(1)


# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

# 语义化版本：不兼容改动升第一位，新增功能升第二位，修复问题升第三位
VERSION = "1.0.0"

# 固定使用常见浏览器 UA，降低被简单 UA 规则拦截的概率
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# 只读取响应前 8 KiB：足够判断魔数/SQL 特征，又不必下载整个文件
READ_LIMIT = 8192
RANGE_HEADERS = {"Range": f"bytes=0-{READ_LIMIT - 1}"}
REDIRECT_CODES = frozenset((301, 302, 303, 307, 308))
MAX_REDIRECTS = 5   # 根 URL 最多跟随的跳转次数

TIMEOUT = 8.0   # 单次请求超时（秒），固定值
RETRIES = 1     # 失败重试次数，固定值

# 根目录候选后缀
EXTS_DEFAULT = (
    ".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".gz",
    ".tar.bz2", ".bz2", ".tar.xz", ".xz", ".sql", ".sql.gz",
    ".bak", ".backup",
)

# 最常见的备份 / 源码目录名
CORE_NAMES = (
    "www", "wwwroot", "web", "webroot", "website", "site", "htdocs",
    "public_html", "public", "html", "app", "project", "source", "src",
    "files", "data", "db", "database", "backup", "old", "temp", "test",
    "dev", "build",
)

# 补充备份名；已去掉 a / b / 123 / v1 这类低概率噪音
COMMON_NAMES = (
    "sql", "dump", "bak", "archive", "archives", "upload", "uploads",
    "release", "dist", "package", "mysql", "code",
)

# 常见备份子目录组合：目录 × 名字 × 后缀
SUBDIR_DIRS = ("backup", "bak", "old", "archive", "db", "data", "sql")
SUBDIR_STEMS = ("www", "wwwroot", "web", "site", "backup", "bak", "db",
                "data", "dump", "sql", "src", "code")
SUBDIR_EXTS = (".zip", ".rar", ".7z", ".tar.gz", ".sql")

# 文件头魔数 -> 类型
MAGIC = (
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),   # 空 ZIP（只有中央目录结束记录）
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"\x1f\x8b\x08", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"SQLite format 3\x00", "SQLite"),
)

# SQL 导出文件的常见特征
SQL_HINTS = (
    b"CREATE TABLE", b"INSERT INTO", b"DROP TABLE", b"CREATE DATABASE",
    b"SET NAMES", b"LOCK TABLES", b"DELIMITER", b"ALTER TABLE",
    b"-- MySQL", b"-- PostgreSQL", b"-- Dump", b"pg_dump", b"/*!40",
    b"SQLite format 3",
)

# 常见二进制 Content-Type（用于「可疑」判定）
BINARY_CT = (
    "application/zip", "application/x-zip", "application/x-rar",
    "application/x-7z", "application/x-tar", "application/gzip",
    "application/x-gzip", "application/x-bzip2", "application/x-xz",
    "application/octet-stream", "application/x-compressed",
    "application/zstd",
)

# Content-Disposition 中带这些后缀时视为备份文件下载
CD_EXTS = (".zip", ".rar", ".7z", ".tar", ".gz", ".sql", ".bak", ".backup")

BANNER = r"""
 ___   ___    ___    _     ___    _    _  _
/ __| | _ \  / __|  | |   | __|  / \  | |/ /
\__ \ |   / | (__   | |__ | _|  / _ \ | ' <
|___/ |_|\_\  \___|  |____||___| /_/ \_\|_|\_\
        源码泄露自查  ::  v{version}
"""

LEGAL = """\
[!] 仅限授权使用：请只对自己拥有或获得明确授权的系统运行本工具。
    使用者需自行遵守所在地区法律法规，并对任何误用后果负责。
"""

# 请求失败原因 -> 中文标签
STATE_LABELS = {
    "timeout": "超时",
    "tls": "TLS 证书错误",
    "conn": "连接失败",
    "error": "请求错误",
}

# 命中类型 -> 中文标签
KIND_LABELS = {
    "protected": "受保护资源",
    "attachment": "附件下载",
    "binary": "二进制内容",
    "text": "文本内容",
    "SQL (unverified)": "SQL（未验证）",
}


# --------------------------------------------------------------------------
# 控制台输出
# --------------------------------------------------------------------------

class Color:
    """ANSI 颜色码。"""

    RESET = "\033[0m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GRAY = "\033[90m"


class Console:
    """终端输出：banner、带时间戳的日志、进度条。"""

    def __init__(self):
        self.tty = sys.stdout.isatty()
        self.ansi = self._enable_vt() if self.tty else False
        # 非 TTY 不输出颜色；NO_COLOR 环境变量可强制关闭
        self.color = self.ansi and "NO_COLOR" not in os.environ
        self._progress = False
        self._last_progress = 0.0

    @staticmethod
    def _enable_vt() -> bool:
        """在 Windows 控制台开启 ANSI 转义支持；失败时降级为无色输出。"""
        if os.name != "nt":
            return True
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False

    def paint(self, text: str, code: str) -> str:
        """按需给文本套上 ANSI 颜色。"""
        return f"{code}{text}{Color.RESET}" if self.color else text

    def _clear_progress(self) -> None:
        """清除当前行进度条，避免和日志混在一起。"""
        if not self._progress:
            return
        if self.ansi:
            sys.stdout.write("\r\033[K")
        else:
            sys.stdout.write("\r" + " " * 120 + "\r")
        self._progress = False

    def _line(self, level: str, color: str, message: str) -> None:
        """输出一行带时间戳和级别的日志。"""
        self._clear_progress()
        stamp = datetime.now().strftime("%H:%M:%S")
        sys.stdout.write(
            f"{self.paint('[' + stamp + ']', Color.GRAY)} "
            f"[{self.paint(level, color)}] {message}\n")
        sys.stdout.flush()

    def info(self, message: str) -> None:
        self._line("信息", Color.CYAN, message)

    def warning(self, message: str) -> None:
        self._line("警告", Color.YELLOW, message)

    def critical(self, message: str) -> None:
        self._line("严重", Color.RED, message)

    def log(self, level: str, color: str, message: str) -> None:
        self._line(level, color, message)

    def success(self, message: str) -> None:
        self._clear_progress()
        sys.stdout.write(self.paint(f"[+] {message}", Color.GREEN) + "\n")
        sys.stdout.flush()

    def raw(self, message: str, color: str = Color.BLUE) -> None:
        """输出不带级别前缀的原始行（开始/结束时间）。"""
        self._clear_progress()
        sys.stdout.write(self.paint(message, color) + "\n")
        sys.stdout.flush()

    def finish(self) -> None:
        self._clear_progress()

    def banner(self) -> None:
        sys.stdout.write(self.paint(BANNER.format(version=VERSION), Color.CYAN))
        sys.stdout.write(self.paint(LEGAL, Color.GRAY))
        sys.stdout.flush()

    def progress(self, done: int, total: int, stats: "Stats") -> None:
        """显示进度：TTY 下画进度条，非 TTY 下每 1/4 打一行。"""
        if not self.tty:
            step = max(1, total // 4)
            if done and (done % step == 0 or done == total):
                self.info(f"进度 {done}/{total}（{done / total * 100:.0f}%）"
                          f" | 确认 {stats.confirmed}"
                          f" | 可疑 {stats.suspicious}")
            return
        now = time.monotonic()
        if done != total and now - self._last_progress < 0.2:
            return
        self._last_progress = now
        pct = done / total * 100 if total else 100.0
        filled = int(pct / 100 * 24)
        bar = "#" * filled + "." * (24 - filled)
        errors = (stats.timeout + stats.tls + stats.conn
                  + stats.error + stats.http_error)
        line = (f"{self.paint('[*]', Color.BLUE)} {done}/{total} [{bar}] "
                f"{pct:5.1f}%  确认 {stats.confirmed}  "
                f"可疑 {stats.suspicious}  软404 {stats.soft404}  "
                f"错误 {errors}")
        sys.stdout.write("\r" + line + ("\033[K" if self.ansi else " " * 8))
        sys.stdout.flush()
        self._progress = True

    def target_summary(self, elapsed: float, stats: "Stats") -> None:
        """输出单个目标的扫描汇总。"""
        self.info(f"扫描完成，用时 {elapsed:.1f}s | 测试 {stats.tested}"
                  f" | 确认 {stats.confirmed}"
                  f" | 可疑 {stats.suspicious}"
                  f" | 软404 {stats.soft404}")
        if (stats.redirect or stats.denied or stats.timeout or stats.tls
                or stats.conn or stats.error or stats.http_error):
            self.info(f"其他: 重定向 {stats.redirect} | 拒绝 {stats.denied}"
                      f" | 超时 {stats.timeout} | TLS {stats.tls}"
                      f" | 连接 {stats.conn} | 错误 {stats.error}"
                      f" | 5xx/429 {stats.http_error}")


# --------------------------------------------------------------------------
# 数据模型
# --------------------------------------------------------------------------

class Verdict(str, Enum):
    """检测结论。"""

    CONFIRMED = "CONFIRMED"      # 命中文件魔数或 SQL 导出特征
    SUSPICIOUS = "SUSPICIOUS"    # 仅凭响应头 / Content-Type 判断，需人工确认


@dataclass
class Hit:
    """一条命中记录。"""

    url: str
    status: int
    kind: str
    verdict: Verdict
    content_type: str = ""
    size: Optional[int] = None


@dataclass
class Stats:
    """一轮扫描的计数器。"""

    tested: int = 0
    confirmed: int = 0
    suspicious: int = 0
    soft404: int = 0
    redirect: int = 0
    denied: int = 0
    timeout: int = 0
    tls: int = 0
    conn: int = 0
    error: int = 0
    http_error: int = 0


@dataclass
class Baseline:
    """软 404 基线：随机路径的状态、指纹与稳定性。"""

    status: int = 0
    wildcard: bool = False
    stable: bool = False
    signature: Optional[tuple] = None


# --------------------------------------------------------------------------
# 候选生成
# --------------------------------------------------------------------------

def domain_names(base: str) -> set:
    """由目标域名生成候选名：example.com / example_com / example-com / example。

    IP 目标直接返回空集，避免生成 1.2.3.4.zip、1.zip 这类噪音。
    """
    host = (urlsplit(base).hostname or "").lower()
    if not host:
        return set()
    try:
        ipaddress.ip_address(host)
        return set()
    except ValueError:
        pass

    out = {host, host.replace(".", "_"), host.replace(".", "-")}
    if host.startswith("www."):
        bare = host[4:]
        out |= {bare, bare.replace(".", "_"), bare.replace(".", "-")}
    out.add(host.split(".")[0])
    return {name for name in out if name}


def build_candidates(base: str) -> list:
    """生成全部候选路径：根目录「名字 + 后缀」，以及常见备份子目录。"""
    names = set(CORE_NAMES) | set(COMMON_NAMES) | domain_names(base)

    paths = set()
    for name in names:
        # 跳过会破坏 URL 结构的名字
        if not name or any(ch in name for ch in "/\\:?#& \t"):
            continue
        for ext in EXTS_DEFAULT:
            paths.add(name + ext)

    for directory in SUBDIR_DIRS:
        for stem in SUBDIR_STEMS:
            for ext in SUBDIR_EXTS:
                paths.add(f"{directory}/{stem}{ext}")
    return sorted(paths)


# --------------------------------------------------------------------------
# 响应处理辅助函数
# --------------------------------------------------------------------------

def base_ct(ct: str) -> str:
    """取 Content-Type 的主类型并转小写。"""
    return (ct or "").split(";")[0].strip().lower()


def fmt_size(size: Optional[int]) -> str:
    """把字节数格式化为可读大小。"""
    if size is None:
        return "?"
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        value /= 1024
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
    return f"{size} B"


def response_size(resp) -> Optional[int]:
    """从 Content-Range / Content-Length 推断文件完整大小。

    Range 请求下优先看 Content-Range 的总长度；如果总长度是 *（未知），
    不能拿分片长度冒充文件大小，直接返回 None。
    """
    content_range = resp.headers.get("Content-Range") or ""
    if content_range:
        match = re.search(r"/\s*(\d+)\s*$", content_range)
        return int(match.group(1)) if match else None
    value = (resp.headers.get("Content-Length") or "").strip()
    return int(value) if value.isdigit() else None


def read_head(resp, limit: int = READ_LIMIT) -> bytes:
    """读取响应体前 limit 字节，读完立即关闭响应以释放连接。"""
    data = bytearray()
    try:
        for chunk in resp.iter_content(2048):
            if not chunk:
                continue
            data.extend(chunk)
            if len(data) >= limit:
                break
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return bytes(data[:limit])


def sniff(head: bytes) -> Optional[str]:
    """按文件头魔数判断类型。"""
    for signature, name in MAGIC:
        if head.startswith(signature):
            if name == "BZIP2" and not head[3:4].isdigit():
                continue
            return name
    # TAR 的 ustar 标识位于偏移 257
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "TAR"
    return None


def is_html(head: bytes, ct: str) -> bool:
    """判断响应是否像 HTML 页面（用于过滤错误页 / 教程页）。"""
    if "text/html" in ct or "application/xhtml" in ct:
        return True
    body = head[:2048].lower()
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]
    body = body.lstrip()
    return (b"<!doctype html" in body[:64]
            or b"<html" in body[:512]
            or b"<head" in body[:512])


def looks_sql(head: bytes) -> bool:
    """响应前 8 KiB 是否包含 SQL 导出特征。"""
    return any(hint in head for hint in SQL_HINTS)


def is_binary_ct(ct: str) -> bool:
    """Content-Type 是否属于常见二进制类型。"""
    return any(item in ct for item in BINARY_CT)


def classify_error(exc: Exception) -> str:
    """把 requests 异常归类为统计用的状态。"""
    # SSLError / ProxyError 都是 ConnectionError 的子类，必须先判断
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "conn"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "conn"
    return "error"


# --------------------------------------------------------------------------
# HTTP 客户端
# --------------------------------------------------------------------------

class HttpClient:
    """线程本地 Session：每个线程复用一条连接，并带固定重试策略。"""

    def __init__(self, verify: bool):
        self.timeout = TIMEOUT
        self.verify = verify
        self._local = threading.local()
        self._sessions = []
        self._lock = threading.Lock()
        if not verify:
            warnings.simplefilter("ignore", InsecureRequestWarning)

    def session(self) -> requests.Session:
        """返回当前线程的 Session，首次调用时创建。"""
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        session.headers.update({
            "User-Agent": UA,
            "Accept": "*/*",
            # 关闭压缩，保证 Range 读取到的是原始字节
            "Accept-Encoding": "identity",
        })

        retry = Retry(
            total=RETRIES,
            connect=RETRIES,
            # 读超时不重试：否则 8 秒超时会翻倍成 16 秒，
            # 且 urllib3 会把 ReadTimeout 包装成 ConnectionError，导致统计误分类
            read=False,
            status=RETRIES,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        # 每个线程同一时刻只有一个请求，连接池 1 条即可
        adapter = HTTPAdapter(max_retries=retry,
                              pool_connections=1, pool_maxsize=1)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        self._local.session = session
        with self._lock:
            self._sessions.append(session)
        return session

    def close(self) -> None:
        """关闭所有线程创建的 Session。"""
        with self._lock:
            sessions, self._sessions = self._sessions, []
        for session in sessions:
            try:
                session.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# 扫描器
# --------------------------------------------------------------------------

class Scanner:
    """对单个目标执行一轮探测。"""

    def __init__(self, client: HttpClient, console: Console, threads: int):
        self.client = client
        self.console = console
        self.threads = threads
        self.baseline = Baseline()

    # -- 目标准备 -----------------------------------------------------------

    def resolve_base(self, base: str) -> str:
        """跟随根 URL 的重定向，只允许同主机（含 www 变体）。

        跨主机跳转只告警、不跟随，避免把扫描带到授权范围外的资产。
        """
        current = base
        for _ in range(MAX_REDIRECTS):
            try:
                resp = self.client.session().get(
                    current, timeout=self.client.timeout,
                    allow_redirects=False, verify=self.client.verify,
                    stream=True)
            except requests.RequestException as exc:
                state = classify_error(exc)
                self.console.warning(
                    f"无法连接目标 URL（{STATE_LABELS.get(state, state)}）")
                return current

            try:
                status = resp.status_code
                location = resp.headers.get("Location")
            finally:
                try:
                    resp.close()
                except Exception:
                    pass

            if status not in REDIRECT_CODES or not location:
                return current

            try:
                target = normalize_target(urljoin(current, location))
            except ValueError:
                return current

            if host_key(target) != host_key(current):
                self.console.warning(
                    f"目标重定向到其他主机 {target}；已停止跟随"
                    f"（如属授权范围，请直接扫描该 URL）")
                return current

            # 规范化后相同（例如 /base 与 /base/）就不再请求，避免空转
            if target == current:
                return current

            self.console.warning(f"目标重定向到 {target}")
            current = target

        self.console.warning("根 URL 跳转次数过多，已停止跟随")
        return current

    def probe_baseline(self, base: str) -> Baseline:
        """请求两个随机路径，判断站点是否对不存在的路径返回 200/206。

        两次响应指纹一致时，才启用软 404 过滤；不一致则关闭过滤。
        """
        baseline = Baseline()
        signatures = []
        first_status = None

        for index in range(2):
            name = f"_probe_{uuid.uuid4().hex[:10]}.zip"
            url = f"{base}/{name}"
            try:
                resp = self.client.session().get(
                    url, headers=RANGE_HEADERS, timeout=self.client.timeout,
                    allow_redirects=False, verify=self.client.verify,
                    stream=True)
            except requests.RequestException as exc:
                state = classify_error(exc)
                self.console.warning(
                    f"基线探测失败（{STATE_LABELS.get(state, state)}）；"
                    f"已关闭软 404 过滤")
                return baseline
            try:
                status = resp.status_code
                if index == 0:
                    first_status = status
                ct = resp.headers.get("Content-Type") or ""
                head = read_head(resp)
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
            signatures.append(
                self._signature(ct, head, self._tokens(url)))

        baseline.status = first_status or 0
        baseline.wildcard = baseline.status in (200, 206)
        baseline.stable = (len(signatures) == 2
                           and signatures[0] == signatures[1])
        baseline.signature = signatures[0] if baseline.stable else None

        if baseline.wildcard:
            self.console.warning(
                f"目标对不存在的路径返回 {baseline.status}（检测到软 404）")
            if baseline.stable:
                self.console.info(
                    f"基线指纹: {baseline.signature[1][:16]}")
            else:
                self.console.warning(
                    "基线指纹不稳定；已关闭软 404 过滤")
        else:
            self.console.info(
                f"基线探测: HTTP {baseline.status}（无通配响应）")
            if baseline.status in (401, 403):
                self.console.warning(
                    "随机路径返回 401/403：站点可能全站鉴权，结果需人工确认")
        return baseline

    # -- 扫描主流程 ---------------------------------------------------------

    def scan(self, base: str, stats: Stats) -> None:
        """扫描单个目标，统计结果累加到 stats。"""
        self.baseline = Baseline()

        self.console.info(f"目标: {base}")
        self.console.info("正在测试目标 URL 连通性")
        base = self.resolve_base(base)

        self.console.info("正在探测软 404 / 通配响应")
        self.baseline = self.probe_baseline(base)

        paths = build_candidates(base)
        self.console.info(f"候选路径: {len(paths)}")
        self._run(base, paths, stats)

    def _run(self, base: str, paths: list, stats: Stats) -> None:
        """并发请求所有候选路径，边完成边汇总统计。"""
        started = time.monotonic()
        total = len(paths)
        executor = ThreadPoolExecutor(max_workers=self.threads)
        futures = [executor.submit(self.check, f"{base}/{path}")
                   for path in paths]
        try:
            for future in as_completed(futures):
                try:
                    state, hit = future.result()
                except Exception:
                    state, hit = "error", None

                stats.tested += 1
                if state == "hit" and hit:
                    if hit.kind == "protected":
                        stats.denied += 1
                    if hit.verdict is Verdict.CONFIRMED:
                        stats.confirmed += 1
                    else:
                        stats.suspicious += 1
                    self._report(hit)
                elif state == "soft404":
                    stats.soft404 += 1
                elif state == "redirect":
                    stats.redirect += 1
                elif state == "http_error":
                    stats.http_error += 1
                elif state in ("timeout", "tls", "conn", "error"):
                    setattr(stats, state, getattr(stats, state) + 1)

                self.console.progress(stats.tested, total, stats)
        finally:
            # Ctrl+C 时取消排队任务；已在执行的请求由解释器退出前收尾
            executor.shutdown(wait=False, cancel_futures=True)

        elapsed = time.monotonic() - started
        self.console.target_summary(elapsed, stats)

        if total and stats.redirect > total * 0.5:
            self.console.warning(
                "大量请求被重定向；可改用最终的 scheme/host 重新扫描")
        errors = stats.timeout + stats.tls + stats.conn + stats.error
        if total and errors > total * 0.8:
            self.console.warning(
                "大量请求失败；请检查网络和 TLS 设置（可尝试 -k）")
        if total and stats.http_error > total * 0.5:
            self.console.warning(
                "大量请求返回 5xx/429；可能被 WAF 拦截或站点异常")
        if stats.confirmed == 0:
            self.console.info("该目标未确认泄露")

    # -- 单次请求 -----------------------------------------------------------

    def check(self, url: str):
        """请求一个候选路径，返回 (状态, Hit|None)。"""
        try:
            resp = self.client.session().get(
                url, headers=RANGE_HEADERS, timeout=self.client.timeout,
                allow_redirects=False, verify=self.client.verify, stream=True)
        except requests.RequestException as exc:
            return classify_error(exc), None

        try:
            status = resp.status_code
            if status in REDIRECT_CODES:
                return "redirect", None

            content_type = resp.headers.get("Content-Type") or ""
            if status in (401, 403):
                # 随机路径不是 401/403，而候选是，说明文件可能存在但被拒绝
                if self.baseline.status in (401, 403):
                    return "other", None
                return "hit", Hit(
                    url=url,
                    status=status,
                    kind="protected",
                    verdict=Verdict.SUSPICIOUS,
                    content_type=base_ct(content_type),
                    size=response_size(resp),
                )
            if status not in (200, 206):
                # 5xx / 429 单独计数：整站返回这些状态通常意味着 WAF 拦截或站点异常
                if status == 429 or 500 <= status < 600:
                    return "http_error", None
                return "other", None

            disposition = (resp.headers.get("Content-Disposition") or "").lower()
            size = response_size(resp)
            head = read_head(resp)
        finally:
            try:
                resp.close()
            except Exception:
                pass

        if not head:
            return "other", None

        # 与基线指纹一致 => 软 404，丢弃
        ct_lower = content_type.lower()
        if self.baseline.stable and self.baseline.signature:
            if self._signature(content_type, head,
                               self._tokens(url)) == self.baseline.signature:
                return "soft404", None

        def mk(verdict: Verdict, kind: str):
            return "hit", Hit(
                url=url,
                status=status,
                kind=kind,
                verdict=verdict,
                content_type=base_ct(content_type),
                size=size,
            )

        # 判定顺序：魔数 > HTML 过滤 > SQL 特征 > 附件/二进制/文本
        known = sniff(head)
        if known:
            return mk(Verdict.CONFIRMED, known)

        if is_html(head, ct_lower):
            return "other", None

        path = urlsplit(url).path.lower()
        if path.endswith((".sql", ".sql.gz")):
            if looks_sql(head):
                return mk(Verdict.CONFIRMED, "SQL")
            return mk(Verdict.SUSPICIOUS, "SQL (unverified)")

        if any(ext in disposition for ext in CD_EXTS):
            return mk(Verdict.SUSPICIOUS, "attachment")

        if is_binary_ct(ct_lower):
            return mk(Verdict.SUSPICIOUS, "binary")

        if path.endswith((".bak", ".backup")):
            return mk(Verdict.SUSPICIOUS, "text")

        return "other", None

    # -- 输出与指纹 ---------------------------------------------------------

    def _report(self, hit: Hit) -> None:
        """打印一条命中。"""
        kind = KIND_LABELS.get(hit.kind, hit.kind)
        if hit.verdict is Verdict.CONFIRMED:
            label, level, color = f"确认 {kind}", "严重", Color.RED
        else:
            label, level, color = f"可疑 {kind}", "警告", Color.YELLOW
        self.console.log(level, color,
                         f"{label}: {hit.url}  (状态: {hit.status}, "
                         f"大小: {fmt_size(hit.size)}, "
                         f"类型: {hit.content_type or '-'})")

    @staticmethod
    def _tokens(url: str) -> list:
        """提取路径中长度 >= 4 的片段，用于抵消随机路径名对指纹的影响。

        必须按长度从长到短替换：先替换完整路径，再替换文件名；
        否则先替换文件名会留下前导 "/"，导致同一页面的指纹不一致。
        """
        path = urlsplit(url).path
        naming = {path, path.rsplit("/", 1)[-1]}
        return [item.encode("utf-8", "ignore")
                for item in sorted(naming, key=len, reverse=True)
                if len(item) >= 4]

    @staticmethod
    def _signature(ct: str, head: bytes, tokens: list) -> tuple:
        """响应指纹：(Content-Type, 去掉路径片段后的正文哈希)。"""
        body = head
        for token in tokens:
            body = body.replace(token, b"<PATH>")
        return (base_ct(ct), hashlib.sha1(body).hexdigest())


# --------------------------------------------------------------------------
# 命令行
# --------------------------------------------------------------------------

class ChineseUsageFormatter(argparse.HelpFormatter):
    """让 argparse 的用法行使用中文前缀「用法: 」。"""

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix is None:
            prefix = "用法: "
        return super()._format_usage(usage, actions, groups, prefix)


class ChineseArgumentParser(argparse.ArgumentParser):
    """参数错误时打印中文用法并以退出码 2 结束。"""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: 错误: {message}\n")


def parse_args(argv=None) -> argparse.Namespace:
    """解析命令行参数。"""
    parser = ChineseArgumentParser(
        prog="src_leak_scan.py",
        formatter_class=ChineseUsageFormatter,
        add_help=False,
    )

    parser.add_argument("-u", "--url", help="目标 URL，如 https://example.com")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="并发线程数（默认 10）")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="忽略 TLS 证书错误")

    args = parser.parse_args(argv)

    if not args.url:
        parser.error("请提供 -u/--url")
    if not 1 <= args.threads <= 100:
        parser.error("--threads 必须在 1..100 之间")
    return args


def normalize_target(raw: str) -> str:
    """规范化目标 URL：补协议、校验 scheme/host、去掉查询和锚点。"""
    value = raw.strip().lstrip("\ufeff")
    if not value:
        raise ValueError("目标为空")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"不支持的协议 '{parts.scheme}'")
    if not parts.hostname:
        raise ValueError("缺少主机名")
    return urlunsplit((parts.scheme, parts.netloc,
                       parts.path.rstrip("/"), "", ""))


def host_key(url: str) -> str:
    """判断两个 URL 是否同一主机：忽略 scheme/port 和 www. 前缀。"""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def force_utf8() -> None:
    """把 stdout/stderr 切到 UTF-8，避免 Windows 控制台中文乱码。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv=None) -> int:
    """程序入口，返回进程退出码。"""
    force_utf8()
    args = parse_args(argv)
    console = Console()
    console.banner()

    started = datetime.now()
    console.raw(f"[*] 开始 @ {started:%Y-%m-%d %H:%M:%S}")

    try:
        target = normalize_target(args.url)
    except ValueError as exc:
        console.critical(f"无效目标 {args.url!r}: {exc}")
        return 2

    client = HttpClient(verify=not args.insecure)
    scanner = Scanner(client, console, args.threads)

    stats = Stats()
    interrupted = False
    try:
        scanner.scan(target, stats)
    except KeyboardInterrupt:
        interrupted = True
        console.critical("用户中断（Ctrl+C）")
    finally:
        console.finish()
        # 中断时可能仍有线程在请求，交给进程退出时清理，避免并发关闭连接
        if not interrupted:
            client.close()

    ended = datetime.now()
    elapsed = (ended - started).total_seconds()

    if stats.confirmed:
        console.success(f"共确认泄露: {stats.confirmed}")
    else:
        console.info("未发现确认泄露")
    if stats.suspicious:
        console.info(f"共可疑响应: {stats.suspicious}")
    console.info(f"耗时: {elapsed:.1f}s | 已测试: {stats.tested}")

    console.raw(f"[*] 结束 @ {ended:%Y-%m-%d %H:%M:%S}")

    if interrupted:
        return 130
    return 1 if stats.confirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
