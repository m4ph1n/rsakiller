"""Sage 桥接层：把重型格攻击（Coppersmith / Boneh-Durfee）交给本机 SageMath。

设计：
- Sage 启动慢（Cygwin 版约 3~6 秒），因此一次调用批量跑完全部重型候选，
  结果按 context 缓存，后续攻击直接命中缓存。
- 任务/结果用 JSON 文件交换，避免大整数在命令行上的转义与长度问题。
- 找不到 Sage 时返回 None，由纯 Python 实现兜底（精度/速度较差但可用）。

支持两种安装形态：
1. 原生 sage（Linux/macOS/已入 PATH）
2. Windows 的 SageMath 官方安装包（Cygwin 运行时，runtime/opt/sagemath-*/local/bin/sage）
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SCRIPT = os.path.join(_HERE, "sage_scripts", "heavy.py")
_TMPDIR = os.path.join(_ROOT, ".tmp")

_PROBE: Dict[str, Any] = {"done": False, "info": None, "err": ""}


def _to_cygwin(path: str) -> str:
    p = os.path.abspath(path).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    if m:
        return "/cygdrive/%s/%s" % (m.group(1).lower(), m.group(2))
    return p


def find_sage(force: bool = False) -> Optional[Dict[str, str]]:
    """定位本机 Sage，返回 {"kind","sage","bash"}；找不到返回 None。"""
    if _PROBE["done"] and not force:
        return _PROBE["info"]
    _PROBE["done"] = True
    _PROBE["info"] = None
    _PROBE["err"] = ""

    # 1) PATH 中的原生 sage
    exe = shutil.which("sage")
    if exe:
        _PROBE["info"] = {"kind": "native", "sage": exe, "bash": ""}
        return _PROBE["info"]

    # 2) Windows SageMath 安装包（Cygwin）
    bases: List[str] = []
    for drive in ("C:", "D:", "E:", "F:"):
        for pat in (drive + "/SageMath*", drive + "/sage*", drive + "/Program Files/SageMath*"):
            bases.extend(glob.glob(pat))
    seen = set()
    for d in bases:
        if not os.path.isdir(d) or d in seen:
            continue
        seen.add(d)
        bash = os.path.join(d, "runtime", "bin", "bash.exe")
        if not os.path.exists(bash):
            continue
        for sage in glob.glob(os.path.join(d, "runtime", "opt", "sagemath-*", "local", "bin", "sage")):
            if not os.path.exists(sage):
                continue
            # Cygwin bash 需要 /tmp 与 /dev/shm 可写，缺了会报 mount 错误
            for sub in ("tmp", "dev/shm"):
                try:
                    os.makedirs(os.path.join(d, "runtime", sub), exist_ok=True)
                except OSError:
                    pass
            # 必须用 Cygwin 内部路径（/opt/...），走 /cygdrive 会卡死
            rel = os.path.relpath(sage, os.path.join(d, "runtime")).replace("\\", "/")
            _PROBE["info"] = {
                "kind": "cygwin",
                "sage": "/" + rel,
                "bash": bash,
            }
            return _PROBE["info"]
    _PROBE["err"] = "未找到 SageMath 安装"
    return None


def sage_version(timeout: float = 90.0) -> str:
    """返回 Sage 版本字符串；不可用返回空串。"""
    info = find_sage()
    if not info:
        return ""
    if info["kind"] == "native":
        cmd = [info["sage"], "--version"]
    else:
        cmd = [info["bash"], "-lc", "'%s' --version" % info["sage"]]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
        m = re.search(r"SageMath version\s+([0-9][\w.\-]*)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def available() -> bool:
    return find_sage() is not None


_EVAL = "import os,sys; exec(open(os.environ['RSAKILLER_HEAVY']).read())"


def _runner_script(info: Dict[str, str]) -> str:
    """为 Cygwin 版生成固定的 runner.sh（内容只依赖 sage 路径）。"""
    path = os.path.join(_TMPDIR, "run_heavy.sh")
    content = ("#!/bin/bash\nexport CCACHE_DISABLE=1\nexec '%s' -c \"%s\"\n"
               % (info["sage"], _EVAL))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    return path


def run_jobs(jobs: List[Dict[str, Any]], timeout: float = 900.0,
             verbose: bool = False) -> Optional[List[Dict[str, Any]]]:
    """批量执行 Sage 任务。失败返回 None（调用方应回退纯 Python）。"""
    info = find_sage()
    if not info or not jobs:
        return None
    try:
        os.makedirs(_TMPDIR, exist_ok=True)
    except OSError:
        return None

    token = "%d_%d" % (os.getpid(), int(time.time() * 1000) % 10_000_000)
    taskf = os.path.join(_TMPDIR, "task_%s.json" % token)
    resf = os.path.join(_TMPDIR, "res_%s.json" % token)
    env = dict(os.environ)
    env.setdefault("HOME", os.path.expanduser("~"))
    env["PYTHONWARNINGS"] = "ignore"
    # 关键：Cygwin 版 Sage 的 ccache 在本机会卡住（编译锁死），直接绕过
    env["CCACHE_DISABLE"] = "1"
    try:
        with open(taskf, "w", encoding="utf-8") as f:
            json.dump(jobs, f)
        if info["kind"] == "native":
            env["RSAKILLER_HEAVY"] = _SCRIPT
            env["RSAKILLER_TASK"] = taskf
            env["RSAKILLER_RESULT"] = resf
            cmd = [info["sage"], "-c", _EVAL]
        else:
            env["RSAKILLER_HEAVY"] = _to_cygwin(_SCRIPT)
            env["RSAKILLER_TASK"] = _to_cygwin(taskf)
            env["RSAKILLER_RESULT"] = _to_cygwin(resf)
            runner = _runner_script(info)
            cmd = [info["bash"], "-lc", _to_cygwin(runner)]
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env,
                              stdin=subprocess.DEVNULL)
        if verbose:
            print("    [sage] 批任务 %d 个，用时 %.1fs，退出码 %s"
                  % (len(jobs), time.time() - t0, proc.returncode))
        if not os.path.exists(resf):
            if verbose:
                err = (proc.stderr or b"").decode("utf-8", "replace")
                print("    [sage] 无结果文件：%s" % err[-800:])
            return None
        with open(resf, encoding="utf-8") as f:
            return json.load(f)
    except subprocess.TimeoutExpired:
        if verbose:
            print("    [sage] 超时 %.0fs" % timeout)
        return None
    except Exception as exc:
        if verbose:
            print("    [sage] 调用失败：%s: %s" % (type(exc).__name__, exc))
        return None
    finally:
        for p in (taskf, resf):
            try:
                os.unlink(p)
            except OSError:
                pass

            except OSError:
                pass


def selftest() -> str:
    """简单自检：返回状态描述。"""
    info = find_sage()
    if not info:
        return "Sage: 未找到（重型攻击将回退纯 Python）"
    ver = sage_version()
    res = run_jobs([{"op": "ping"}], timeout=120)
    ok = bool(res and res and res[0].get("ok"))
    return "Sage%s: %s，ping %s" % (
        (" " + ver) if ver else "", info["kind"], "正常" if ok else "异常")
