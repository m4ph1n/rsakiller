"""Sage 桥接层：把重型格攻击（Coppersmith / Boneh-Durfee）交给本机 SageMath。

设计：
- Sage 启动昂贵（本机 Cygwin 版约 8~10 秒，其中 `sage -c` 的解释器初始化占大头），
  因此默认起一个**常驻 worker**：进程只启动一次，之后按行收发 JSON 任务，
  单次任务往返降到毫秒级。worker 起不来时退回一次性调用（`sage -python heavy.py`）。
- 任务/结果优先走管道；一次性调用用 JSON 文件交换，避免大整数在命令行上的转义问题。
- 找不到 Sage 时返回 None，由纯 Python 实现兜底（精度/速度较差但可用）。

支持两种安装形态：
1. 原生 sage（Linux/macOS/已入 PATH）
2. Windows 的 SageMath 官方安装包（Cygwin 运行时，runtime/opt/sagemath-*/local/bin/sage）
"""
from __future__ import annotations

import atexit
import glob
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_SCRIPT = os.path.join(_HERE, "sage_scripts", "heavy.py")
_TMPDIR = os.path.join(_ROOT, ".tmp")
_VERSION_CACHE = os.path.join(_TMPDIR, "sage_version.json")
_VERSION_TTL = 7 * 24 * 3600.0

# worker 启动上限：实测冷启动 8~10 秒，留足余量给杀毒软件/冷缓存
_BOOT_TIMEOUT = float(os.environ.get("RSAKILLER_SAGE_BOOT_TIMEOUT", "180"))

_PROBE: Dict[str, Any] = {"done": False, "info": None, "err": ""}
# 探测结果允许多线程同时查（预热线程会先发起探测）
_PROBE_LOCK = threading.Lock()


def _to_cygwin(path: str) -> str:
    p = os.path.abspath(path).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    if m:
        return "/cygdrive/%s/%s" % (m.group(1).lower(), m.group(2))
    return p


def find_sage(force: bool = False) -> Optional[Dict[str, str]]:
    """定位本机 Sage，返回 {"kind","sage","bash","python"}；找不到返回 None。

    结果进程内缓存；并发调用由 `_PROBE_LOCK` 串行化，避免读到半初始化的状态。
    """
    if _PROBE["done"] and not force:
        return _PROBE["info"]
    with _PROBE_LOCK:
        if _PROBE["done"] and not force:
            return _PROBE["info"]
        _PROBE["done"] = False
        _PROBE["info"] = None
        _PROBE["err"] = ""
        _PROBE["info"] = _locate_sage()
        _PROBE["done"] = True
        if _PROBE["info"] is None and not _PROBE["err"]:
            _PROBE["err"] = "未找到 SageMath 安装"
        return _PROBE["info"]


def _locate_sage() -> Optional[Dict[str, str]]:
    """实际执行探测，由 `find_sage` 持锁调用。"""
    # 1) PATH 中的原生 sage
    exe = shutil.which("sage")
    if exe:
        return {"kind": "native", "sage": exe, "bash": "", "python": ""}

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
            return {
                "kind": "cygwin",
                "sage": "/" + rel,
                "bash": bash,
                # -python 跳过 sage 解释器初始化，比 -c 快约 3 秒
                "python": "/" + rel.replace("/bin/sage", "/bin/python"),
            }
    return None


def available() -> bool:
    return find_sage() is not None


# --------------------------------------------------------------------------
# 版本探测：`sage --version` 约 1.5~2 秒，结果按安装路径 + mtime 缓存
# --------------------------------------------------------------------------
_VERSION_RE = re.compile(r"SageMath version\s+([0-9][\w.\-]*)")


def _read_version_cache(info: Dict[str, str]) -> str:
    try:
        with open(_VERSION_CACHE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return ""
    if not isinstance(data, dict) or data.get("sage") != info["sage"]:
        return ""
    if time.time() - float(data.get("at") or 0) > _VERSION_TTL:
        return ""
    return str(data.get("version") or "")


def _write_version_cache(info: Dict[str, str], version: str) -> None:
    try:
        os.makedirs(_TMPDIR, exist_ok=True)
        with open(_VERSION_CACHE, "w", encoding="utf-8") as f:
            json.dump({"sage": info["sage"], "version": version, "at": time.time()}, f)
    except OSError:
        pass


def sage_version(timeout: float = 90.0) -> str:
    """返回 Sage 版本字符串；不可用返回空串。"""
    env = os.environ.get("RSAKILLER_SAGE_VERSION", "")
    if env:
        return env
    worker = _worker_handle()
    if worker is not None and worker.version:
        return worker.version
    info = find_sage()
    if not info:
        return ""
    cached = _read_version_cache(info)
    if cached:
        return cached
    if info["kind"] == "native":
        cmd = [info["sage"], "--version"]
    else:
        cmd = [info["bash"], "-lc", "'%s' --version" % info["sage"]]
    try:
        r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout)
        out = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
        m = _VERSION_RE.search(out)
        ver = m.group(1) if m else ""
        if ver:
            _write_version_cache(info, ver)
        return ver
    except Exception:
        return ""


# --------------------------------------------------------------------------
# 常驻 worker
# --------------------------------------------------------------------------
class _Worker:
    """一个常驻 `sage -python heavy.py --serve` 进程。

    所有收发都经调用方持有的锁串行化；进程僵死时直接杀掉，下次调用重新拉起。
    """

    def __init__(self, info: Dict[str, str], log_path: str) -> None:
        self.info = info
        self.log_path = log_path
        self.version = ""
        self.proc: Optional[subprocess.Popen] = None
        # stdout 由一个后台线程独占读取，主线程只从队列取（见 _read_line 的说明）
        self._lines: Optional["queue.Queue[Optional[str]]"] = None

    def _cmd(self) -> List[str]:
        info = self.info
        if info["kind"] == "native":
            return [info["sage"], "-python", _SCRIPT, "--serve"]
        # Cygwin：必须用内部路径，且经 bash -lc 才能拿到完整的 Sage 环境
        return [info["bash"], "-lc",
                "'%s' -python '%s' --serve" % (info["sage"], _to_cygwin(_SCRIPT))]

    def _env(self) -> Dict[str, str]:
        env = dict(os.environ)
        env.setdefault("HOME", os.path.expanduser("~"))
        env["PYTHONWARNINGS"] = "ignore"
        env["PYTHONUNBUFFERED"] = "1"
        # 关键：Cygwin 版 Sage 的 ccache 在本机会卡住（编译锁死），直接绕过
        env["CCACHE_DISABLE"] = "1"
        return env

    def start(self, deadline: float) -> bool:
        """拉起进程并等到 ready 行；返回是否可用。"""
        try:
            os.makedirs(_TMPDIR, exist_ok=True)
            log = open(self.log_path, "wb")
        except OSError:
            return False
        try:
            self.proc = subprocess.Popen(
                self._cmd(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=log, env=self._env(), bufsize=0)
        except OSError:
            log.close()
            return False
        finally:
            log.close()
        self._lines = queue.Queue()
        threading.Thread(target=self._pump, args=(self.proc.stdout,),
                         name="sage-stdout", daemon=True).start()
        ready = self._read_until_ready(deadline)
        if not ready:
            self.close()
        return ready

    def _read_line(self, deadline: float) -> Optional[str]:
        """带截止时间读一行；超时或 EOF 返回 None。

        不能"起线程读一行 + join 超时"：超时后那个线程仍阻塞在管道上，
        随后 `close()` 关闭 stdout 会与它抢同一把缓冲锁，进程永久卡死。
        改成由后台线程把所有行推进队列，这里只带超时地从队列取 ——
        读者永远只有一个，关闭时不会有两个线程争同一流。
        """
        assert self._lines is not None
        remaining = max(0.0, deadline - time.time())
        try:
            item = self._lines.get(timeout=remaining)
        except queue.Empty:
            return None
        if item is None:                  # 读到 EOF：后台线程投递的哨兵
            return None
        return item

    def _pump(self, stream) -> None:
        """后台线程：逐行读 stdout 投递到队列，结束（含异常）时投 None。"""
        try:
            for raw in iter(stream.readline, b""):
                self._lines.put(raw.decode("utf-8", "replace")
                                if isinstance(raw, bytes) else str(raw))
        except Exception:
            pass
        finally:
            self._lines.put(None)

    def _read_until_ready(self, deadline: float) -> bool:
        while time.time() < deadline:
            line = self._read_line(deadline)
            if line is None:
                return False
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue            # Sage 启动期的杂项输出
            if isinstance(msg, dict) and msg.get("ready"):
                self.version = str(msg.get("sage_version") or "")
                return True
        return False

    def request(self, jobs: List[Dict[str, Any]], deadline: float) -> Optional[List[Dict[str, Any]]]:
        assert self.proc is not None and self.proc.stdin is not None
        try:
            self.proc.stdin.write((json.dumps({"jobs": jobs}) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (OSError, ValueError):
            return None
        while time.time() < deadline:
            line = self._read_line(deadline)
            if line is None:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("ok"):
                results = msg.get("results")
                return results if isinstance(results, list) else None
        return None

    def close(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                try:
                    if proc.stdin:
                        proc.stdin.write(b'{"op": "__quit__"}\n')
                        proc.stdin.flush()
                except (OSError, ValueError):
                    pass
                proc.wait(timeout=5)
        except Exception:
            pass
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        # 只关 stdin。stdout 由 `_pump` 线程独占读，进程退出后它自会读到 EOF；
        # 这里再 close() 会与读线程争同一把缓冲锁，把关闭动作卡死。
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass

    def tail(self, limit: int = 800) -> str:
        try:
            with open(self.log_path, "rb") as f:
                data = f.read()
        except OSError:
            return ""
        return data.decode("utf-8", "replace")[-limit:]


_WORKER: Optional[_Worker] = None
_WORKER_LOCK = threading.Lock()
_WORKER_SEQ = 0
# worker 起不来时置为 True，本次进程内不再重试，避免每个任务都白等一个启动超时
_WORKER_DISABLED = os.environ.get("RSAKILLER_SAGE_NO_WORKER", "") not in ("", "0")
# 预热被取消（任务结束时 Sage 根本没用上）：线程收尾时直接关掉进程
_CANCELLED = False


def _worker_handle() -> Optional[_Worker]:
    return _WORKER


def _spawn_worker(deadline: float) -> Optional[_Worker]:
    """拉起常驻 worker；失败返回 None（调用方回退一次性调用）。

    启动本身不持 `_WORKER_LOCK`（Sage 启动要好几秒，持锁会卡住退出路径）；
    只在最后发布 `_WORKER` 时短暂持锁。
    """
    global _WORKER, _WORKER_SEQ, _WORKER_DISABLED
    info = find_sage()
    if not info or _WORKER_DISABLED:
        return None
    _WORKER_SEQ += 1
    log_path = os.path.join(_TMPDIR, "sage_worker_%d_%d.log" % (os.getpid(), _WORKER_SEQ))
    worker = _Worker(info, log_path)
    if not worker.start(deadline):
        _WORKER_DISABLED = True
        return None
    with _WORKER_LOCK:
        if _CANCELLED:
            # 启动期间被取消（任务已经结束了）：别留着
            worker.close()
            return None
        _WORKER = worker
    return worker


def shutdown() -> None:
    """关闭常驻 worker（幂等）。

    解释器退出时调用：不等待预热线程，置位取消标志并直接杀进程，
    避免退出被 Sage 启动耗时拖住。
    """
    cancel_prewarm()


# 注意：`cancel_prewarm` 定义在下方预热小节，这里通过模块级名称在调用时解析。


atexit.register(shutdown)


# --------------------------------------------------------------------------
# 预热：在后台把 worker 拉起来，让 Sage 启动与纯 Python 攻击重叠
# --------------------------------------------------------------------------
_PREWARM: Optional[threading.Thread] = None
_PREWARM_LOCK = threading.Lock()


def warm_up(timeout: float = _BOOT_TIMEOUT) -> None:
    """异步启动常驻 worker，不阻塞调用方。

    Sage 启动约 6~10 秒，而纯 Python 攻击通常在前几秒就结束；
    在 `solve()` 开头预热可把这段启动时间藏进纯 Python 攻击的耗时里。
    重复调用无副作用；worker 起不来时本次进程内不再尝试。
    """
    global _PREWARM, _CANCELLED
    if _WORKER_DISABLED or _WORKER is not None:
        return
    with _PREWARM_LOCK:
        if _PREWARM is not None and _PREWARM.is_alive():
            return
        if _WORKER is not None or _WORKER_DISABLED:
            return
        _CANCELLED = False

        def run() -> None:
            deadline = time.time() + max(1.0, float(timeout))
            # 不持锁启动：持锁会让退出路径（shutdown/cancel）被 Sage 启动耗时卡住。
            # 用 `_PREWARM_LOCK` 之外的状态保证同时只有一个预热在跑。
            if _WORKER is not None or _WORKER_DISABLED or _CANCELLED:
                return
            _spawn_worker(deadline)

        _PREWARM = threading.Thread(target=run, name="sage-prewarm", daemon=True)
        _PREWARM.start()


def _ensure_worker(deadline: float) -> Optional[_Worker]:
    """拿到可用的 worker：等进行中的预热、复用现有进程，都没有才新起一个。

    注意**不能持 `_WORKER_LOCK` 调 `_spawn_worker`**：后者发布结果时要拿同一把
    非重入锁，持锁调用会自锁死（Sage 启动要好几秒，表现为整条链路永久卡住）。
    """
    th = _PREWARM
    if th is not None and th.is_alive() and _WORKER is None:
        # 预热线程正在起进程（不持锁）：等它落地，避免同时拉起两个 Sage
        th.join(max(0.0, deadline - time.time()))
    with _WORKER_LOCK:
        if _WORKER is not None:
            return _WORKER
    return _spawn_worker(min(deadline, time.time() + _BOOT_TIMEOUT))


def cancel_prewarm() -> None:
    """放弃预热：已起好的 worker 立即关掉；还没起完的让它收尾时自行关闭。

    求解结束时若 Sage 一次都没用上，就不该继续等它启动，也不该留着
    一个常驻进程吊住内存和解释器退出。这里不抢 `_WORKER_LOCK`——预热
    线程可能正在发布新进程；只置 `_CANCELLED`，由 `_spawn_worker` 收尾。
    """
    global _CANCELLED, _WORKER
    _CANCELLED = True
    worker, _WORKER = _WORKER, None
    if worker is not None:
        worker.close()


def join_prewarm(timeout: Optional[float] = None) -> bool:
    """等待预热线程结束；返回 worker 是否可用。"""
    th = _PREWARM
    if th is not None:
        th.join(timeout)
    return _WORKER is not None


# --------------------------------------------------------------------------
# 一次性调用（worker 不可用时的退路）
# --------------------------------------------------------------------------
def _run_once(info: Dict[str, str], jobs: List[Dict[str, Any]], resf: str,
              deadline: float) -> Optional[List[Dict[str, Any]]]:
    """起一个一次性 Sage 进程执行任务，结果经结果文件返回。

    stdout/stderr 一律重定向到文件，**不用管道**：Cygwin 的 bash 会再拉一个
    sage python 孙进程，孙进程会继承管道写端；一旦 bash 先退出，`subprocess.run`
    读到 EOF 之前会一直阻塞，连 `timeout=` 都救不回来（Windows 上的已知陷阱）。
    """
    taskf = resf.replace("res_", "task_")
    logf = resf.replace("res_", "log_")
    try:
        with open(taskf, "w", encoding="utf-8") as f:
            json.dump(jobs, f)
        env = dict(os.environ)
        env.setdefault("HOME", os.path.expanduser("~"))
        env["PYTHONWARNINGS"] = "ignore"
        env["PYTHONUNBUFFERED"] = "1"
        env["CCACHE_DISABLE"] = "1"
        if info["kind"] == "native":
            cmd = [info["sage"], "-python", _SCRIPT, taskf, resf]
        else:
            cmd = [info["bash"], "-lc",
                   "'%s' -python '%s' '%s' '%s'"
                   % (info["sage"], _to_cygwin(_SCRIPT), _to_cygwin(taskf), _to_cygwin(resf))]
        remaining = max(1.0, deadline - time.time())
        with open(logf, "wb") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                    env=env)
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                # 进程超时：连同它拉起的子进程一起收掉，别留在后台吃 CPU
                try:
                    proc.kill()
                    proc.wait(timeout=30)
                except Exception:
                    pass
                return None
        if not os.path.exists(resf):
            return None
        with open(resf, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
    finally:
        for tmp in (taskf, logf):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def run_jobs(jobs: List[Dict[str, Any]], timeout: float = 900.0,
             verbose: bool = False) -> Optional[List[Dict[str, Any]]]:
    """批量执行 Sage 任务。失败返回 None（调用方应回退纯 Python）。

    `timeout` 是这一批任务的总墙钟预算，含首次启动 worker 的成本。
    首次调用之后 worker 常驻，后续调用只需计算时间。
    """
    global _WORKER
    info = find_sage()
    if not info or not jobs:
        return None
    try:
        os.makedirs(_TMPDIR, exist_ok=True)
    except OSError:
        return None

    deadline = time.time() + max(1.0, float(timeout))
    t0 = time.time()
    # 预热线程可能正在启动 worker：先让路，避免又起一个
    reused = _WORKER is not None
    worker = _ensure_worker(deadline)
    with _WORKER_LOCK:
        results: Optional[List[Dict[str, Any]]] = None
        if worker is not None:
            results = worker.request(jobs, deadline)
            if results is None:
                # 进程僵死或协议损坏：杀掉，下次调用重新拉起
                worker.close()
                if _WORKER is worker:
                    _WORKER = None
        if results is None:
            token = "%d_%d" % (os.getpid(), int(time.time() * 1000) % 10_000_000)
            resf = os.path.join(_TMPDIR, "res_%s.json" % token)
            try:
                results = _run_once(info, jobs, resf, deadline)
            finally:
                try:
                    os.unlink(resf)
                except OSError:
                    pass
    if verbose and results is None:
        print("    [sage] 批任务 %d 个未拿到结果（超时或 Sage 进程异常退出）" % len(jobs))
    elif verbose:
        mode = "复用" if reused else ("常驻 worker" if worker is not None else "未复用")
        print("    [sage] 批任务 %d 个，用时 %.1fs，%s"
              % (len(jobs), time.time() - t0, mode))
    return results


def run_shards(batches: List[List[Dict[str, Any]]], timeout: float = 900.0,
               procs: int = 1, verbose: bool = False) -> Optional[List[Optional[List[Dict[str, Any]]]]]:
    """把若干批任务分发给多个独立 Sage 进程并行跑，返回各批结果。

    每批走一次性调用（各自一个 Sage 进程），因为常驻 worker 是单进程串行。
    多进程只在"单个任务就要跑很久"的场景值得：一次性调用各付一次启动成本
    （本机 Cygwin 版约 8 秒），换来的是 N 倍算力。

    `timeout` 是**整组**的墙钟预算，但每批各自从启动时刻起算自己那份：
    并行跑 N 批时共用一个绝对截止时间，会让所有批在同一个时刻一起被判超时，
    于是"还没算完"被误当成"没有结果"。返回按输入顺序对齐的列表，单批
    失败处填 None；`timed_out` 里记录哪几批是被超时打断的，调用方可据此
    区分"真没有"和"没算完"。
    """
    info = find_sage()
    if not info or not batches:
        return None
    try:
        os.makedirs(_TMPDIR, exist_ok=True)
    except OSError:
        return None
    procs = max(1, min(int(procs), len(batches)))
    # 每批拿到完整预算：并行时批与批之间不互相抢时间
    per_batch = max(1.0, float(timeout))
    out: List[Optional[List[Dict[str, Any]]]] = [None] * len(batches)
    timed_out: List[int] = []
    t0 = time.time()

    def one(idx: int) -> None:
        token = "%d_%d_%d" % (os.getpid(), idx, int(time.time() * 1000) % 10_000_000)
        resf = os.path.join(_TMPDIR, "res_%s.json" % token)
        batch_deadline = time.time() + per_batch
        try:
            out[idx] = _run_once(info, batches[idx], resf, batch_deadline)
        finally:
            try:
                os.unlink(resf)
            except OSError:
                pass
        if out[idx] is None:
            timed_out.append(idx)

    with _SHARD_LOCK:
        with _ThreadPoolExecutor(max_workers=procs) as pool:
            list(pool.map(one, range(len(batches))))
    if verbose:
        msg = "    [sage] 并行 %d 批 × %d 进程，用时 %.1fs" % (
            len(batches), procs, time.time() - t0)
        if timed_out:
            msg += "，其中 %d 批超时/失败" % len(timed_out)
        print(msg)
    run_shards.last_timeouts = sorted(timed_out)      # 供调用方判断是否"没算完"
    return out


_SHARD_LOCK = threading.Lock()


def selftest() -> str:
    """简单自检：返回状态描述。"""
    info = find_sage()
    if not info:
        return "Sage: 未找到（重型攻击将回退纯 Python）"
    ver = sage_version()
    t0 = time.time()
    res = run_jobs([{"op": "ping"}], timeout=120)
    first = time.time() - t0
    ok = bool(res and res[0].get("ok"))
    t1 = time.time()
    res2 = run_jobs([{"op": "ping"}], timeout=120)
    second = time.time() - t1
    warm = bool(res2 and res2[0].get("ok"))
    return "Sage%s: %s，ping %s（首次 %.1fs，复用 %.2fs，%s）" % (
        (" " + ver) if ver else "", info["kind"],
        "正常" if ok else "异常", first, second,
        "已常驻" if warm else "未常驻")
