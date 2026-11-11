# rsakiller

CTF RSA 通杀工具：自动解析题目参数，按「廉价攻击 → Sage 重型攻击 → 通用分解」的顺序逐条尝试，并对结果做校验。

## 架构

双引擎设计，纯 Python 快速路径负责毫秒级常见题型，Sage 重型路径负责格攻击，两者自动衔接。

| 模块 | 职责 |
| --- | --- |
| `rsakiller/cli.py` | 命令行入口，支持多文件输入（题目脚本 + 输出数据一起喂） |
| `rsakiller/ctx.py` | 参数解析：从代码/文本/注释中提取 n、e、c、p、q、dp、phi、near_p、d 低位、故障签名等 |
| `rsakiller/solver.py` | 攻击编排与结果校验 |
| `rsakiller/attacks.py` | 纯 Python 攻击集（直接解密、小 q、Fermat、共模、广播、Wiener、Bellcore 等） |
| `rsakiller/special.py` | 特殊结构分解：素数幂、两平方和、强伪素数、Williams p+1、著名数列、ROCA 检测 |
| `rsakiller/bonedurfee.py` | Boneh-Durfee 格攻击 |
| `rsakiller/lll.py` | 纯 Python LLL 实现（Coppersmith、Franklin-Reiter、短填充） |
| `rsakiller/modular.py` | 模运算工具 |
| `rsakiller/mt19937.py` | MT19937 状态恢复与种子预测 |
| `rsakiller/oracle.py` | 加解密/根运算封装 |
| `rsakiller/factor.py` | FactorDB 与通用分解 |
| `rsakiller/sagebridge.py` | 自动定位本机 Sage，JSON 任务协议，一次进程内批量跑完全部重型候选 |
| `rsakiller/sage_scripts/heavy.py` | Sage 侧实现：Coppersmith、Boneh-Durfee、Franklin-Reiter、qInv+dq 枚举、e 高位二次方程、退化椭圆曲线等 |
| `rsakiller/ec.py` | 椭圆曲线攻击的纯 Python 侧（退化曲线分解、还原 e·P 原像） |

## 用法

```bash
# 单个题目文件
python -m rsakiller challenge.py

# 题目脚本 + 输出数据一起喂（推荐，能提取 getPrime(1024) 等信息）
python -m rsakiller main.py output.txt

# 管道
cat output.txt | python -m rsakiller -

# 只用纯 Python，不启动 Sage
python -m rsakiller --no-sage challenge.py

# 手给泄露量：phi、p 的近似值、d 的低位、RSA-CRT 故障签名
python -m rsakiller -n 0x.. -e 65537 -c 0x.. --phi 0x..
python -m rsakiller -n 0x.. -e 65537 --near-p 0x..
python -m rsakiller -n 0x.. -e 3 --d-low 0x.. --d-known-bits 300
python -m rsakiller -n 0x.. -e 65537 --sig 0x.. --signed-msg 0x..

# qInv + dq 低位（CISCN2024 ez_rsa 型；这是本轮新解出的题型）
python -m rsakiller chal.txt --only qinv_dq_low --qhunt-procs 4
# 已知 k 的大致范围时可大幅加速
python -m rsakiller chal.txt --only qinv_dq_low --qhunt-k-lo 40000 --qhunt-k-hi 50000

# e 的高位泄露（CISCN2024 OvO 型：e = e >> 200 << 200）
python -m rsakiller task.py output.txt --only e_high_leak

# 退化椭圆曲线（07 型：E: y²=x³+p·x+q，系数 a=p、b=q 就是 n 的因子）
python -m rsakiller challenge.sage output.txt --only ec_degenerate

# 已知明文的前后缀，中间一段未知
python -m rsakiller -n 0x.. -e 3 -c 0x.. --prefix 'flag{' --suffix '}' --unknown-len 16

# 查看全部攻击
python -m rsakiller --list
```

## 攻击清单

`python -m rsakiller --list` 会打印完整列表。按能力分组：

**参数泄露 / 直接解密**：`known_pq`、`known_d`、`known_phi`、`dp_dq_leak`、`d_leak`、`c_gcd_n`、`rsa_crt_fault`（Bellcore 故障签名）、`mt_replay`（MT19937 重放）

**部分密钥 / 高位泄露**：`qinv_dq_low`（qInv + dq 低位，枚举 k 的 Coppersmith —— **单看 qInv 等价于分解 n，但配上 dq 低 48 bit 就落进 Coppersmith 可行域**）、`e_high_leak`（e 由 p、q 组合且低位被抹零：先解近似二次方程取 p 初值，再用 Coppersmith 补足）

**椭圆曲线**：`ec_degenerate`（退化曲线 —— `E: y²=x³+p·x+q` 的系数 a=p、b=q **就是 n 的因子**，mod p 时 a≡0 使曲线退化，于是 `q ≡ Cy²−Cx³ (mod p)` 成为模未知因子的小根；分解后再在两条退化曲线上各求一次 e 的逆元还原 P）

**低指数 / 共模 / 相关消息**：`small_e_root`、`hastad`、`common_modulus`（含 gcd(e₁,e₂)>1）、`franklin_reiter`、`short_pad`（填充差未知）、`stereotyped`（已知明文前后缀）

**小私钥 / 近似参数**：`wiener`、`boneh_durfee`、`approx_power`（e ≈ n^k·v/u）、`near_p`（p 的近似值）、`partial_d`（d 的低位）

**部分信息（Coppersmith）**：`partial_p`（p 的高位或低位）、`m_high`（明文高位）、`stereotyped`

**n 的结构弱点**：`prime_power`（n = p^k）、`non_rsa`（n 是素数或素数幂）、`fermat` / `fermat_multiplier`、`special_structure`（Carmichael 数、Fibonacci/Lucas/阶乘等序列构造、Euler 两平方和）、`novelty_prime`

**分解兜底**：`small_q`、`common_factor`、`factordb`、`factorize`、`sage_heavy`

### 关于多解

`e` 与 `phi` 不互素时，满足 `c = m^e mod n` 的明文本来就不止一个（彼此差在尾部填充）。
工具会给出最像 flag 的那个，同时把**全部候选**列在结果里（`--json` 下有 `candidates` 字段），
由人确认。命令末尾的「注意」块就是这层提示。

## 自测

```bash
python tests/selftest.py --no-sage     # 24 项纯 Python
python tests/selftest.py --with-sage   # 29 项，含格攻击与三项新攻击
```

**注意**：含 Sage 的项必须在**系统 Python** 下跑。用 Sage 自带的 python 跑会失败——
它没有 pycryptodome，且 `find_sage()` 会返回 Cygwin 内路径（`/opt/.../src/bin/sage`），
Windows 下不可执行，导致 `run_jobs` 拿不到结果。

## 关于重型攻击的耗时

`qinv_dq_low` 要对 `k ∈ [1, e)` 逐个跑一次 dim=11 的 LLL，**全量约 2.6 小时（4 进程）**：

| 场景 | 实测 |
|---|---|
| 单次 LLL（dim=11） | ~0.11 s |
| 单核吞吐 | ~0.43 s/k |
| 4 进程并行 | ~2.1x（本机拐点，8 进程反降到 1.9x） |

所以它默认参与管线，但**强烈建议**用 `--qhunt-k-lo/--qhunt-k-hi` 限定区间；
`k` 无法从公开量先验缩小范围（`e·dq_low − 1 ≡ k·q − k (mod 2^48)` 里 `q` 也未知），
只有 `v2(k) ≤ v2(e·dq_low−1)` 这一条免费的筛选。

**Sage 在受限沙箱下起不来**：Windows 版 SageMath 的 Cygwin 运行时需要创建命名管道，
被文件沙箱拒绝时 bash 会直接死在 `couldn't create signal pipe, Win32 error 5`。
遇到「Sage 不可用」但 `sage --version` 能跑，先检查是不是沙箱拦的。

**常驻 worker 的两个通路陷阱**（都已在 `sagebridge.py` 修掉，改这里时别退回旧写法）：

1. `_ensure_worker` 不能持 `_WORKER_LOCK` 调 `_spawn_worker` —— 后者发布结果要拿同一把
   非重入锁，会自锁死。表现为首次 `run_jobs` 永久卡住。
2. worker 的 stdout 必须由**唯一一个后台线程**逐行读进队列，主线程从队列带超时地取。
   旧写法「每次起线程读一行 + join 超时」在超时后那个线程仍阻塞在管道上，
   随后 `close()` 关 stdout 要与它抢缓冲锁，同样永久死锁。

两条的表现都是「卡住不返回」，不是报错 —— 排查时先怀疑这类，而不是 Sage 慢。
一次性调用（`run_shards`）**绝不能用 `capture_output=True`**：Cygwin bash 拉起的孙进程
会继承管道写端，bash 先退出时 `subprocess.run` 读到 EOF 前会一直阻塞，`timeout=` 也救不回来。

## Sage 集成说明

`sagebridge.py` 自动识别两种 Sage 部署：

- **PATH 中的原生 sage**（Linux / macOS / conda）
- **Windows 官方 Cygwin 安装包**，通过 `runtime/bin/bash.exe -lc` 调用

Cygwin 版有几个必须的约定：

- 必须使用 Cygwin 内部路径 `/opt/sagemath-9.3/...`，走 `/cygdrive/...` 会卡死
- 必须 `CCACHE_DISABLE=1`，默认 ccache 在本机会死锁
- 挂载只在 login shell（`-lc`）下生效，且需要 `runtime/tmp` 目录存在
- 跨进程调用要传 `stdin=DEVNULL`，否则 sage 可能进 REPL 阻塞

找不到 Sage 时会自动回退纯 Python 路径，不影响常见题型。

## 依赖

- Python 3.9+
- 可选：SageMath（格攻击、Coppersmith 等重型攻击需要）
- `pycryptodome`、`gmpy2`（部分攻击与题目脚本使用）

## 说明

题目样本文件以 SHA256 命名，是实战中喂给工具的原始题目数据，保留用于回归测试。
