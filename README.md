# rsakiller

CTF RSA 通杀工具：自动解析题目参数，按「廉价攻击 → Sage 重型攻击 → 通用分解」的顺序逐条尝试，并对结果做校验。

## 架构

双引擎设计，纯 Python 快速路径负责毫秒级常见题型，Sage 重型路径负责格攻击，两者自动衔接。

| 模块 | 职责 |
| --- | --- |
| `rsakiller/cli.py` | 命令行入口，支持多文件输入（题目脚本 + 输出数据一起喂） |
| `rsakiller/ctx.py` | 参数解析：从代码/文本/注释中提取 n、e、c、p、q、dp、hint 等 |
| `rsakiller/solver.py` | 攻击编排与结果校验 |
| `rsakiller/attacks.py` | 纯 Python 攻击集（直接解密、小 q、Fermat、共模、广播、Wiener 等） |
| `rsakiller/bonedurfee.py` | Boneh-Durfee 格攻击 |
| `rsakiller/lll.py` | 纯 Python LLL 实现 |
| `rsakiller/modular.py` | 模运算工具 |
| `rsakiller/mt19937.py` | MT19937 状态恢复与种子预测 |
| `rsakiller/oracle.py` | 加解密/根运算封装 |
| `rsakiller/factor.py` | FactorDB 与通用分解 |
| `rsakiller/sagebridge.py` | 自动定位本机 Sage，JSON 任务协议，一次进程内批量跑完全部重型候选 |
| `rsakiller/sage_scripts/heavy.py` | Sage 侧实现：Coppersmith、Boneh-Durfee、Franklin-Reiter 等 |

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
```

## 自测

```bash
python tests/selftest.py --no-sage     # 15 项纯 Python
python tests/selftest.py --with-sage   # 17 项，含格攻击
```

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
