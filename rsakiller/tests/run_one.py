# -*- coding: utf-8 -*-
"""在 Sage 环境下单独跑 selftest 的某一项（合成题需要 Sage）。"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

name = sys.argv[1] if len(sys.argv) > 1 else "t_ec_degenerate"
sys.argv = ["selftest.py", "--with-sage"]

import selftest as T  # noqa: E402

fn = getattr(T, name)
fn()
for r in T.RESULTS:
    print(r)
