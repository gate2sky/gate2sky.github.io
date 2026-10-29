"""Builds pages/index.html from template.html: splices in the drawings whose
geometry is computed (the hero's two gates and their link, the How it works
gates and strands, the logo), the stars of the sky and the version in
VERSION, which the release regenerates the page for.

    python3 scripts/landing/gen.py scripts/landing/template.html pages/index.html
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hero  # noqa: E402

rnd = random.Random(79)


def f(x):
    return f"{x:.1f}".rstrip("0").rstrip(".")


def stars(n, w, h):
    out = []
    for i in range(n):
        x, y = rnd.uniform(0, w), rnd.uniform(0, h)
        r = rnd.choice([0.6, 0.8, 0.8, 1, 1, 1.3, 1.7])
        d = rnd.uniform(0, 6)
        out.append(f'<circle cx="{f(x)}" cy="{f(y)}" r="{r}" style="animation-delay:-{f(d)}s"/>')
    return "\n    ".join(out)


tpl = open(sys.argv[1]).read()
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
tpl = tpl.replace("@@VERSION@@", open(os.path.join(root, "VERSION")).read().strip())
tpl = tpl.replace("@@HERO@@", hero.hero())
tpl = tpl.replace("@@BRAND@@", hero.brand())
# How it works: the gate at your machine, the tube, gate2sky's gate.
tpl = tpl.replace("@@FLOW_STRANDS_W@@", hero.flow_strands(360, 150, 184))
tpl = tpl.replace("@@FLOW_GATES_W@@", hero.gate("home", (262, 150), 0, 0.58) + "\n          " + hero.gate("web", (490, 150), 0, 1.05))
tpl = tpl.replace("@@FLOW_STRANDS_T@@", hero.flow_strands(160, 258, 144, 90))
tpl = tpl.replace("@@FLOW_GATES_T@@", hero.gate("home", (160, 176), 90, 0.5) + "\n          " + hero.gate("web", (160, 352), 90, 1.0))
tpl = tpl.replace("@@STARS@@", stars(90, 1600, 1000))
open(sys.argv[2], "w").write(tpl)
