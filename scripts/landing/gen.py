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
    """The sky in three layers, far to near: each pans left at its own pace
    and is drawn twice, a width apart, so the loop has no seam; and a few
    shooting stars."""
    layers = []
    for i, (share, sizes) in enumerate([(0.5, [0.5, 0.6, 0.8]), (0.32, [0.8, 1, 1]), (0.18, [1.2, 1.4, 1.7])]):
        out = []
        for _ in range(round(n * share)):
            x, y = rnd.uniform(0, w), rnd.uniform(0, h)
            d = rnd.uniform(0, 6)
            r = rnd.choice(sizes)
            for dx in (0, w):
                out.append(f'<circle cx="{f(x + dx)}" cy="{f(y)}" r="{r}" style="animation-delay:-{f(d)}s"/>')
        layers.append(f'<g class="pan pan-{i + 1}">' + "".join(out) + "</g>")
    meteors = []
    for x, y, a, t, d in [(1250, 90, 152, 11, 2), (700, 40, 160, 17, 9), (1500, 300, 148, 23, 15)]:
        meteors.append(f'<g class="meteor" style="--x:{x}px;--y:{y}px;--a:{a}deg;animation-duration:{t}s;animation-delay:{d}s">'
                       '<line x2="140" stroke="url(#meteor)"/></g>')
    defs = ('<defs><linearGradient id="meteor" gradientUnits="userSpaceOnUse" x2="140">'
            '<stop offset="0" stop-color="var(--star)" stop-opacity="0"/>'
            '<stop offset="1" stop-color="var(--star)"/></linearGradient></defs>')
    return "\n    ".join([defs] + layers + ['<g class="meteors">' + "".join(meteors) + "</g>"])


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
tpl = tpl.replace("@@STARS@@", stars(110, 1600, 1000))
open(sys.argv[2], "w").write(tpl)
