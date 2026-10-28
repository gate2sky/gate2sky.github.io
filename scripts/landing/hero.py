"""The hero drawing: two plain gates, one on the internet and one at home,
facing each other across an encrypted link. Requests leave the globe as
plain text, cross the link scrambled, and reach the house as plain text
again; responses go back the same way."""
import math

ANG = math.radians(27)          # the link's slope
CX, CY = 244, 212               # the link's middle
HALF = 96                       # from the middle to each gate
UX, UY = math.cos(ANG), math.sin(ANG)
CYCLE = 6                       # seconds for a request and its response
RESPONSE_AT = 4.4               # when the response leaves home


def f(x):
    return f"{x:.1f}".rstrip("0").rstrip(".")


def along(d):
    """The point d along the link from its middle (negative: towards the internet)."""
    return CX + d * UX, CY + d * UY


GATE_A = along(-HALF)
GATE_B = along(HALF)
GLOBE = along(-HALF - 92)
GLOBE = (GLOBE[0] - 6, GLOBE[1] - 10)
HOUSE = along(HALF + 96)
HOUSE = (HOUSE[0] + 4, HOUSE[1] + 6)
DOOR = (HOUSE[0] + 13.5, HOUSE[1] + 22)


def gate(name, at, rot=math.degrees(ANG), scale=1.0):
    """A gate: a ring, its glowing surface and three lamps; nothing more."""
    x, y = at
    lamps = []
    for i, t in enumerate((-90, -128, -52)):
        r = math.radians(t)
        lamps.append(f'<circle class="lamp" style="--i:{i}" cx="{f(21 * math.cos(r))}" cy="{f(58 * math.sin(r))}" r="3.4"/>')
    size = f" scale({f(scale)})" if scale != 1 else ""
    return f'''<g class="gate gate-{name}" transform="translate({f(x)} {f(y)}) rotate({f(rot)}){size}">
          <ellipse class="horizon" rx="17" ry="52"/>
          <ellipse class="shimmer" rx="17" ry="52"/>
          <ellipse class="ring" rx="21" ry="58"/>
          <ellipse class="ring-edge" rx="26" ry="64"/>
          {"".join(lamps)}
        </g>'''


def strand(phase, length=260, amp=8, wave=32):
    pts = []
    x = -length / 2
    while x <= length / 2 + 0.01:
        pts.append(f"{f(x)} {f(amp * math.sin(2 * math.pi * x / wave + phase))}")
        x += 2
    return "M" + " L".join(pts)


def chip(cls, text, path, window, begin):
    """A packet showing text, moving along path during window (fractions of
    the cycle) and hidden the rest of it."""
    a, b = window
    return f'''<g class="chip {cls}" opacity="0">
          <rect x="-20" y="-9" width="40" height="18" rx="9"/>
          <text y="3.6" text-anchor="middle">{text}</text>
          <animateMotion dur="{CYCLE}s" begin="{begin}s" repeatCount="indefinite" path="{path}"
            keyPoints="0;0;1;1" keyTimes="0;{a};{b};1" calcMode="linear"/>
          <animate attributeName="opacity" dur="{CYCLE}s" begin="{begin}s" repeatCount="indefinite"
            values="0;1;0" keyTimes="0;{a};{b}" calcMode="discrete"/>
        </g>'''


def cipher(cls, path, window, begin, seed):
    """A packet on the link: its bytes keep changing."""
    a, b = window
    words = ["9f3a", "c71e", "04bd", "e28c", "5a90", "b3f1"]
    words = words[seed:] + words[:seed]
    flicker = []
    for i, w in enumerate(words[:3]):
        flicker.append(f'''<text y="3.6" text-anchor="middle" opacity="0">{w}<animate attributeName="opacity" dur=".42s" begin="{(0, 0.14, 0.28)[i]}s" repeatCount="indefinite" values="1;0" keyTimes="0;.33" calcMode="discrete"/></text>''')
    return f'''<g class="chip cipher {cls}" opacity="0">
          <rect x="-21" y="-9" width="42" height="18" rx="4"/>
          {"".join(flicker)}
          <animateMotion dur="{CYCLE}s" begin="{begin}s" repeatCount="indefinite" path="{path}"
            keyPoints="0;0;1;1" keyTimes="0;{a};{b};1" calcMode="linear"/>
          <animate attributeName="opacity" dur="{CYCLE}s" begin="{begin}s" repeatCount="indefinite"
            values="0;1;0" keyTimes="0;{a};{b}" calcMode="discrete"/>
        </g>'''


def line(p, q):
    return f"M{f(p[0])} {f(p[1])} L{f(q[0])} {f(q[1])}"


def hero():
    gx, gy = GLOBE
    hx, hy = HOUSE
    a_in = along(-HALF - 8)      # where traffic enters gate A from the internet
    b_out = along(HALF + 8)
    link_a = along(-HALF + 22)
    link_b = along(HALF - 22)
    globe_edge = (gx + 34 * UX, gy + 34 * UY)
    seg1 = line(globe_edge, a_in)
    seg3 = line(b_out, DOOR)
    link = line(link_a, link_b)
    seg1_r = line(a_in, globe_edge)
    seg3_r = line(DOOR, b_out)
    link_r = line(link_b, link_a)

    deg = f(math.degrees(ANG))
    return f'''<svg class="duo" viewBox="0 40 480 360" role="img" aria-label="Two gates linked by an encrypted tunnel: one on the internet, one at home. Requests reach the first gate in plain text, cross the link scrambled, and arrive home readable again; responses travel back the same way.">
        <defs>
          <clipPath id="link-clip"><rect x="-74" y="-15" width="148" height="30" rx="15"/></clipPath>
        </defs>

        <!-- the internet: a globe, visitors circling it -->
        <g class="globe" transform="translate({f(gx)} {f(gy)})">
          <circle class="sphere" r="34"/>
          <ellipse class="meridian m1" rx="34" ry="34"/>
          <ellipse class="meridian m2" rx="17" ry="34"/>
          <path class="parallel" d="M-34 0H34M-29.4 -17H29.4M-29.4 17H29.4"/>
          <circle class="visitor" r="3.2"><animateMotion dur="7s" repeatCount="indefinite" path="M-48 0a48 18 -20 1 0 96 0a48 18 -20 1 0 -96 0"/></circle>
          <circle class="visitor" r="2.6"><animateMotion dur="7s" begin="-2.4s" repeatCount="indefinite" path="M-48 0a48 18 -20 1 0 96 0a48 18 -20 1 0 -96 0"/></circle>
          <circle class="visitor" r="2.2"><animateMotion dur="7s" begin="-4.7s" repeatCount="indefinite" path="M-48 0a48 18 -20 1 0 96 0a48 18 -20 1 0 -96 0"/></circle>
        </g>
        <text class="cap" x="{f(gx)}" y="{f(gy + 62)}" text-anchor="middle">the internet</text>

        <!-- plain traffic on either side -->
        <path class="wire" d="{seg1}"/>
        <path class="wire" d="{seg3}"/>

        <!-- the link: a tube with two strands twisting through it -->
        <g transform="translate({f(CX)} {f(CY)}) rotate({deg})">
          <path class="tube" d="M-74 0H74"/>
          <path class="tube-edge" d="M-74 -15H74M-74 15H74"/>
          <g clip-path="url(#link-clip)">
            <g class="twist">
              <path class="strand s1" d="{strand(0)}"/>
              <path class="strand s2" d="{strand(math.pi)}"/>
            </g>
          </g>
        </g>
        <g class="lock" transform="translate({f(CX - 40 * UY)} {f(CY + 40 * UX)})">
          <rect x="-10" y="-4" width="20" height="15" rx="3.5"/>
          <path class="shackle" d="M-5.5 -4v-4.5a5.5 5.5 0 0 1 11 0v4.5"/>
        </g>
        <text class="cap enc" x="{f(CX - 40 * UY)}" y="{f(CY + 40 * UX + 30)}" text-anchor="middle">encrypted</text>

        {gate("a", GATE_A)}
        {gate("b", GATE_B)}
        <text class="mono" x="{f(GATE_A[0] + 2)}" y="{f(GATE_A[1] - 78)}" text-anchor="middle">*.example.com</text>

        <!-- home -->
        <g class="house" transform="translate({f(hx)} {f(hy)})">
          <path class="fill" d="M-32 -12 L0 -38 L32 -12 V34 H-32 Z"/>
          <path class="roof" d="M-40 -6 L0 -40 L40 -6"/>
          <path class="walls" d="M-32 -12 V34 H32 V-12"/>
          <rect class="window" x="-22" y="-2" width="18" height="15" rx="2"/>
          <rect class="door" x="6" y="10" width="15" height="24" rx="2"/>
          <path class="chimney" d="M18 -25 V-38 H27 V-17"/>
        </g>
        <text class="cap" x="{f(hx)}" y="{f(hy + 56)}" text-anchor="middle">home</text>
        <text class="mono" x="{f(hx)}" y="{f(hy + 72)}" text-anchor="middle">localhost:3000</text>

        <!-- a request, and its response -->
        {chip("req", "GET /", seg1, (0, .2), 0)}
        {cipher("req", link, (.2, .58), 0, 0)}
        {chip("req", "GET /", seg3, (.58, .74), 0)}
        {chip("res", "200", seg3_r, (0, .14), RESPONSE_AT)}
        {cipher("res", link_r, (.14, .52), RESPONSE_AT, 3)}
        {chip("res", "200", seg1_r, (.52, .7), RESPONSE_AT)}
      </svg>'''


def brand():
    """The logo: two small gates and the link between them."""
    return '''<svg viewBox="0 0 40 40" aria-hidden="true">
        <path d="M11 26 L29 14" stroke="#ffa23a" stroke-width="2.4" stroke-linecap="round"/>
        <g transform="translate(9 27.5) rotate(-34)"><ellipse rx="4.6" ry="9.5" fill="url(#horizon)"/><ellipse rx="4.6" ry="9.5" fill="none" stroke="url(#metal)" stroke-width="3"/></g>
        <g transform="translate(31 12.5) rotate(-34)"><ellipse rx="4.6" ry="9.5" fill="url(#horizon)"/><ellipse rx="4.6" ry="9.5" fill="none" stroke="url(#metal)" stroke-width="3"/></g>
      </svg>'''


def flow_strands(cx, cy, length, rot=0):
    """The twisting strands inside a tube of the How it works drawing."""
    half = length / 2
    clip = f"flow-clip-{int(cx)}-{int(cy)}"
    return f'''<g transform="translate({f(cx)} {f(cy)}) rotate({f(rot)})">
            <clipPath id="{clip}"><rect x="{f(-half)}" y="-13" width="{f(length)}" height="26" rx="13"/></clipPath>
            <g clip-path="url(#{clip})"><g class="twist">
              <path class="strand s1" d="{strand(0, length + 70, 7)}"/>
              <path class="strand s2" d="{strand(math.pi, length + 70, 7)}"/>
            </g></g>
          </g>'''
