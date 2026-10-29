// The demo's code colours: a component file — its markup, its <script>
// and its <style> — as HTML for jq79's `:html`, each token a
// `<span class="hl-…">`. The spans arrive through `:html`, which a scoped
// style does not reach, so their colours are the page's (`demo.css`).
// Enough to read a component by, not a parser: a token it does not know
// is drawn plain.

const escape = text => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
const span = (kind, text) => `<span class="hl-${kind}">${escape(text)}</span>`

// Tries the rules in order at each position: the first that matches there
// colours what it matched (or leaves it plain, with no kind); a character
// none matches is plain.
const lex = (text, rules) => {
  let out = ""
  let plain = ""
  let i = 0
  next: while (i < text.length) {
    for (const [kind, re] of rules) {
      re.lastIndex = i
      const m = re.exec(text)
      if (!m || !m[0].length) continue
      if (plain) {
        out += escape(plain)
        plain = ""
      }
      out += typeof kind === "function" ? kind(m[0]) : kind ? span(kind, m[0]) : escape(m[0])
      i += m[0].length
      continue next
    }
    plain += text[i++]
  }
  return out + escape(plain)
}

const STRINGS = [
  ["string", /"(?:[^"\\\n]|\\.)*"?/y],
  ["string", /'(?:[^'\\\n]|\\.)*'?/y],
]

const JS = [
  ["comment", /\/\/[^\n]*/y],
  ["comment", /\/\*[\s\S]*?(?:\*\/|$)/y],
  ...STRINGS,
  ["string", /`(?:[^`\\]|\\[\s\S])*`?/y],
  ["keyword", /(?:const|let|var|await|async|return|if|else|for|of|in|new|function|import|export|from|try|catch|finally|throw|typeof|instanceof|while|break|continue|null|undefined|true|false|this)(?![\w$])/y],
  // jq79's own: `$:`, `$emit`, `$self`, `$updateModel`…
  ["builtin", /\$[A-Za-z]\w*|\$(?=:)/y],
  ["number", /\d[\d_]*(?:\.\d+)?(?:e[+-]?\d+)?/y],
  [null, /[A-Za-z_$][\w$]*/y],
]

const CSS = [
  ["comment", /\/\*[\s\S]*?(?:\*\/|$)/y],
  ...STRINGS,
  ["keyword", /@[\w-]+/y],
  ["variable", /--[\w-]+/y],
  // A property is followed by its value and a `;` or `}`, before any `{`;
  // a selector by a `{`.
  ["property", /[\w-]+(?=\s*:[^;{}]*[;}])/y],
  ["selector", /[.#]?[\w-]+(?=[^;{}]*\{)/y],
  ["number", /#[0-9a-fA-F]{3,8}(?![\w-])|-?\d*\.?\d+(?:[a-z]+|%)?/y],
  ["builtin", /[\w-]+(?=\()/y],
  [null, /[\w-]+/y],
]

const ATTRIBUTES = [
  // A value can run over lines: a `:setup` and its props.
  ["string", /"[^"]*"?/y],
  ["string", /'[^']*'?/y],
  // jq79's: `:if`, `:class.on`, `@click`, `:slot.foot`…
  ["directive", /[:@][\w.:-]*/y],
  ["attr", /[\w-]+/y],
]

// A tag: its name — a component's, capitalised, apart — and its attributes.
const tag = text => {
  const m = /^(<\/?)([A-Za-z][\w.-]*)([\s\S]*?)(\/?>)?$/.exec(text)
  if (!m) return escape(text)
  return escape(m[1]) + span(/^[A-Z]/.test(m[2]) ? "component" : "tag", m[2]) +
    lex(m[3], ATTRIBUTES) + escape(m[4] || "")
}

const MARKUP = [
  ["comment", /<!--[\s\S]*?(?:-->|$)/y],
  [tag, /<\/?[A-Za-z][\w.-]*(?:[^>"']|"[^"]*"|'[^']*')*>?/y],
  ["interpolation", /\{\{[\s\S]*?(?:\}\}|$)/y],
  [null, /[^<{]+/y],
]

export const highlight = source => {
  const parts = /(<script\b[^>]*>)([\s\S]*?)(<\/script>|$)|(<style\b[^>]*>)([\s\S]*?)(<\/style>|$)/g
  let out = ""
  let last = 0
  let m
  while ((m = parts.exec(source))) {
    out += lex(source.slice(last, m.index), MARKUP)
    out += m[1] !== undefined
      ? lex(m[1], MARKUP) + lex(m[2], JS) + lex(m[3], MARKUP)
      : lex(m[4], MARKUP) + lex(m[5], CSS) + lex(m[6], MARKUP)
    last = parts.lastIndex
    if (last >= source.length) break
  }
  return out + lex(source.slice(last), MARKUP)
}
