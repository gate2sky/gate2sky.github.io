// The theme's tokens, for the inspector to edit: each `--ig-…` that
// `tokens.css` declares, in the block it is declared in — `root`, the same
// in both tones, or `dark` or `light` — and where its value is in the file,
// so an edit is written back where a person would write it and leaves as a
// patch. And the colours: a value the browser's colour picker takes, and
// the value back with the colour picked. The demo's, not the theme's.

// The blocks whose tokens can be edited, by their selector. Any other (an
// `@media`'s) is left as it is.
const SCOPES = { ":root": "root", ':root, [data-tone="dark"]': "dark", '[data-tone="light"]': "light" }

// Comments as spaces, so what one says is not read as code and every index
// still points into the file.
const blank = text => text.replace(/\/\*[\s\S]*?\*\//g, c => c.replace(/[^\n]/g, " "))

// Every token, in the file's order: `{ key, scope, name, value, start, end }`,
// its value at `start…end`. `key` is `scope:name`.
export const parseTokens = text => {
  const code = blank(text)
  const tokens = []
  let depth = 0
  let from = 0
  let selector = ""
  for (let i = 0; i < code.length; i++) {
    if (code[i] === "{") {
      if (depth++ === 0) {
        selector = code.slice(from, i).trim().replace(/\s+/g, " ")
        from = i + 1
      }
    } else if (code[i] === "}" && --depth === 0) {
      const scope = SCOPES[selector]
      const declaration = /(--ig-[\w-]+)(\s*:\s*)([^;]*[^;\s])\s*;/g
      let m
      while (scope && (m = declaration.exec(code.slice(from, i)))) {
        const start = from + m.index + m[1].length + m[2].length
        const end = start + m[3].length
        tokens.push({ key: scope + ":" + m[1], scope, name: m[1], value: text.slice(start, end), start, end })
      }
      from = i + 1
    }
  }
  return tokens
}

// The file with `values` (by key) in place of what it declares.
export const writeTokens = (text, tokens, values) => {
  let out = text
  for (const token of [...tokens].sort((a, b) => b.start - a.start)) {
    const value = values[token.key]
    if (value !== undefined && value !== token.value) out = out.slice(0, token.start) + value + out.slice(token.end)
  }
  return out
}

// A value that cannot break out of its declaration.
export const usable = value => !!value.trim() && !/[;{}]/.test(value)

// CSS that declares `values` on what `where` selects, and on each island of
// a tone inside it, over what `tokens.css` declares there.
export const declare = (where, values) => {
  const scopes = { root: [where], dark: [where, `${where} [data-tone="dark"]`], light: [`${where} [data-tone="light"]`] }
  const by = { root: "", dark: "", light: "" }
  for (const [key, value] of Object.entries(values)) {
    const [scope, name] = key.split(":")
    if (by[scope] !== undefined && usable(value)) by[scope] += `${name}: ${value}; `
  }
  return Object.entries(by).filter(([, body]) => body).map(([scope, body]) => `${scopes[scope].join(", ")} { ${body}}\n`).join("")
}

// ---- colours ----------------------------------------------------------------

const HEX = /^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i
const RGB = /^rgba?\(\s*(\d+(?:\.\d+)?)[\s,]+(\d+(?:\.\d+)?)[\s,]+(\d+(?:\.\d+)?)\s*(?:[,/]\s*(\d*\.?\d+%?))?\s*\)$/i
const two = n => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, "0")

// The colour picker's `#rrggbb` for a hex colour or an `rgb()`, or null:
// the picker takes no other, and no alpha.
export const pickable = value => {
  let m = HEX.exec(value.trim())
  if (m) {
    const hex = m[1].length <= 4 ? [...m[1]].map(c => c + c).join("") : m[1]
    return "#" + hex.slice(0, 6).toLowerCase()
  }
  m = RGB.exec(value.trim())
  return m ? "#" + m.slice(1, 4).map(Number).map(two).join("") : null
}

// `value` with the picker's colour in it, written as it was: a hex stays a
// hex and an `rgb()` an `rgb()`, each keeping its alpha.
export const repick = (value, picked) => {
  let m = HEX.exec(value.trim())
  if (m) {
    const alpha = m[1].length === 4 ? m[1][3].repeat(2) : m[1].length === 8 ? m[1].slice(6) : ""
    return picked.toLowerCase() + alpha
  }
  m = RGB.exec(value.trim())
  if (!m) return picked
  const rgb = [1, 3, 5].map(i => parseInt(picked.slice(i, i + 2), 16)).join(" ")
  return m[4] ? `rgb(${rgb} / ${m[4]})` : `rgb(${rgb})`
}
