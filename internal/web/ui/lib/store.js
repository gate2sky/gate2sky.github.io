// The app's state: what the server told the page when it served it (the
// signed-in user, the CSRF token, which sign-in methods are on), and which
// page is showing.

import { $reactive } from "@ui/vendor/jq79.js"

const boot = JSON.parse(document.getElementById("boot").textContent)

export const app = $reactive({
  user: null,
  csrf: "",
  email_flow: "",
  error: null,
  ...boot,
  path: location.pathname,
  search: location.search,
  // A message after something was done: { kind: "ok" | "error", text }.
  toast: null,
})

// The pages the app draws itself. A link anywhere else (an OAuth provider,
// a tunnel) is an ordinary navigation.
const PAGES = [
  [/^\/$/, () => ({ page: "subdomains" })],
  [/^\/subdomains\/([^/]+)$/, m => ({ page: "subdomain", name: decodeURIComponent(m[1]) })],
  [/^\/account$/, () => ({ page: "account" })],
  [/^\/admin$/, () => ({ page: "admin" })],
  [/^\/login$/, () => ({ page: "login" })],
]

export const route = path => {
  for (const [pattern, page] of PAGES) {
    const match = path.match(pattern)
    if (match) return page(match)
  }
  return null
}

export const query = name => new URLSearchParams(app.search).get(name)

const sync = () => {
  app.path = location.pathname
  app.search = location.search
  app.error = null
}

export const go = (url, { replace = false } = {}) => {
  const to = new URL(url, location.href)
  if (to.origin !== location.origin || !route(to.pathname)) {
    location.assign(to.href)
    return
  }
  history[replace ? "replaceState" : "pushState"](null, "", to.pathname + to.search + to.hash)
  sync()
  window.scrollTo(0, 0)
}

addEventListener("popstate", sync)

// A click on a link to one of the app's pages changes the page in place.
document.addEventListener("click", event => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  const link = event.target.closest?.("a[href]")
  if (!link || link.target || link.hasAttribute("download")) return
  const to = new URL(link.href)
  if (to.origin !== location.origin || !route(to.pathname)) return
  event.preventDefault()
  go(to.href)
})

let toastTimer = null
export const toast = (text, kind = "ok") => {
  app.toast = { text, kind }
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { app.toast = null }, kind === "ok" ? 4000 : 10000)
}
