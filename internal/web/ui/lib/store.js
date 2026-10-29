// The app's state: what the server told the page when it served it (the
// signed-in user, the CSRF token, which sign-in methods are on), and which
// page is showing.

import { $reactive } from "@ui/vendor/jq79.js"
import { prefetch } from "@ui/lib/api.js"

const boot = JSON.parse(document.getElementById("boot").textContent)

export const app = $reactive({
  user: null,
  csrf: "",
  email_flow: "",
  error: null,
  ...boot,
  path: location.pathname,
  search: location.search,
  // A page is on its way: the one showing dims until it arrives.
  loading: false,
  // A message after something was done: { kind: "ok" | "error", text }.
  toast: null,
})

// The pages the app draws itself, and what each one asks the API for as
// it opens. A link anywhere else (an OAuth provider, a tunnel) is an
// ordinary navigation.
const PAGES = [
  [/^\/$/, () => ({ page: "subdomains", data: ["/subdomains"] })],
  [/^\/subdomains\/([^/]+)$/, m => {
    const name = decodeURIComponent(m[1])
    return { page: "subdomain", name, data: ["/subdomains/" + encodeURIComponent(name)] }
  }],
  [/^\/account$/, () => ({ page: "account", data: ["/account"] })],
  [/^\/admin$/, () => ({ page: "admin", data: ["/admin/subdomains", "/admin/users"] })],
  [/^\/login$/, () => ({ page: "login", data: [] })],
]

export const route = path => {
  for (const [pattern, page] of PAGES) {
    const match = path.match(pattern)
    if (match) return page(match)
  }
  return null
}

export const query = name => new URLSearchParams(app.search).get(name)

// The error first: it takes the page's place before the page could mount.
const sync = (error = null) => {
  app.error = error
  app.path = location.pathname
  app.search = location.search
}

// Changing page keeps the current one on screen, dimmed, while the next
// one's data loads, then shows it at once. If that fails, an error takes
// its place; a missing subdomain or a page that is not yours is the page's
// own to show. Only the
// latest of several quick changes lands.
let navigation = 0
const arrive = async (pathname, commit) => {
  const id = ++navigation
  const page = app.user && route(pathname)
  let failure = null
  app.loading = true
  try {
    await Promise.all((page?.data || []).map(prefetch))
  } catch (e) {
    if (![401, 403, 404].includes(e.status)) failure = e
  }
  if (id !== navigation) return
  app.loading = false
  commit()
  sync(failure && (failure.status
    ? { status: failure.status, title: "This page could not be loaded", message: failure.message, retry: true }
    : { title: "gate2sky can't be reached", message: "Check your connection and try again.", retry: true }))
}

export const go = (url, { replace = false } = {}) => {
  const to = new URL(url, location.href)
  if (to.origin !== location.origin || !route(to.pathname)) {
    location.assign(to.href)
    return
  }
  return arrive(to.pathname, () => {
    history[replace ? "replaceState" : "pushState"](null, "", to.pathname + to.search + to.hash)
    window.scrollTo(0, 0)
  })
}

// Back and forward have already changed the address.
addEventListener("popstate", () => arrive(location.pathname, () => {}))

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
