// Calls to the dashboard's API. Every call that changes something carries
// the session's CSRF token; an error comes back as an ApiError whose
// message is the server's, written for the person reading it.

import { app } from "@ui/lib/store.js"

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error || `The request failed (${status}).`)
    this.status = status
    this.body = body || {}
  }
}

export const api = async (method, path, body) => {
  const headers = {}
  if (body !== undefined) headers["Content-Type"] = "application/json"
  if (method !== "GET" && app.csrf) headers["X-CSRF-Token"] = app.csrf
  let response
  try {
    response = await fetch("/api" + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    })
  } catch {
    throw new ApiError(0, { error: "gate2sky can't be reached. Check your connection and try again." })
  }
  if (response.status === 204) return null
  const data = await response.json().catch(() => null)
  if (response.status === 401 && app.user) {
    // The session ended elsewhere (sign-out, expiry, a disabled account):
    // back to the sign-in form, which returns here.
    app.user = null
    app.csrf = ""
  }
  if (!response.ok) throw new ApiError(response.status, data)
  return data
}
