// Passkeys (WebAuthn): signing in with one, and adding one to the account.
// The server speaks the JSON of go-webauthn; the browser wants buffers.

import { api, ApiError } from "@ui/lib/api.js"

export const supported = Boolean(window.PublicKeyCredential)

const fromB64url = text => {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=")
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer
}

const toB64url = buffer =>
  btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

const descriptors = list => (list || []).map(d => ({ ...d, id: fromB64url(d.id) }))

const credentialJSON = credential => {
  const r = credential.response
  const response = { clientDataJSON: toB64url(r.clientDataJSON) }
  if (r.attestationObject) {
    response.attestationObject = toB64url(r.attestationObject)
    if (r.getTransports) response.transports = r.getTransports()
  } else {
    response.authenticatorData = toB64url(r.authenticatorData)
    response.signature = toB64url(r.signature)
    if (r.userHandle) response.userHandle = toB64url(r.userHandle)
  }
  return {
    id: credential.id,
    rawId: toB64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response,
  }
}

// signIn asks for a passkey and signs in with it, resolving to where the
// app goes next. `mediation: "conditional"` offers passkeys in the email
// field's autofill instead of a dialog.
export const signIn = async (rd, { mediation, signal } = {}) => {
  const options = await api("POST", "/login/passkey/options?rd=" + encodeURIComponent(rd || "/"))
  const publicKey = options.publicKey
  publicKey.challenge = fromB64url(publicKey.challenge)
  publicKey.allowCredentials = descriptors(publicKey.allowCredentials)
  const credential = await navigator.credentials.get({ publicKey, mediation, signal })
  const result = await api("POST", "/login/passkey", credentialJSON(credential))
  return result.redirect || "/"
}

export const autofillAvailable = async () =>
  supported && Boolean(await PublicKeyCredential.isConditionalMediationAvailable?.().catch(() => false))

// register creates a passkey for the signed-in user and saves it.
export const register = async name => {
  const options = await api("POST", "/account/passkeys/options", {})
  const publicKey = options.publicKey
  publicKey.challenge = fromB64url(publicKey.challenge)
  publicKey.user.id = fromB64url(publicKey.user.id)
  publicKey.excludeCredentials = descriptors(publicKey.excludeCredentials)
  const credential = await navigator.credentials.create({ publicKey })
  return api("POST", "/account/passkeys?name=" + encodeURIComponent(name || ""), credentialJSON(credential))
}

// problem is what to tell the user when a ceremony failed, or "" when they
// cancelled it themselves.
export const problem = error => {
  if (!error || error.name === "AbortError") return ""
  if (error instanceof ApiError) return error.message
  if (error.name === "NotAllowedError") return "The passkey prompt was closed or timed out."
  if (error.name === "InvalidStateError") return "This device already has a passkey for your account."
  if (error.name === "SecurityError") return "Passkeys need the dashboard's own address (HTTPS, or localhost)."
  return error.message || "Something went wrong."
}
