// Passkey (WebAuthn) sign-in and registration for the securegate dashboard.
(() => {
  "use strict";
  if (!window.PublicKeyCredential) {
    document.querySelectorAll("[data-passkey-login], [data-passkey-register]").forEach((el) => {
      el.disabled = true;
      el.title = "This browser does not support passkeys";
    });
    return;
  }

  const b64urlToBuf = (s) => {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
  };
  const bufToB64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const decodeDescriptors = (list) => (list || []).map((d) => ({ ...d, id: b64urlToBuf(d.id) }));

  const credentialToJSON = (cred) => {
    const r = cred.response;
    const response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = bufToB64url(r.attestationObject);
      if (r.getTransports) response.transports = r.getTransports();
    } else {
      response.authenticatorData = bufToB64url(r.authenticatorData);
      response.signature = bufToB64url(r.signature);
      if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
    }
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response,
    };
  };

  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

  const post = async (url, body, auth) => {
    const headers = { "Content-Type": "application/json" };
    if (auth) headers["X-CSRF-Token"] = csrf();
    const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body || {}), credentials: "same-origin" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
    return data;
  };

  const showError = (el, err) => {
    if (err && (err.name === "AbortError")) return;
    const box = el.closest("section, .card, main")?.querySelector(".passkey-error");
    const msg = err && err.name === "NotAllowedError"
      ? "The passkey prompt was closed or timed out."
      : (err && err.message) || "Something went wrong.";
    if (box) {
      box.textContent = msg;
      box.hidden = false;
    } else {
      alert(msg);
    }
  };

  const go = (redirect) => { window.location.assign(redirect || "/"); };

  // Sign in.
  let conditional = null;

  const signIn = async (rd, mediation, signal) => {
    const opts = await post("/login/passkey/options?rd=" + encodeURIComponent(rd || "/"));
    const pk = opts.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.allowCredentials = decodeDescriptors(pk.allowCredentials);
    const cred = await navigator.credentials.get({ publicKey: pk, mediation, signal });
    const result = await post("/login/passkey", credentialToJSON(cred));
    go(result.redirect);
  };

  document.querySelectorAll("[data-passkey-login]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (conditional) conditional.abort();
      btn.disabled = true;
      try {
        await signIn(btn.dataset.rd);
      } catch (err) {
        showError(btn, err);
      } finally {
        btn.disabled = false;
      }
    });
  });

  // Offer passkeys in the email field's autofill, where supported.
  const autofill = document.querySelector('input[autocomplete~="webauthn"]');
  const loginBtn = document.querySelector("[data-passkey-login]");
  if (autofill && loginBtn && PublicKeyCredential.isConditionalMediationAvailable) {
    PublicKeyCredential.isConditionalMediationAvailable().then((ok) => {
      if (!ok) return;
      conditional = new AbortController();
      signIn(loginBtn.dataset.rd, "conditional", conditional.signal).catch((err) => {
        if (err.name !== "AbortError" && err.name !== "NotAllowedError") showError(loginBtn, err);
      });
    });
  }

  // Register.
  document.querySelectorAll("[data-passkey-register]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        const opts = await post("/account/passkeys/options", {}, true);
        const pk = opts.publicKey;
        pk.challenge = b64urlToBuf(pk.challenge);
        pk.user.id = b64urlToBuf(pk.user.id);
        pk.excludeCredentials = decodeDescriptors(pk.excludeCredentials);
        const cred = await navigator.credentials.create({ publicKey: pk });
        const nameInput = btn.dataset.nameInput && document.querySelector('[name="' + btn.dataset.nameInput + '"]');
        const params = new URLSearchParams({ name: nameInput ? nameInput.value : "", rd: btn.dataset.rd || "/account" });
        const result = await post("/account/passkeys?" + params, credentialToJSON(cred), true);
        go(result.redirect);
      } catch (err) {
        if (err && err.name === "InvalidStateError") err = new Error("This device already has a passkey for your account.");
        showError(btn, err);
      } finally {
        btn.disabled = false;
      }
    });
  });
})();
