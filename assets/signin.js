"use strict";

/* project-lore sign-in helpers shared by the admin page and the OAuth
   consent page: passkeys (WebAuthn) and the second step of a sign-in.
   The server sends WebAuthn options as JSON with base64url fields; this
   file turns them into what navigator.credentials wants and the answers
   back into JSON. No dependencies; DOM through textContent only. */

(function () {
  function b64urlToBytes(text) {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "===".slice((base64.length + 3) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bytesToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function available() {
    return !!window.PublicKeyCredential && !!navigator.credentials;
  }

  function descriptors(list) {
    return (list || []).map((item) => ({ ...item, id: b64urlToBytes(item.id) }));
  }

  function creationOptions(json) {
    return {
      ...json,
      challenge: b64urlToBytes(json.challenge),
      user: { ...json.user, id: b64urlToBytes(json.user.id) },
      excludeCredentials: descriptors(json.excludeCredentials),
    };
  }

  function requestOptions(json) {
    return {
      ...json,
      challenge: b64urlToBytes(json.challenge),
      allowCredentials: descriptors(json.allowCredentials),
    };
  }

  function registrationJSON(credential) {
    const response = credential.response;
    const transports = typeof response.getTransports === "function" ? response.getTransports() : [];
    return {
      id: credential.id,
      rawId: bytesToB64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      response: {
        clientDataJSON: bytesToB64url(response.clientDataJSON),
        attestationObject: bytesToB64url(response.attestationObject),
        transports,
      },
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    };
  }

  function assertionJSON(credential) {
    const response = credential.response;
    return {
      id: credential.id,
      rawId: bytesToB64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      response: {
        clientDataJSON: bytesToB64url(response.clientDataJSON),
        authenticatorData: bytesToB64url(response.authenticatorData),
        signature: bytesToB64url(response.signature),
        userHandle: response.userHandle ? bytesToB64url(response.userHandle) : null,
      },
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    };
  }

  /* What a browser error from a passkey prompt means, in words. */
  function errorText(problem, creating) {
    const name = problem && problem.name;
    if (name === "NotAllowedError") return "The passkey prompt was closed or timed out.";
    if (name === "InvalidStateError" && creating) return "This authenticator already holds a passkey for you here.";
    if (name === "SecurityError") return "Passkeys do not work on this address.";
    if (name === "NotSupportedError") return "This browser or authenticator does not support what lore asks for.";
    return (problem && problem.message) || "The passkey did not work.";
  }

  /* POSTs JSON; returns { response, body }. */
  async function post(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
    const body = await response.json().catch(() => ({}));
    return { response, body };
  }

  /* Asks the browser for an assertion; a refused prompt becomes an
     answer the caller shows like a server error. */
  async function getAssertion(options) {
    try {
      const credential = await navigator.credentials.get({ publicKey: requestOptions(options.publicKey) });
      return { credential: assertionJSON(credential) };
    } catch (problem) {
      return { error: errorText(problem, false) };
    }
  }

  function failed(message, status) {
    return { response: { ok: false, status: status || 0, headers: new Headers() }, body: { error: message } };
  }

  /* Signs in with a passkey alone. */
  async function passkeySignIn() {
    const options = await post("/admin/api/login/passkey/options");
    if (!options.response.ok) return options;
    const answer = await getAssertion(options.body);
    if (answer.error) return failed(answer.error);
    return post("/admin/api/login/passkey", { ceremony: options.body.ceremony, credential: answer.credential });
  }

  /* The second step with a passkey. */
  async function secondFactorPasskey() {
    const options = await post("/admin/api/login/second-factor/passkey-options");
    if (!options.response.ok) return options;
    const answer = await getAssertion(options.body);
    if (answer.error) return failed(answer.error);
    return post("/admin/api/login/second-factor", {
      method: "passkey", ceremony: options.body.ceremony, credential: answer.credential,
    });
  }

  function secondFactorCode(method, code) {
    return post("/admin/api/login/second-factor", { method, code });
  }

  function cancelPending() {
    return post("/admin/api/login/cancel");
  }

  /* Adds a passkey to the signed-in account. `send` is the page's fetch
     wrapper (it handles re-authentication). */
  async function registerPasskey(name, send) {
    const options = await send("/admin/api/security/passkeys/options", { name });
    if (!options.response.ok) return options;
    let credential;
    try {
      credential = await navigator.credentials.create({ publicKey: creationOptions(options.body.publicKey) });
    } catch (problem) {
      return failed(errorText(problem, true));
    }
    return send("/admin/api/security/passkeys", {
      ceremony: options.body.ceremony, credential: registrationJSON(credential),
    });
  }

  /* Confirms it is you with a passkey (user verification). */
  async function reauthPasskey() {
    const options = await post("/admin/api/security/reauth/options");
    if (!options.response.ok) return options;
    const answer = await getAssertion(options.body);
    if (answer.error) return failed(answer.error);
    return post("/admin/api/security/reauth", { ceremony: options.body.ceremony, credential: answer.credential });
  }

  function tooMany(response) {
    const wait = Number(response.headers.get("Retry-After")) || 60;
    return `Too many attempts. Try again in ${Math.ceil(wait / 60)} min.`;
  }

  /* Wires the second-step card (same ids on both pages). `onDone(body)`
     gets a successful sign-in's answer, `onRestart(message)` is called
     when the password has to be entered again. Returns show/hide. */
  function secondFactorCard(handlers) {
    const $ = (id) => document.getElementById(id);
    const card = $("second-factor");
    if (!card) return { show() {}, hide() {} };
    const error = $("sf-error");
    let methods = [];
    let busy = false;

    function useRecovery(on) {
      $("sf-code-field").hidden = on || !methods.includes("totp");
      $("sf-recovery-field").hidden = !on;
      $("sf-submit").hidden = !(on || methods.includes("totp"));
      $("sf-use-recovery").hidden = on || !methods.includes("recovery");
      $("sf-use-recovery").textContent = methods.includes("totp")
        ? "Use a recovery code instead" : "Use a recovery code";
      const focus = on ? $("sf-recovery") : $("sf-code");
      if (!focus.closest("[hidden]")) focus.focus();
    }

    function show(info) {
      methods = (info && info.methods) || [];
      $("sf-user").textContent = (info && info.username) || "";
      error.textContent = "";
      $("sf-code").value = "";
      $("sf-recovery").value = "";
      $("sf-passkey").hidden = !(methods.includes("passkey") && available());
      card.hidden = false;
      useRecovery(!methods.includes("totp") && methods.includes("recovery") && !methods.includes("passkey"));
      if (!methods.length) {
        error.textContent = "None of your second steps can be checked here. Ask an administrator to reset your second steps.";
      } else if (methods.includes("passkey") && !methods.includes("totp")) {
        $("sf-passkey").focus();
      }
    }

    function hide() {
      card.hidden = true;
      error.textContent = "";
      $("sf-code").value = "";
      $("sf-recovery").value = "";
    }

    async function finish(result) {
      const { response, body } = result;
      if (response.ok) {
        hide();
        handlers.onDone(body);
        return;
      }
      if (body.restart) {
        hide();
        handlers.onRestart(body.error || "Enter the password again.");
        return;
      }
      error.textContent = response.status === 429 ? tooMany(response) : (body.error || "That did not work.");
    }

    async function run(task) {
      if (busy) return;
      busy = true;
      error.textContent = "";
      try {
        await finish(await task());
      } catch (_) {
        error.textContent = "Lore cannot be reached. Check the connection and try again.";
      } finally {
        busy = false;
      }
    }

    card.addEventListener("submit", (event) => {
      event.preventDefault();
      const recovery = !$("sf-recovery-field").hidden;
      const code = recovery ? $("sf-recovery").value : $("sf-code").value;
      if (!code.trim()) { error.textContent = "Enter the code."; return; }
      run(() => secondFactorCode(recovery ? "recovery" : "totp", code));
    });
    $("sf-passkey").addEventListener("click", () => run(secondFactorPasskey));
    $("sf-use-recovery").addEventListener("click", () => useRecovery(true));
    $("sf-cancel").addEventListener("click", async () => {
      await cancelPending().catch(() => {});
      hide();
      handlers.onRestart("");
    });
    return { show, hide };
  }

  window.loreSignIn = {
    b64urlToBytes, bytesToB64url, available, creationOptions, requestOptions,
    registrationJSON, assertionJSON, errorText, passkeySignIn, secondFactorPasskey,
    secondFactorCode, cancelPending, registerPasskey, reauthPasskey, secondFactorCard, tooMany,
  };
})();
