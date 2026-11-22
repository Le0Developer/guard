"use strict";
(() => {
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const encode = value => {
    if (!value) return null;
    const bytes = new Uint8Array(value);
    let text = "";
    bytes.forEach(byte => { text += String.fromCharCode(byte); });
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  async function post(url, fields) {
    const response = await fetch(url, {method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:new URLSearchParams(fields), redirect:"error"});
    const value = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(value.error || "This request failed. Reload the page or sign in again.");
    return value;
  }
  document.querySelectorAll("form[data-webauthn]").forEach(form => {
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const button = form.querySelector("button[type=submit]");
      const status = form.querySelector("[data-status]");
      button.disabled = true; status.textContent = "Waiting for your security key…";
      try {
        if (!window.PublicKeyCredential || !navigator.credentials || !window.isSecureContext) throw new Error("Security keys require a supported browser and HTTPS (or localhost).");
        const fields = new FormData(form);
        const challenge = await post(form.action, fields);
        const publicKey = challenge.publicKey;
        publicKey.challenge = decode(publicKey.challenge);
        for (const item of publicKey.excludeCredentials || publicKey.allowCredentials || []) item.id = decode(item.id);
        const registering = form.dataset.webauthn === "register";
        if (registering) publicKey.user.id = decode(publicKey.user.id);
        const credential = registering ? await navigator.credentials.create({publicKey}) : await navigator.credentials.get({publicKey});
        if (!credential) throw new Error("No security-key response was received.");
        const result = {id:credential.id, rawId:encode(credential.rawId), type:credential.type, extensions:credential.getClientExtensionResults(), response:{clientDataJSON:encode(credential.response.clientDataJSON)}};
        if (registering) {
          result.response.attestationObject = encode(credential.response.attestationObject);
          if (credential.response.getTransports) result.response.transports = credential.response.getTransports();
        } else {
          result.response.authenticatorData = encode(credential.response.authenticatorData);
          result.response.signature = encode(credential.response.signature);
          result.response.userHandle = encode(credential.response.userHandle);
        }
        const done = await post(form.dataset.finish, {csrf_token:fields.get("csrf_token"), ceremony:challenge.ceremony, credential:JSON.stringify(result)});
        window.location.assign(done.redirect);
      } catch (error) {
        status.textContent = error.name === "NotAllowedError" ? "The security-key request was cancelled or timed out. Try again or use another method." : error.message;
      } finally { button.disabled = false; }
    });
  });
  document.querySelector("[data-download-codes]")?.addEventListener("click", () => {
    const codes = [...document.querySelectorAll("[data-backup-codes] code")].map(node => node.textContent);
    const blob = new Blob(["Guard backup codes\nEach code can be used once.\n\n" + codes.join("\n") + "\n"], {type:"text/plain;charset=utf-8"});
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "guard-backup-codes.txt";
    link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });
})();
