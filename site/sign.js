/* c2pa-inspector — sign a file in the browser.
   The private key lives in WebCrypto, non-extractable; Go (the wasm) builds
   and validates the manifest and asks WebCrypto for each signature. Nothing
   leaves the browser unless a timestamp authority is named. */
(function () {
  "use strict";

  var MAX_SIGN_BYTES = 64 * 1024 * 1024; // peak wasm memory is several times the file
  var UI_TIMEOUT_MS = 35000;             // re-enable the button if a promise never settles

  var $ = function (id) { return document.getElementById(id); };
  var credNone = document.querySelector("[data-cred-none]"), credHave = document.querySelector("[data-cred-have]");
  var credName = $("cred-name"), credCreate = $("cred-create"), credImportBtn = $("cred-import-btn");
  var importKey = $("import-key"), importChain = $("import-chain");
  var importKeyFile = $("import-key-file"), importChainFile = $("import-chain-file");
  var credSummary = document.querySelector("[data-cred-summary]"), credKind = document.querySelector("[data-cred-kind]");
  var credRemember = $("cred-remember"), credForget = $("cred-forget"), credStatus = $("cred-status");
  var signFile = $("sign-file"), signTitle = $("sign-title"), signAction = $("sign-action");
  var signDst = $("sign-dst"), signDstCustom = $("sign-dst-custom"), signTSA = $("sign-tsa");
  var signRole = $("sign-role");
  var signGo = $("sign-go"), signStatus = $("sign-status"), signResult = $("sign-result");
  var tpl = $("signed-template");
  if (!credNone || !signGo || !tpl) return;

  // --- state ---------------------------------------------------------------
  // cred is {key: CryptoKey, certPEM, summary, kind, label, createdAt} or null.
  var cred = null;
  var remember = false;
  var storageOK = typeof indexedDB !== "undefined";
  var chosen = null; // the File picked for signing

  // --- readiness -----------------------------------------------------------
  var ready = new Promise(function (resolve) {
    (function wait() {
      if (typeof window.c2paSign === "function") return resolve();
      setTimeout(wait, 10);
    })();
  });
  ready.then(function () {
    credCreate.disabled = false;
    credImportBtn.disabled = false;
    return loadCredential();
  }).then(function (rec) {
    if (rec && rec.key) { cred = rec; remember = true; }
    render();
  }).catch(function (err) {
    setStatus(credStatus, "Could not restore the remembered identity: " + message(err), "bad");
    render();
  });

  // --- IndexedDB: the CryptoKey is structured-cloneable and stays non-extractable
  function openDB() {
    return new Promise(function (resolve, reject) {
      if (!storageOK) return reject(new Error("IndexedDB is not available"));
      var req = indexedDB.open("c2pa-inspector", 1);
      req.onupgradeneeded = function () { req.result.createObjectStore("credential"); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error || new Error("IndexedDB open failed")); };
      req.onblocked = function () { reject(new Error("IndexedDB is blocked")); };
    });
  }
  function withStore(mode, fn) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction("credential", mode);
        var req = fn(tx.objectStore("credential"));
        tx.oncomplete = function () { db.close(); resolve(req && req.result); };
        tx.onerror = function () { db.close(); reject(tx.error || new Error("IndexedDB transaction failed")); };
        tx.onabort = function () { db.close(); reject(tx.error || new Error("IndexedDB transaction aborted")); };
      });
    });
  }
  function loadCredential() {
    if (!storageOK) return Promise.resolve(null);
    return withStore("readonly", function (s) { return s.get("current"); }).catch(function () { storageOK = false; return null; });
  }
  function saveCredential(rec) {
    return withStore("readwrite", function (s) { return s.put(rec, "current"); });
  }
  function clearCredential() {
    if (!storageOK) return Promise.resolve();
    return withStore("readwrite", function (s) { return s.delete("current"); }).catch(function () {});
  }

  // --- identity panel ------------------------------------------------------
  function render() {
    var have = !!cred;
    credNone.hidden = have;
    credHave.hidden = !have;
    if (have) {
      var s = cred.summary || {};
      credSummary.textContent = "";
      addRow(credSummary, "name", cred.label || s.label);
      addRow(credSummary, "subject", s.subject);
      if (s.issuer && s.issuer !== s.subject) addRow(credSummary, "issuer", s.issuer);
      addRow(credSummary, "algorithm", s.algorithm ? s.algorithm + " (" + s.cose + ")" : "");
      addRow(credSummary, "valid until", s.notAfter ? s.notAfter.slice(0, 10) : "");
      addRow(credSummary, "fingerprint", s.fingerprint ? "sha256:" + s.fingerprint.slice(0, 16) + "…" : "");
      credKind.textContent = cred.kind === "test"
        ? "Self-signed test identity — this browser issued the certificate to itself. Files you sign will verify, and every verifier will report the signer as untrusted."
        : "Imported identity — " + (s.chainLength || 1) + " certificate" + (s.chainLength === 1 ? "" : "s") + ". Verifiers trust it if your issuer is on the C2PA trust list.";
      credRemember.checked = remember;
      credRemember.disabled = !storageOK;
      credRemember.parentNode.title = storageOK ? "" : "This browser does not allow storage here (private window?)";
    }
    signGo.disabled = !(have && chosen);
  }

  function addRow(dl, key, val) {
    if (!val) return;
    var dt = document.createElement("dt"); dt.textContent = key;
    var dd = document.createElement("dd"); dd.textContent = val;
    dl.appendChild(dt); dl.appendChild(dd);
  }

  function adopt(result, kind, label) {
    cred = { v: 1, key: result.key, certPEM: result.certPEM, summary: result.summary, kind: kind,
      label: label || (result.summary && result.summary.label) || "", createdAt: new Date().toISOString() };
    remember = kind === "test" && storageOK; // opt-in default: on for a test identity, off for an imported key
    var persisted = remember ? saveCredential(cred).catch(function (err) {
      remember = false;
      setStatus(credStatus, "Identity ready, but it could not be remembered: " + message(err), "bad");
    }) : Promise.resolve();
    return persisted.then(function () {
      render();
      if (!credStatus.textContent) setStatus(credStatus, kind === "test" ? "Test identity created." : "Identity imported.", "");
    });
  }

  credCreate.addEventListener("click", function () {
    busy(credCreate, true);
    setStatus(credStatus, "Creating a key in WebCrypto…", "working");
    window.c2paCredentialCreate(credName.value).then(function (result) {
      setStatus(credStatus, "", "");
      return adopt(result, "test", credName.value.trim() || "Test identity");
    }).catch(function (err) {
      setStatus(credStatus, explain(err), "bad");
    }).finally(function () { busy(credCreate, false); });
  });

  credImportBtn.addEventListener("click", function () {
    busy(credImportBtn, true);
    setStatus(credStatus, "Importing into WebCrypto…", "working");
    window.c2paCredentialImport(importKey.value, importChain.value).then(function (result) {
      importKey.value = ""; // the PEM text is not kept; the key now lives only in WebCrypto
      setStatus(credStatus, "", "");
      return adopt(result, "imported", "");
    }).catch(function (err) {
      setStatus(credStatus, explain(err), "bad");
    }).finally(function () { busy(credImportBtn, false); });
  });

  function wireFile(input, textarea) {
    input.addEventListener("change", function () {
      var f = input.files && input.files[0];
      if (!f) return;
      f.text().then(function (txt) { textarea.value = txt; }, function () { setStatus(credStatus, "Could not read " + f.name, "bad"); });
      input.value = "";
    });
  }
  wireFile(importKeyFile, importKey);
  wireFile(importChainFile, importChain);

  credRemember.addEventListener("change", function () {
    if (!cred) return;
    remember = credRemember.checked;
    var p = remember ? saveCredential(cred) : clearCredential();
    p.then(function () {
      setStatus(credStatus, remember ? "Remembered in this browser." : "This identity will be forgotten when you leave.", "");
    }, function (err) {
      remember = false; credRemember.checked = false;
      setStatus(credStatus, "Could not remember it: " + message(err), "bad");
    });
  });

  credForget.addEventListener("click", function () {
    clearCredential().then(function () {
      cred = null; remember = false;
      signResult.textContent = "";
      setStatus(credStatus, "Identity forgotten. The key was never exportable, so there is nothing else to clean up.", "");
      render();
    });
  });

  // --- sign form -----------------------------------------------------------
  signFile.addEventListener("change", function () {
    chosen = signFile.files && signFile.files[0] || null;
    if (chosen && !signTitle.value) signTitle.placeholder = chosen.name;
    if (chosen && chosen.size > MAX_SIGN_BYTES) {
      setStatus(signStatus, "That file is " + Math.round(chosen.size / 1048576) + " MiB; signing in the browser is capped at 64 MiB.", "bad");
      chosen = null;
    } else {
      setStatus(signStatus, chosen ? "Ready to sign " + chosen.name + "." : "", "");
    }
    render();
  });

  signDst.addEventListener("change", function () {
    signDstCustom.hidden = signDst.value !== "custom";
  });

  signGo.addEventListener("click", function () {
    if (!cred || !chosen) return;
    var file = chosen;
    var title = signTitle.value.trim() || file.name;
    var dst = signDst.value === "custom" ? signDstCustom.value.trim() : signDst.value;
    var role = signRole ? signRole.value : "";
  var opts = { key: cred.key, certPEM: cred.certPEM, title: title, action: signAction.value,
    identityRoles: role ? [role] : [],
      digitalSourceType: dst, tsaURL: signTSA.value.trim() };
    busy(signGo, true);
    setStatus(signStatus, "Signing " + file.name + "…" + (opts.tsaURL ? " (contacting the timestamp authority)" : ""), "working");
    var timer = setTimeout(function () {
      busy(signGo, false);
      setStatus(signStatus, "Still signing… the page may be busy hashing a large file.", "working");
    }, UI_TIMEOUT_MS);
    // Let the status paint before the main thread goes into the wasm.
    setTimeout(function () {
      file.arrayBuffer().then(function (buf) {
        return window.c2paSign(new Uint8Array(buf), opts);
      }).then(function (res) {
        var report = JSON.parse(res.report);
        var outName = file.name.replace(/(\.[^.]+)?$/, function (ext) { return "-signed" + ext; });
        var blob = new Blob([res.bytes], { type: file.type || "application/octet-stream" });
        download(blob, outName);
        setStatus(signStatus, "Signed. Your download should have started.", "");
        renderSigned(res.bytes, blob, outName, report, opts);
      }).catch(function (err) {
        setStatus(signStatus, explain(err), "bad");
      }).finally(function () {
        clearTimeout(timer);
        busy(signGo, false);
      });
    }, 0);
  });

  function download(blob, name) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  // --- the Signed card -----------------------------------------------------
  function renderSigned(bytes, blob, name, report, opts) {
    signResult.textContent = "";
    var node = tpl.content.cloneNode(true);
    var q = function (sel) { return node.querySelector(sel); };
    var codes = {};
    (report.statuses || []).forEach(function (s) { codes[s.code] = s.severity; });
    // The library answers "is the file bound to this manifest" itself now, and
    // its answer covers every binding — box hashes and fragmented merkle trees
    // included, which the old status-code match here did not.
    var bound = codes["claimSignature.validated"] === "success" && report.binding === "verified";
    var trusted = codes["signingCredential.trusted"] === "success";

    q("[data-signed-sub]").textContent = name + " — " + (report.activeManifestLabel ? "manifest " + report.activeManifestLabel : "signed") +
      (report.verifiedSignedAt ? ", timestamped " + report.verifiedSignedAt : "") + ".";

    var trust = q("[data-trust]");
    var strong = document.createElement("strong");
    if (cred.kind === "test") {
      trust.className = "trust bad";
      strong.textContent = "Signed with a self-signed test identity. ";
      trust.appendChild(strong);
      trust.appendChild(document.createTextNode(
        "The signature and the content hash verify, so this proves the file has not changed since you signed it — " +
        "not who you are. This browser issued the certificate to itself, so every verifier, this page included, reports " +
        "signingCredential.untrusted. Import a certificate chain from a CA on the C2PA trust list for a trusted result."));
    } else if (trusted) {
      trust.className = "trust ok";
      strong.textContent = "Signed and trusted. ";
      trust.appendChild(strong);
      trust.appendChild(document.createTextNode("Your certificate chain reaches an anchor on the C2PA trust list, so this page verifies the file as " +
        (report.verifiedSigner || "your identity") + "."));
    } else {
      trust.className = "trust bad";
      strong.textContent = "Signed, but the signer is untrusted here. ";
      trust.appendChild(strong);
      trust.appendChild(document.createTextNode("The signature verifies; the certificate chain does not reach an anchor on the C2PA trust list this page ships, " +
        "so it reports signingCredential.untrusted. A verifier that trusts your issuer will disagree."));
    }

    var dl = q("[data-signed-claims]");
    addRow(dl, "signed by", report.signedBy);
    addRow(dl, "signature and hash", bound ? "verified — the file is bound to this manifest" : "NOT verified: " + (report.firstFailure || "see the inspection"));
    addRow(dl, "signer trusted", trusted ? "yes" : "no — " + (cred.kind === "test" ? "self-signed test identity" : "issuer not on the trust list"));
    // What the identity assertion says, in the verifier's own terms rather than
    // ours: it went in, and whether anyone believes it is their decision.
    if (opts.identityRoles && opts.identityRoles.length) {
      var wrote = (report.identities || []).length > 0;
      addRow(dl, "vouched as", opts.identityRoles.join(", ") +
        (wrote ? " — recorded; a verifier reports it unproven unless they trust your issuer" : " — NOT recorded, see the inspection"));
    }
    addRow(dl, "title", report.title);
    addRow(dl, "action", opts.action === "auto" ? (report.statuses && hasIngredient(report) ? "opened (chained to the existing credentials)" : "created") : opts.action);
    addRow(dl, "generator", report.claimGenerator);
    addRow(dl, "size", bytes.length.toLocaleString() + " bytes");

    q("[data-signed-download]").addEventListener("click", function () { download(blob, name); });
    q("[data-signed-inspect]").addEventListener("click", function () {
      if (typeof window.c2paInspectorInspect !== "function") return;
      window.c2paInspectorInspect(bytes, name, blob).then(function () {
        var results = $("results");
        if (results) results.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
    signResult.appendChild(node);
    signResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function hasIngredient(report) {
    return (report.statuses || []).some(function (s) { return /^ingredient\./.test(s.code) || /c2pa\.ingredient/.test(s.uri || ""); });
  }

  // --- errors --------------------------------------------------------------
  // The wasm rejects with an Error carrying .code; the message is already a
  // sentence for people. A few codes get an extra pointer to the fix.
  function explain(err) {
    var code = err && err.code;
    var msg = message(err);
    switch (code) {
      case "already-signed":
        signAction.value = "opened";
        return msg + " The action has been switched to \"opened\" for you — sign again.";
      case "expired":
        return msg;
      case "no-webcrypto":
        return msg + " Open this page over https (or from localhost when developing).";
      default:
        return msg;
    }
  }
  function message(err) {
    if (!err) return "unknown error";
    if (typeof err === "string") return err;
    return err.message || String(err);
  }

  function busy(btn, on) {
    btn.disabled = on || (btn === signGo && !(cred && chosen));
    btn.classList.toggle("busy", !!on);
  }
  function setStatus(el, text, cls) {
    el.className = "dz-status" + (cls ? " " + cls : "");
    el.textContent = text || "";
  }
})();
