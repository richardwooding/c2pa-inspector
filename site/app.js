/* c2pa-inspector — load the WASM validator and wire the drop zone.
   All inspection happens in-page; no bytes ever leave the browser. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var pick = $("pick"), sample = $("try-sample"), sampleVideo = $("try-sample-video");
  var fileInput = $("file"), dropzone = $("dropzone"), term = $("term");

  // --- boot the Go runtime -------------------------------------------------
  var go = new Go();
  var boot = (WebAssembly.instantiateStreaming
    ? WebAssembly.instantiateStreaming(fetch("c2pa.wasm"), go.importObject)
    : fetch("c2pa.wasm").then(function (r) { return r.arrayBuffer(); })
        .then(function (b) { return WebAssembly.instantiate(b, go.importObject); }))
    .then(function (result) {
      go.run(result.instance); // resolves only on exit; main() parks forever
      return new Promise(function (resolve) {
        (function wait() {
          if (typeof window.c2paInspect === "function") return resolve();
          setTimeout(wait, 10);
        })();
      });
    });

  boot.then(function () {
    pick.disabled = false;
    pick.textContent = "Choose a file";
    sample.disabled = false;
    sampleVideo.disabled = false;
  }).catch(function (err) {
    pick.textContent = "Validator failed to load";
    setTerm([
      ["fail", "✗ could not load c2pa.wasm — " + String(err)]
    ]);
  });

  // --- input plumbing ------------------------------------------------------
  pick.addEventListener("click", function () { fileInput.click(); });
  dropzone.addEventListener("click", function () { if (!pick.disabled) fileInput.click(); });
  dropzone.addEventListener("keydown", function (e) {
    if ((e.key === "Enter" || e.key === " ") && !pick.disabled) { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", function () {
    if (fileInput.files.length) inspectFile(fileInput.files[0]);
    fileInput.value = "";
  });

  ["dragover", "dragenter"].forEach(function (t) {
    dropzone.addEventListener(t, function (e) { e.preventDefault(); dropzone.classList.add("dragover"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    dropzone.addEventListener(t, function (e) { e.preventDefault(); dropzone.classList.remove("dragover"); });
  });
  dropzone.addEventListener("drop", function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) inspectFile(f);
  });

  function wireSample(button, name, mime) {
    button.addEventListener("click", function () {
      button.classList.add("busy");
      fetch(name).then(function (r) { return r.arrayBuffer(); }).then(function (buf) {
        inspectBytes(new Uint8Array(buf), name, new Blob([buf], { type: mime }));
      }).finally(function () { button.classList.remove("busy"); });
    });
  }
  wireSample(sample, "sample.jpg", "image/jpeg");
  wireSample(sampleVideo, "sample.mp4", "video/mp4");

  function inspectFile(f) {
    f.arrayBuffer().then(function (buf) {
      inspectBytes(new Uint8Array(buf), f.name, f);
    });
  }

  // --- inspection + rendering ----------------------------------------------
  var previewURL = null;

  function inspectBytes(bytes, name, blob) {
    boot.then(function () {
      setTerm([["pr-line", "c2pa validate " + name]], true);
      var res;
      try {
        res = JSON.parse(window.c2paInspect(bytes));
      } catch (err) {
        res = { error: "validator crashed: " + String(err) };
      }
      render(res, name, blob);
    });
  }

  function render(res, name, blob) {
    var results = $("results");
    results.hidden = false;

    // verdict banner
    var verdict = $("verdict"), title = $("verdict-title"), sub = $("verdict-sub");
    verdict.classList.remove("ok", "bad", "none");
    var mark = verdict.querySelector(".mark");
    if (res.error) {
      verdict.classList.add("bad"); mark.textContent = "✗";
      title.textContent = "Could not inspect " + name;
      sub.textContent = res.error;
    } else if (!res.present) {
      verdict.classList.add("none"); mark.textContent = "·";
      title.textContent = "No Content Credentials";
      sub.textContent = name + " (" + res.container + ") carries no C2PA manifest. Most images don't — absence proves nothing either way.";
    } else if (res.valid) {
      verdict.classList.add("ok"); mark.textContent = "✓";
      title.textContent = "Verified";
      sub.textContent = name + " — signature, trust chain, and hash bindings all check out" +
        (res.verifiedSignedAt ? "; signed at " + res.verifiedSignedAt : "") + ".";
    } else {
      verdict.classList.add("bad"); mark.textContent = "✗";
      title.textContent = "Not verified";
      sub.textContent = name + " has Content Credentials, but validation failed: " + (res.firstFailure || "see the log") + ".";
    }

    // preview thumbnail: <video> for video types; <img> otherwise, hidden on
    // decode failure (Chrome cannot render HEIC/AVIF-HEVC in <img>).
    var img = $("preview"), vid = $("preview-video");
    if (previewURL) { URL.revokeObjectURL(previewURL); previewURL = null; }
    img.hidden = true;
    vid.hidden = true;
    vid.removeAttribute("src");
    if (blob && !res.error) {
      previewURL = URL.createObjectURL(blob);
      var isVideo = /^video\//.test(blob.type) || /\.(mp4|mov|m4v)$/i.test(name);
      if (isVideo) {
        vid.src = previewURL;
        vid.hidden = false;
      } else {
        img.onerror = function () { img.hidden = true; };
        img.src = previewURL;
        img.alt = "Preview of " + name;
        img.hidden = false;
      }
    }

    // claims
    var claims = $("claims");
    claims.textContent = "";
    if (res.present) {
      addClaim(claims, "generator", res.claimGenerator);
      addClaim(claims, "title", res.title);
      addClaim(claims, "format", res.format);
      addClaimNode(claims, "ai-generated", badgeText(res.aiGenerated ? "yes — declared AI-generated" : "no"));
      addClaim(claims, "signed by", res.signedBy);
      addClaim(claims, "claimed time", res.claimedSignedAt);
      addClaim(claims, "verified time", res.verifiedSignedAt || "— (no trusted timestamp)");
      addClaim(claims, "manifest", res.activeManifestLabel);
    } else {
      addClaim(claims, "manifest", "none found");
    }

    // signer chain
    var chain = $("chain");
    chain.textContent = "";
    (res.signerChain || []).forEach(function (c) {
      var li = document.createElement("li");
      var cn = document.createElement("div"); cn.className = "cn"; cn.textContent = c.subject;
      var meta = document.createElement("div"); meta.className = "meta";
      meta.textContent = "issued by " + c.issuer + " · " + c.algorithm + " · valid " +
        c.notBefore.slice(0, 10) + " → " + c.notAfter.slice(0, 10);
      li.appendChild(cn); li.appendChild(meta);
      chain.appendChild(li);
    });
    if (!res.signerChain || !res.signerChain.length) {
      var li = document.createElement("li");
      li.textContent = "No signer chain parsed.";
      chain.appendChild(li);
    }

    // status log (both the hero terminal and the results terminal)
    var lines = (res.statuses || []).map(function (s) {
      var cls = s.severity === "success" ? "ok" : s.severity === "failure" ? "fail" : "info";
      var glyph = s.severity === "success" ? "✓" : s.severity === "failure" ? "✗" : "·";
      return [cls, glyph + " " + s.code + (s.explanation ? "  — " + s.explanation : "")];
    });
    if (!lines.length) lines = [["info", "· no validation statuses recorded"]];
    renderTerm($("statuses"), [["pr-line", "c2pa validate " + name]].concat(lines));
    renderTerm(term, [["pr-line", "c2pa validate " + name]].concat(lines.slice(0, 8),
      lines.length > 8 ? [["info", "… " + (lines.length - 8) + " more below"]] : []));

    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function addClaim(dl, key, val) {
    if (!val) return;
    var dd = document.createElement("dd");
    dd.textContent = val;
    appendClaimRow(dl, key, dd);
  }

  function addClaimNode(dl, key, node) {
    var dd = document.createElement("dd");
    dd.appendChild(node);
    appendClaimRow(dl, key, dd);
  }

  function appendClaimRow(dl, key, dd) {
    var dt = document.createElement("dt");
    dt.textContent = key;
    dl.appendChild(dt); dl.appendChild(dd);
  }

  function badgeText(text) {
    var span = document.createElement("span");
    span.textContent = text;
    return span;
  }

  function renderTerm(pre, lines) {
    pre.textContent = "";
    lines.forEach(function (l, i) {
      if (i) pre.appendChild(document.createTextNode("\n"));
      if (l[0] === "pr-line") {
        var pr = document.createElement("span"); pr.className = "pr"; pr.textContent = "$";
        pre.appendChild(pr);
        pre.appendChild(document.createTextNode(" " + l[1]));
      } else {
        var span = document.createElement("span");
        span.className = l[0];
        span.textContent = l[1];
        pre.appendChild(span);
      }
    });
  }

  function setTerm(lines, keepPrompt) {
    renderTerm(term, lines);
  }
})();
