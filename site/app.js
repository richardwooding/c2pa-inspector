/* c2pa-inspector — load the WASM validator and wire the drop zone.
   All inspection happens in-page; no bytes ever leave the browser. */
(function () {
  "use strict";

  var MAX_FILES = 10;
  var MAX_SHARE_BYTES = 6000; // keep the fragment inside every browser's URL ceiling

  var $ = function (id) { return document.getElementById(id); };
  var pick = $("pick"), sample = $("try-sample"), sampleVideo = $("try-sample-video");
  var samplePDF = $("try-sample-pdf");
  var fileInput = $("file"), dropzone = $("dropzone"), dzStatus = $("dz-status");
  var results = $("results"), list = $("results-list"), countEl = $("results-count");
  var shareBtn = $("share"), clearBtn = $("clear"), tpl = $("result-template");

  // Each entry is {name, res} — the rendered results, which is also what a
  // shareable link carries. The bytes are never retained.
  var rendered = [];

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
    pick.textContent = "Choose files";
    sample.disabled = false;
    sampleVideo.disabled = false;
    samplePDF.disabled = false;
    showEngineVersion();
    restoreFromHash();
  }).catch(function (err) {
    pick.textContent = "Validator failed to load";
    setStatus("Could not load the validator — " + String(err), "bad");
  });

  // The engine version comes from the wasm's own build info, so the footer
  // always names the c2pa release actually compiled into the page.
  function showEngineVersion() {
    var el = document.querySelector("[data-c2pa-version]");
    if (!el || typeof window.c2paLibVersion !== "function") return;
    var v = window.c2paLibVersion();
    if (!v) return;
    el.textContent = v;
    var wrap = el.closest("[hidden]");
    if (wrap) wrap.hidden = false;
  }

  // --- input plumbing ------------------------------------------------------
  pick.addEventListener("click", function () { fileInput.click(); });
  dropzone.addEventListener("click", function () { if (!pick.disabled) fileInput.click(); });
  dropzone.addEventListener("keydown", function (e) {
    if ((e.key === "Enter" || e.key === " ") && !pick.disabled) { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", function () {
    if (fileInput.files.length) inspectFiles(fileInput.files);
    fileInput.value = "";
  });

  ["dragover", "dragenter"].forEach(function (t) {
    dropzone.addEventListener(t, function (e) { e.preventDefault(); dropzone.classList.add("dragover"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    dropzone.addEventListener(t, function (e) { e.preventDefault(); dropzone.classList.remove("dragover"); });
  });
  dropzone.addEventListener("drop", function (e) {
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) inspectFiles(files);
  });

  clearBtn.addEventListener("click", function () {
    rendered = [];
    list.textContent = "";
    results.hidden = true;
    shareBtn.hidden = clearBtn.hidden = true;
    setStatus("", "");
    if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  });

  function wireSample(button, name, mime) {
    button.addEventListener("click", function () {
      button.classList.add("busy");
      setStatus("Checking " + name + "…", "working");
      fetch(name).then(function (r) { return r.arrayBuffer(); }).then(function (buf) {
        reset();
        inspectBytes(new Uint8Array(buf), name, new Blob([buf], { type: mime }));
        finish();
      }).finally(function () { button.classList.remove("busy"); });
    });
  }
  wireSample(sample, "sample.jpg", "image/jpeg");
  wireSample(sampleVideo, "sample.mp4", "video/mp4");
  wireSample(samplePDF, "sample.pdf", "application/pdf");

  function inspectFiles(fileList) {
    var files = Array.prototype.slice.call(fileList, 0, MAX_FILES);
    var skipped = fileList.length - files.length;
    boot.then(function () {
      reset();
      setStatus("Checking " + files.length + " file" + (files.length === 1 ? "" : "s") + "…", "working");
      return Promise.all(files.map(function (f) {
        return f.arrayBuffer().then(function (buf) { return { f: f, bytes: new Uint8Array(buf) }; });
      }));
    }).then(function (loaded) {
      loaded.forEach(function (it) { inspectBytes(it.bytes, it.f.name, it.f); });
      finish(skipped);
    });
  }

  function reset() {
    rendered = [];
    list.textContent = "";
  }

  function finish(skipped) {
    results.hidden = false;
    shareBtn.hidden = clearBtn.hidden = rendered.length === 0;
    var n = rendered.length;
    countEl.textContent = n + (n === 1 ? " file inspected" : " files inspected") +
      (skipped ? " · " + skipped + " skipped (10 at a time)" : "");
    $("results-h").textContent = n === 1 ? "Inspection result." : "Inspection results.";
    setStatus(summarise(), "");
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // --- inspection ----------------------------------------------------------
  function inspectBytes(bytes, name, blob) {
    var res;
    try {
      res = JSON.parse(window.c2paInspect(bytes));
    } catch (err) {
      res = { error: "validator crashed: " + String(err) };
    }
    var manifest = null;
    if (!res.error && res.present && typeof window.c2paManifest === "function") {
      try {
        manifest = JSON.parse(window.c2paManifest(bytes));
      } catch (err) {
        manifest = null;
      }
    }
    rendered.push({ name: name, res: res, manifest: manifest });
    list.appendChild(buildCard(name, res, manifest, blob));
  }

  // --- rendering -----------------------------------------------------------
  function buildCard(name, res, manifest, blob) {
    var node = tpl.content.cloneNode(true);
    var q = function (sel) { return node.querySelector(sel); };

    var verdict = q("[data-verdict]"), mark = verdict.querySelector(".mark");
    var title = q("[data-verdict-title]"), sub = q("[data-verdict-sub]");
    verdict.classList.remove("ok", "bad", "none");
    if (res.error) {
      verdict.classList.add("bad"); mark.textContent = "✗";
      title.textContent = "Could not inspect " + name;
      sub.textContent = res.error;
    } else if (!res.present) {
      verdict.classList.add("none"); mark.textContent = "·";
      title.textContent = "No Content Credentials";
      sub.textContent = name + " (" + res.container + ") carries no C2PA manifest. Most files don't — absence proves nothing either way.";
    } else if (res.valid) {
      verdict.classList.add("ok"); mark.textContent = "✓";
      title.textContent = "Verified";
      sub.textContent = name + " — signature, trust chain, and hash bindings all check out" +
        (res.verifiedSigner ? "; verifiably signed by " + res.verifiedSigner : "") +
        (res.verifiedSignedAt ? " at " + res.verifiedSignedAt : "") + ".";
    } else {
      verdict.classList.add("bad"); mark.textContent = "✗";
      title.textContent = "Not verified";
      sub.textContent = name + " has Content Credentials, but validation failed: " + (res.firstFailure || "see the log") + ".";
    }

    // The AI question is what most visitors came for, so it gets its own banner
    // rather than a row in a definition list.
    if (res.present && res.aiGenerated) {
      var flag = q("[data-ai-flag]");
      flag.hidden = false;
      var strong = document.createElement("strong");
      strong.textContent = "Declared AI-generated.";
      flag.appendChild(strong);
      var txt = " This file's manifest carries a trainedAlgorithmicMedia source type" +
        (res.softwareAgent ? ", naming " + res.softwareAgent + " as the tool" : "") + ".";
      flag.appendChild(document.createTextNode(txt));
    }

    attachPreview(q("[data-preview]"), q("[data-preview-video]"), name, blob, res);

    var claims = q("[data-claims]");
    if (res.present) {
      addClaim(claims, "generator", res.claimGenerator);
      addClaim(claims, "software agent", res.softwareAgent);
      addClaim(claims, "title", res.title);
      addClaim(claims, "format", res.format);
      addClaim(claims, "container", res.container);
      addClaim(claims, "ai-generated", res.aiGenerated ? "yes — declared AI-generated" : "no");
      if (res.attribution === "embedded") {
        addClaim(claims, "attribution", "embedded resource — this manifest records the provenance of something the file carries (an image or font inside a PDF), not of the file itself, so the signer below is not the document's");
      } else if (res.attribution === "unknown") {
        addClaim(claims, "attribution", "unknown — the manifest is not associated with this file, so it may describe something the file carries");
      }
      addClaim(claims, "signed by (claimed)", res.signedBy);
      addClaim(claims, "signed by (verified)", res.verifiedSigner);
      addClaim(claims, "claimed time", res.claimedSignedAt);
      addClaim(claims, "verified time", res.verifiedSignedAt || "— (no trusted timestamp)");
      addClaim(claims, "manifest", res.activeManifestLabel);
    } else {
      addClaim(claims, "container", res.container);
      addClaim(claims, "manifest", "none found");
    }

    var chain = q("[data-chain]");
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
      var none = document.createElement("li");
      none.textContent = "No signer chain parsed.";
      chain.appendChild(none);
    }

    renderTerm(q("[data-statuses]"), termLines(name, res));

    if (manifest && manifest.boxes && manifest.boxes.length) {
      buildManifest(q("[data-manifest-card]"), q("[data-boxes]"), q("[data-manifest-size]"),
        q("[data-download-manifest]"), name, manifest);
    }
    return node;
  }

  // buildManifest renders the JUMBF box tree — the byte-level view of what is
  // actually embedded, including assertions the summary above doesn't model.
  function buildManifest(card, host, sizeEl, dl, name, manifest) {
    card.hidden = false;
    sizeEl.textContent = "(" + manifest.boxes.length + " boxes · " + manifest.storeSize.toLocaleString() + " bytes)";

    manifest.boxes.forEach(function (b) {
      var d = document.createElement("details");
      var s = document.createElement("summary");
      var t = document.createElement("span"); t.className = "tbox"; t.textContent = b.type;
      var l = document.createElement("span"); l.className = "blabel"; l.textContent = b.label || "—";
      var z = document.createElement("span"); z.className = "bsize"; z.textContent = b.size.toLocaleString() + " B";
      s.appendChild(t); s.appendChild(l); s.appendChild(z);
      d.appendChild(s);

      var pre = document.createElement("pre");
      if (b.payload !== undefined) {
        pre.textContent = JSON.stringify(b.payload, null, 2);
      } else if (b.preview) {
        pre.textContent = b.preview + (b.size > b.preview.length / 2 ? " …" : "");
      } else {
        pre.textContent = "(empty)";
      }
      d.appendChild(pre);
      host.appendChild(d);
    });

    dl.addEventListener("click", function () {
      var blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = name.replace(/\.[^.]+$/, "") + ".manifest.json";
      a.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });
  }

  function attachPreview(img, vid, name, blob, res) {
    if (!blob || res.error) return;
    var url = URL.createObjectURL(blob);
    var isVideo = /^video\//.test(blob.type) || /\.(mp4|mov|m4v)$/i.test(name);
    if (isVideo) {
      vid.src = url;
      vid.hidden = false;
    } else if (!/^audio\//.test(blob.type) && !/\.(mp3|wav|m4a|pdf)$/i.test(name)) {
      img.onerror = function () { img.hidden = true; URL.revokeObjectURL(url); };
      img.src = url;
      img.alt = "Preview of " + name;
      img.hidden = false;
    }
  }

  function termLines(name, res) {
    var lines = (res.statuses || []).map(function (s) {
      var cls = s.severity === "success" ? "ok" : s.severity === "failure" ? "fail" : "info";
      var glyph = s.severity === "success" ? "✓" : s.severity === "failure" ? "✗" : "·";
      return [cls, glyph + " " + s.code + (s.explanation ? "  — " + s.explanation : "")];
    });
    if (res.error) lines = [["fail", "✗ " + res.error]];
    if (!lines.length) lines = [["info", "· no validation statuses recorded"]];
    return [["pr-line", "c2pa validate " + name]].concat(lines);
  }

  function addClaim(dl, key, val) {
    if (!val) return;
    var dt = document.createElement("dt");
    dt.textContent = key;
    var dd = document.createElement("dd");
    dd.textContent = val;
    dl.appendChild(dt); dl.appendChild(dd);
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

  // --- shareable links -----------------------------------------------------
  // The RESULT travels in the fragment, never the file — a fragment is not sent
  // to any server, so sharing a report cannot leak the bytes it came from.
  shareBtn.addEventListener("click", function () {
    var payload = rendered.map(function (r) { return { name: r.name, res: r.res }; });
    var encoded;
    try {
      encoded = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
    } catch (err) {
      return flash(shareBtn, "Could not encode");
    }
    if (encoded.length > MAX_SHARE_BYTES) return flash(shareBtn, "Too large to link");
    var url = location.origin + location.pathname + "#r=" + encoded;
    history.replaceState(null, "", "#r=" + encoded);
    if (navigator.clipboard) {
      navigator.clipboard.writeText(url).then(function () { flash(shareBtn, "Link copied"); },
        function () { flash(shareBtn, "Copy failed"); });
    } else {
      flash(shareBtn, "Link in address bar");
    }
  });

// The dropzone doubles as the page's status line: what it is doing now, or
  // what it found. Previously this was a terminal transcript.
  function setStatus(text, cls) {
    dzStatus.className = "dz-status" + (cls ? " " + cls : "");
    dzStatus.textContent = text || "";
  }

  // summarise says what happened in words a non-developer can act on, rather
  // than restating the C2PA status codes the result cards already list.
  function summarise() {
    var verified = 0, failed = 0, none = 0, ai = 0;
    rendered.forEach(function (r) {
      if (r.res.error || (r.res.present && !r.res.valid)) failed++;
      else if (r.res.present) verified++;
      else none++;
      if (r.res.present && r.res.aiGenerated) ai++;
    });
    var parts = [];
    if (verified) parts.push(verified + " verified");
    if (failed) parts.push(failed + " not verified");
    if (none) parts.push(none + " with no credentials");
    if (ai) parts.push(ai + " declared AI-generated");
    return parts.join(" · ");
  }

  function flash(btn, text) {
    var was = btn.textContent;
    btn.textContent = text;
    setTimeout(function () { btn.textContent = was; }, 1800);
  }

  function restoreFromHash() {
    var m = /^#r=(.+)$/.exec(location.hash);
    if (!m) return;
    var payload;
    try {
      payload = JSON.parse(decodeURIComponent(escape(atob(m[1]))));
    } catch (err) {
      return;
    }
    if (!Array.isArray(payload)) return;
    reset();
    payload.forEach(function (item) {
      if (!item || typeof item.name !== "string" || !item.res) return;
      rendered.push({ name: item.name, res: item.res, manifest: null });
      list.appendChild(buildCard(item.name, item.res, null, null));
    });
    if (rendered.length) finish();
  }
})();
