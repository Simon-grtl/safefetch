// SafeFetch UI. All untrusted strings (file names, URLs, threat names) are
// inserted with textContent — never innerHTML — so a hostile file name cannot
// inject markup or script into this window.
"use strict";

(() => {
  const tauri = window.__TAURI__;
  const invoke = tauri.core.invoke;
  const $ = (id) => document.getElementById(id);
  const jobs = new Map();
  let env = null;

  // ---------- helpers ----------
  function el(tag, opts = {}, ...children) {
    const e = document.createElement(tag);
    if (opts.cls) e.className = opts.cls;
    if (opts.text !== undefined) e.textContent = String(opts.text);
    if (opts.title) e.title = String(opts.title);
    if (opts.onclick) e.addEventListener("click", opts.onclick);
    if (opts.type) e.type = opts.type;
    for (const c of children) if (c) e.append(c);
    return e;
  }
  function fmtBytes(n) {
    if (n === null || n === undefined) return "?";
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  }
  let toastTimer;
  function toast(msg) {
    const t = $("toast");
    t.textContent = String(msg);
    t.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add("hidden"), 5000);
  }
  async function call(cmd, args) {
    try { return await invoke(cmd, args); }
    catch (e) { toast(typeof e === "string" ? e : (e && e.message) || "Error"); throw e; }
  }

  // ---------- status mapping ----------
  const VERDICT = {
    clean: { icon: "✅", label: "Clean", cls: "ok" },
    suspect: { icon: "⚠️", label: "Suspect", cls: "warn" },
    not_analyzed: { icon: "⚠️", label: "Not analyzed", cls: "warn" },
    dangerous: { icon: "❌", label: "Dangerous", cls: "bad" },
  };
  function status(j) {
    if (!j.outcome) {
      return {
        queued: { icon: "⏳", label: "Queued", cls: "muted" },
        checking_link: { icon: "🔎", label: "Checking link", cls: "info" },
        downloading: { icon: "⬇️", label: "Downloading", cls: "info" },
        scanning: { icon: "🛡️", label: "Analyzing", cls: "info" },
        finished: { icon: "⏳", label: "Finishing", cls: "muted" },
      }[j.stage];
    }
    const o = j.outcome;
    const v = j.verdict ? VERDICT[j.verdict.level] : null;
    switch (o.kind) {
      case "delivered": return { icon: v && j.verdict.level === "clean" ? "✅" : "📥", label: v && j.verdict.level === "clean" ? "Clean — delivered" : "Released by you", cls: v && j.verdict.level === "clean" ? "ok" : "warn" };
      case "deleted": return { icon: "❌", label: "Dangerous — deleted", cls: "bad" };
      case "quarantined": return v ? { icon: v.icon, label: `${v.label} — in quarantine`, cls: v.cls } : { icon: "⚠️", label: "In quarantine", cls: "warn" };
      case "blocked": return { icon: "⛔", label: "Link blocked", cls: "bad" };
      case "already_downloaded": return { icon: "♻️", label: "Already downloaded", cls: "muted" };
      case "failed": return { icon: "⚠️", label: "Failed", cls: "warn" };
      case "cancelled": return { icon: "⏸️", label: "Cancelled", cls: "muted" };
      case "discarded": return { icon: "🗑️", label: "Deleted by you", cls: "muted" };
      default: return { icon: "•", label: o.kind, cls: "muted" };
    }
  }

  // ---------- job list ----------
  function actionsFor(j) {
    const box = el("div", { cls: "actions" });
    const add = (label, fn, cls = "ghost small") => box.append(el("button", { cls, text: label, type: "button", onclick: fn }));
    const o = j.outcome;
    if (!o) add("Cancel", () => call("cancel_job", { id: j.id }));
    if (o && (o.kind === "failed" && o.resumable)) add("Resume", () => call("retry_job", { id: j.id }));
    if (o && o.kind === "failed" && !o.resumable) add("Retry", () => call("retry_job", { id: j.id }));
    if (o && o.kind === "cancelled") add(o.resumable ? "Resume" : "Retry", () => call("retry_job", { id: j.id }));
    if (o && o.kind === "blocked") add("Download anyway…", () => {
      if (confirm("VirusTotal flagged this link. Download it into quarantine anyway? It will still be scanned before anything is delivered.")) call("force_download", { id: j.id });
    }, "ghost small danger");
    if (o && (o.kind === "delivered" || o.kind === "already_downloaded")) add("Show in folder", () => call("reveal_delivered", { id: j.id }));
    add("Details", () => openDetails(j.id), "small");
    return box;
  }

  function renderJob(j) {
    const s = status(j);
    const li = el("li", { cls: "job" });
    li.dataset.id = j.id;
    li.append(el("div", { cls: "icon", text: s.icon }));
    const head = el("div", {}, el("div", { cls: "name", text: j.file_name, title: j.file_name }), el("div", { cls: "sub", text: j.display_url, title: j.display_url }));
    li.append(head, actionsFor(j));
    const meta = el("div", { cls: "meta" });
    meta.append(el("span", { cls: `badge ${s.cls}`, text: s.label }));
    if (j.stage === "downloading" && !j.outcome) {
      const p = el("progress");
      p.max = j.size || 1;
      if (j.size) p.value = j.downloaded; else p.removeAttribute("value");
      meta.append(p, el("span", { text: `${fmtBytes(j.downloaded)} / ${j.size ? fmtBytes(j.size) : "?"}` }), el("span", { text: `${fmtBytes(j.speed_bps)}/s` }));
    } else if (j.size || j.downloaded) {
      meta.append(el("span", { text: fmtBytes(j.size || j.downloaded) }));
    }
    if (j.outcome && j.outcome.kind === "failed") meta.append(el("span", { cls: "errors", text: j.outcome.error }));
    if (j.outcome && j.outcome.kind === "blocked") meta.append(el("span", { text: j.outcome.reason }));
    if ((j.name_warnings || []).length) meta.append(el("span", { cls: "badge warn", text: "Suspicious file name", title: j.name_warnings.join(", ") }));
    li.append(meta);
    return li;
  }

  function renderAll() {
    const list = $("job-list");
    const sorted = [...jobs.values()].sort((a, b) => b.id - a.id);
    list.replaceChildren(...sorted.map(renderJob));
    $("empty").classList.toggle("hidden", sorted.length > 0);
  }
  let rafPending = false;
  function scheduleRender() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => { rafPending = false; renderAll(); refreshOpenDetails(); });
  }

  // ---------- details dialog ----------
  let detailsId = null;
  function openDetails(id) { detailsId = id; fillDetails(); $("details").showModal(); }
  function refreshOpenDetails() { if (detailsId !== null && $("details").open) fillDetails(); }
  $("details").addEventListener("close", () => { detailsId = null; });

  function kv(pairs) {
    const dl = el("dl", { cls: "kv" });
    for (const [k, v] of pairs) if (v !== null && v !== undefined && v !== "") dl.append(el("dt", { text: k }), el("dd", { cls: k === "SHA-256" || k === "Expected SHA-256" ? "mono" : "", text: v }));
    return dl;
  }

  function fillDetails() {
    const j = jobs.get(detailsId);
    if (!j) return;
    const body = $("d-body");
    const actions = $("d-actions");
    $("d-title").textContent = j.file_name;
    const parts = [];
    const s = status(j);
    parts.push(el("div", { cls: `verdict-banner ${s.cls}`, text: `${s.icon} ${s.label}` }));
    const v = j.verdict;
    parts.push(kv([
      ["Link", j.display_url],
      ["Final host", j.final_host],
      ["Size", j.size ? fmtBytes(j.size) : null],
      ["SHA-256", v ? v.report.sha256 : null],
      ["Expected SHA-256", j.expected_sha256],
      ["Result", j.outcome && j.outcome.path ? j.outcome.path : null],
    ]));
    if (v) {
      parts.push(el("h3", { text: "Why" }));
      parts.push(el("ul", { cls: "reasons" }, ...v.reasons.map((r) => el("li", { text: r }))));
      if (v.detections.length) {
        const t = el("table");
        t.append(el("tr", {}, el("th", { text: "Engine" }), el("th", { text: "Threat" })));
        for (const d of v.detections) t.append(el("tr", {}, el("td", { text: d.source }), el("td", { text: d.name })));
        parts.push(el("h3", { text: "Detections" }), t);
      }
    }
    if (j.link_check) {
      parts.push(el("h3", { text: `Link reputation: ${j.link_check.status}` }));
      parts.push(el("ul", { cls: "reasons" }, ...j.link_check.details.map((r) => el("li", { text: r }))));
      if (j.link_check.detections.length) {
        const t = el("table");
        t.append(el("tr", {}, el("th", { text: "Source" }), el("th", { text: "Result" })));
        for (const d of j.link_check.detections) t.append(el("tr", {}, el("td", { text: d.source }), el("td", { text: d.name })));
        parts.push(t);
      }
    }
    if ((j.name_warnings || []).length) {
      parts.push(el("h3", { text: "File name" }));
      const explain = {
        path_components_removed: "Folder components (../ or absolute paths) were removed.",
        control_chars_removed: "Invisible control characters were removed.",
        bidi_or_invisible_chars_removed: "Right-to-left override or invisible characters were removed (often used to disguise extensions).",
        reserved_name: "The name was a reserved Windows device name and was prefixed with _.",
        deceptive_double_extension: "A fake extension hid the real one (e.g. invoice.pdf.exe); it was made visible.",
        executable_extension: "This file type can run code when opened.",
        truncated: "The name was too long and was shortened.",
        empty: "No usable name was provided; a generic name was used.",
      };
      parts.push(el("ul", { cls: "reasons" }, ...j.name_warnings.map((w) => el("li", { text: explain[w] || w }))));
    }
    if ((j.warnings || []).length) {
      parts.push(el("h3", { text: "Warnings" }));
      parts.push(el("ul", { cls: "reasons" }, ...j.warnings.map((w) => el("li", { text: w }))));
    }
    body.replaceChildren(...parts);

    const btns = [];
    const b = (label, fn, cls = "") => btns.push(el("button", { cls, text: label, type: "button", onclick: fn }));
    if ((v && v.virustotal_link) || (j.link_check && j.link_check.permalink)) b("Open VirusTotal report", () => call("open_virustotal_report", { id: j.id }), "ghost");
    if (j.outcome && j.outcome.kind === "quarantined") {
      b("Re-scan", () => call("rescan_job", { id: j.id }), "ghost");
      b("Upload to VirusTotal…", async () => {
        if (!confirm("Uploading sends the FILE itself to VirusTotal. Uploaded files can be downloaded by VirusTotal's partners and security researchers. Never upload private or confidential files.\n\nContinue?")) return;
        if (!confirm("Last confirmation: upload this file to VirusTotal now? (free API: max 32 MiB)")) return;
        const link = await call("upload_to_virustotal", { id: j.id, confirmed: true });
        toast(`Uploaded. Report will appear at: ${link}`);
      }, "ghost");
      b("Delete file", async () => { if (confirm("Delete this file from quarantine?")) { await call("discard_job", { id: j.id }); } }, "danger");
      if (!v || v.level !== "dangerous") b("Release to destination…", async () => {
        const what = v ? VERDICT[v.level].label.toLowerCase() : "not verified";
        if (!confirm(`This file is ${what}. Move it to your destination folder anyway? SafeFetch will not open it.`)) return;
        const p = await call("release_job", { id: j.id });
        toast(`Delivered to ${p}`);
      }, "primary");
    }
    actions.replaceChildren(...btns);
  }

  // ---------- environment / first run ----------
  async function loadEnv() {
    env = await call("environment");
    const st = $("env-status");
    const pills = [];
    const pill = (text, cls) => pills.push(el("span", { cls: `pill ${cls}`, text }));
    if (env.clamscan || env.clamd) {
      const age = env.signatures_age_days;
      if (age === null || age === undefined) pill("ClamAV: no signatures?", "warn");
      else pill(`ClamAV signatures: ${age} day(s) old`, age > 3 ? "warn" : "ok");
    } else pill("ClamAV missing", "bad");
    if (env.os === "windows") pill(env.defender ? "Defender available" : "Defender not found", env.defender ? "ok" : "warn");
    pill(env.has_api_key ? "VirusTotal key set" : "No VirusTotal key", env.has_api_key ? "ok" : "warn");
    st.replaceChildren(...pills);

    const issues = [];
    if (!env.destination) issues.push("Choose a destination folder: clean files are delivered there, everything else stays in quarantine.");
    if (!env.clamscan && !env.clamd) issues.push("ClamAV is not installed. Without it, files can never be judged Clean — they will stay in quarantine as “Not analyzed”.");
    else if (env.signatures_age_days === null || env.signatures_age_days === undefined) issues.push("ClamAV has no virus signatures yet: update them.");
    else if (env.signatures_age_days > 3) issues.push(`ClamAV signatures are ${env.signatures_age_days} days old: update them.`);
    const blocking = issues.length;
    if (!env.has_api_key) issues.push("Optional: add a free VirusTotal API key in Settings to check links and file hashes.");
    $("setup-list").replaceChildren(...issues.map((t) => el("li", { text: t })));
    $("install-steps").replaceChildren(...env.install_help.map((t) => el("li", { cls: "mono", text: t })));
    $("install-help").classList.toggle("hidden", !!(env.clamscan || env.clamd));
    $("setup").classList.toggle("hidden", blocking === 0);
    $("setup-dest").classList.toggle("hidden", !!env.destination);
  }

  async function chooseDestination() {
    const s = await call("choose_destination");
    if (s) { toast(`Destination: ${s.destination_dir}`); await loadEnv(); await loadSettings(); }
  }
  async function updateSignatures(btn) {
    btn.disabled = true;
    toast("Updating ClamAV signatures… this can take a few minutes.");
    try { await invoke("update_signatures"); toast("Signatures updated."); }
    catch (e) { toast(`Signature update failed: ${e}`); }
    finally { btn.disabled = false; loadEnv(); }
  }

  // ---------- settings ----------
  let current = null;
  async function loadSettings() {
    current = await call("get_settings");
    $("s-dest").textContent = current.destination_dir || "Not set";
    $("s-vt-danger").value = current.vt_dangerous_threshold;
    $("s-vt-susp").value = current.vt_suspicious_threshold;
    $("s-url").value = current.url_block_threshold;
    $("s-domain").value = current.domain_block_threshold;
    $("s-require-vt").checked = current.require_virustotal;
    $("s-conc").value = current.max_concurrent_downloads;
    $("s-max").value = current.max_file_size_mib;
    $("s-http").checked = current.allow_http;
    $("s-defender").checked = current.use_defender;
    $("s-fresh").checked = current.auto_update_signatures;
    $("s-upd").checked = current.check_app_updates;
    const has = await call("has_api_key");
    $("s-key-state").textContent = has ? "A key is stored in the system keychain." : "No key stored.";
  }
  const num = (id) => Math.max(0, parseInt($(id).value, 10) || 0);
  $("s-save").addEventListener("click", async () => {
    $("s-error").textContent = "";
    const next = {
      ...current,
      vt_dangerous_threshold: num("s-vt-danger"),
      vt_suspicious_threshold: num("s-vt-susp"),
      url_block_threshold: num("s-url"),
      domain_block_threshold: num("s-domain"),
      require_virustotal: $("s-require-vt").checked,
      max_concurrent_downloads: num("s-conc"),
      max_file_size_mib: num("s-max"),
      allow_http: $("s-http").checked,
      use_defender: $("s-defender").checked,
      auto_update_signatures: $("s-fresh").checked,
      check_app_updates: $("s-upd").checked,
    };
    try { current = await invoke("save_settings", { settings: next }); toast("Settings saved."); $("settings").close(); }
    catch (e) { $("s-error").textContent = String(e); }
  });
  $("s-choose").addEventListener("click", chooseDestination);
  $("s-key-save").addEventListener("click", async () => {
    const k = $("s-key").value.trim();
    $("s-key").value = "";
    try { await invoke("set_api_key", { key: k }); toast("API key saved in the system keychain."); }
    catch (e) { $("s-error").textContent = String(e); }
    loadSettings(); loadEnv();
  });
  $("s-key-del").addEventListener("click", async () => { await call("delete_api_key"); toast("API key removed."); loadSettings(); loadEnv(); });
  $("s-check-update").addEventListener("click", async () => {
    try {
      const u = await invoke("check_app_update");
      if (!u) return toast("SafeFetch is up to date.");
      if (confirm(`SafeFetch ${u.version} is available.\n\n${u.notes || ""}\n\nInstall now? (the update's signature is verified before installing)`)) await call("install_app_update");
    } catch (e) { toast(`Update check failed: ${e}`); }
  });
  $("open-settings").addEventListener("click", async () => { await loadSettings(); $("settings").showModal(); });

  // ---------- input ----------
  $("submit").addEventListener("click", async () => {
    const text = $("links").value;
    if (!text.trim()) return;
    const r = await call("submit_links", { text });
    $("input-errors").textContent = r.errors.map((e) => `Line ${e.line}: ${e.message}`).join("\n");
    // Keep only the lines that could not be used, so nothing is submitted twice.
    const lines = text.split(/\r?\n/);
    $("links").value = r.errors.map((e) => lines[e.line - 1]).join("\n");
    if (r.added.length === 0 && r.errors.length === 0) toast("These links are already in the list.");
  });
  $("links").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) $("submit").click(); });
  $("clear").addEventListener("click", async () => {
    await call("clear_finished");
    jobs.clear();
    for (const j of await call("list_jobs")) jobs.set(j.id, j);
    renderAll();
  });
  $("setup-dest").addEventListener("click", chooseDestination);
  $("setup-sigs").addEventListener("click", (e) => updateSignatures(e.currentTarget));
  $("setup-recheck").addEventListener("click", loadEnv);

  // ---------- boot ----------
  (async () => {
    await tauri.event.listen("job-updated", (ev) => { jobs.set(ev.payload.id, ev.payload); scheduleRender(); });
    for (const j of await call("list_jobs")) jobs.set(j.id, j);
    renderAll();
    await loadEnv();
    try {
      const s = await invoke("get_settings");
      if (s.check_app_updates) {
        const u = await invoke("check_app_update").catch(() => null);
        if (u) toast(`SafeFetch ${u.version} is available — see Settings.`);
      }
    } catch (_) { /* ignore */ }
  })();
})();
