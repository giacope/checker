// Compliance chat: conversations about a codebase, a building or a document set and the regulations read with it.
// Answers cite what they rest on; a citation, or a check's locator, opens a preview of the code, the PDF page, the
// drawing sheet, the 3D model element or the regulation clause.

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const B = JSON.parse($("#boot").textContent);
const S = {chat: B.chat, chats: B.chats, ctx: B.contexts, mode: "quick", artifact: B.artifact || "", regs: new Set(B.regulations || []),
           checks: null, cfilter: "attention", stack: [], dispose: null, mesh: {}, timer: null};
const VERDICT = {fail: ["Fails", "fail"], uncertain: ["Uncertain", "unc"], unknown: ["Open", "unc"], pass: ["Passes", "pass"], not_applicable: ["Does not apply", "na"]};
const STATUS = {answered: ["Answered", "pass"], partial: ["Partly answered", "unc"], not_found: ["Not found in the material", "na"], unsupported: ["No answer held up", "fail"]};
const KIND = {scan: ["Code", "</>"], documents: ["Documents", "¶"], project: ["Building", "⌂"], regulation: ["Regulation", "§"]};
const DOMAIN = {scan: "code", project: "building", documents: "documents"};
const SAMPLE = {scan: "How are passwords stored, and does that meet the regulation?", project: "Which stairs fail the riser and going limits, and where?",
                documents: "Which requirements does this plan not cover?"};

async function api(url, body) {
  const r = await fetch(url, body ? {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(body)} : {});
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* not JSON */ }
    throw new Error(msg);
  }
  return r.json();
}
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => t.hidden = true, 4500);
}
const inline = s => s.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
function md(text) {
  return esc(text).split(/\n{2,}/).map(b => {
    const ls = b.split("\n").filter(l => l.trim());
    if (ls.length && ls.every(l => /^\s*[-•*] /.test(l))) return "<ul>" + ls.map(l => `<li>${inline(l.replace(/^\s*[-•*] /, ""))}</li>`).join("") + "</ul>";
    return `<p>${inline(b).replace(/\n/g, "<br>")}</p>`;
  }).join("");
}
const pill = v => { const [l, c] = VERDICT[v] || [v, "na"]; return `<span class="pill ${c}">${l}</span>`; };

// ---------------------------------------------------------------- sidebar and header

function renderSide() {
  $("#side").innerHTML = `<div class="side-top"><a class="brand" href="/">Compliance check</a>
      <button class="icon only-mobile" data-act="close-side" aria-label="Close menu">✕</button></div>
    <a class="newchat" href="/">＋ New chat</a>
    <div class="side-label">Chats</div>
    <nav class="chatlist">${S.chats.map(c => `<a href="/chat/${c.id}" class="${S.chat && S.chat.id === c.id ? "on" : ""}" title="${esc(c.title)}">${esc(c.title)}</a>`).join("")
      || '<p class="muted small" style="padding:0 10px">No chats yet.</p>'}</nav>
    <div class="side-label">Add material</div>
    <nav class="sidenav"><a href="/code">Code repositories</a><a href="/buildings">Buildings: models and drawings</a>
      <a href="/documents">Documents</a><a href="/regulations">Your regulations</a></nav>`;
}

function renderBar() {
  const c = S.chat, t = S.checks && S.checks.totals;
  $("#bar").innerHTML = `<button class="icon only-mobile" data-act="open-side" aria-label="Menu">☰</button>
    <div class="bar-title">${c ? esc(c.title) : "New chat"}</div>
    ${c ? `<div class="parts">${c.parts.map(p => `<a class="part k-${p.kind}" href="${p.href}" target="_blank" title="${esc(p.name)}">${KIND[p.kind]?.[1] || ""} ${esc(p.name)}</a>`).join("")}</div>` : ""}
    ${c && c.artifact ? `<button class="checks-btn" data-act="checks">Checks${t ? `${t.fail ? ` <span class="n fail">${t.fail}</span>` : ""}${t.pass ? ` <span class="n pass">${t.pass}</span>` : ""}` : ""}</button>` : ""}`;
}

// ---------------------------------------------------------------- the conversation

function renderThread(keep) {
  const sc = $("#scroll"), atEnd = sc.scrollHeight - sc.scrollTop - sc.clientHeight < 80;
  $("#thread").innerHTML = S.chat ? S.chat.turns.map(turn).join("") : empty();
  // after the composer below has its final height, or the end of the answer hides behind it
  if (!S.chat) sc.scrollTop = 0;
  else if (!keep || atEnd) requestAnimationFrame(() => { sc.scrollTop = sc.scrollHeight; });
}

function empty() {
  // one suggestion per name, every kind before a second of any kind
  const seen = new Set(), arts = [], rest = [];
  for (const a of S.ctx.artifacts) {
    if (seen.has(a.kind + a.name)) continue;
    seen.add(a.kind + a.name);
    (arts.some(b => b.kind === a.kind) ? rest : arts).push(a);
  }
  arts.push(...rest); arts.length = Math.min(arts.length, 4);
  return `<div class="hero"><h1>What should we check?</h1>
    <p class="muted">Ask about a codebase, a building model or drawing set, or a set of documents, read with the regulations you compiled.
      Every claim cites the line, page, sheet or element it rests on, and the citation opens it.</p>
    <div class="suggest">${arts.map(a => `<button type="button" class="sug" data-act="suggest" data-art="${a.kind}:${a.id}" data-q="${esc(SAMPLE[a.kind])}">
      <b>${KIND[a.kind][1]} ${esc(a.name)}</b><span>${esc(SAMPLE[a.kind])}</span></button>`).join("")}</div></div>`;
}

function turn(t) {
  return `<div class="msg user"><div class="bubble">${esc(t.question)}</div>${t.mode === "deep" ? '<div class="mode-tag">Deep research</div>' : ""}</div>
    <div class="msg bot"><div class="avatar">✓</div><div class="bot-body">${botBody(t)}</div></div>`;
}

function botBody(t) {
  if (t.state === "error") return `<div class="err">The question could not be answered. ${esc(t.error)}</div>`;
  if (t.state !== "done") {
    const log = t.log || [];
    return `<div class="working"><span class="dots"><i></i><i></i><i></i></span> ${esc(t.step || "Queued")}…</div>
      ${log.length > 1 ? `<details class="steps"><summary>${log.length} steps so far</summary><ol>${log.map(l => `<li>${esc(l)}</li>`).join("")}</ol></details>` : ""}`;
  }
  const a = t.answer, order = [], nums = {};
  const num = loc => nums[loc] ?? (order.push(loc), nums[loc] = order.length);
  const chip = loc => t.cites[loc] ? `<button class="cite" data-q="${t.qid}" data-loc="${esc(loc)}" aria-label="Source ${num(loc)}">${num(loc)}</button>` : "";
  const [sl, sc] = STATUS[a.status] || [a.status, "na"];
  const cov = a.coverage || {}, st = a.stats || {};
  let html = `<div class="meta"><span class="pill ${sc}">${sl}</span>
    <span>read ${cov.excerpts_read ?? "?"} of ${cov.excerpts_total ?? "?"} excerpts${cov.chars_total ? ` (${Math.round(100 * cov.chars_read / cov.chars_total)}% of the text)` : ""}</span>
    <span>${st.claims ?? 0} cited claim${st.claims === 1 ? "" : "s"}</span><span>${st.seconds ?? ""} s</span></div>`;
  if (a.answer) html += `<div class="answer">${md(a.answer)}</div>`;
  if (a.status === "unsupported") html += `<div class="box-note">The model answered, but none of the lines it cited were among those it was shown, so its answer is not repeated.</div>`;
  for (const s of a.sections || []) {
    if (!s.claims.length) continue;
    if (s.heading) html += `<div class="sec-h">${esc(s.heading)}</div>`;
    html += `<ul class="claims">${s.claims.map(c => `<li class="claim${c.basis === "absence" ? " absence" : ""}">${inline(esc(c.text))}
      ${c.basis === "absence" ? ` <span class="absent" title="${esc(c.note)}">· not found in what was read</span>` : ""} ${(c.at || []).map(chip).join("")}</li>`).join("")}</ul>`;
  }
  if (a.conflicts?.length) html += `<div class="box-note"><b>The material disagrees with itself</b><ul>${a.conflicts.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>`;
  if (a.open) html += `<p class="small"><b>Left open:</b> ${esc(a.open)}</p>`;
  if (order.length) html += `<div class="sources">${order.map(loc => { const c = t.cites[loc];
    return `<button class="src" data-q="${t.qid}" data-loc="${esc(loc)}"><span class="num">${nums[loc]}</span><span style="min-width:0"><span class="lbl">${esc(c.label)}</span>
      <span class="k">${KIND[c.kind]?.[0] || ""}${c.part ? " · " + esc(c.part) : ""}</span></span></button>`; }).join("")}</div>`;
  html += `<div class="actions"><button data-act="copy" data-q="${t.qid}">Copy</button><a href="/questions/${t.qid}" target="_blank">Open as a page</a></div>`;
  return html;
}

function citeOf(el) {
  const t = S.chat.turns.find(x => x.qid === el.dataset.q);
  return t && t.cites[el.dataset.loc];
}

// ---------------------------------------------------------------- composer

function renderComposer() {
  const fresh = !S.chat;
  $("#composer").innerHTML = `${fresh ? `<div class="ctx"><label class="muted" for="artifact">About</label>
      <select id="artifact"><option value="">Regulations only</option>${["scan", "project", "documents"].map(k => {
        const xs = S.ctx.artifacts.filter(a => a.kind === k);
        return xs.length ? `<optgroup label="${KIND[k][0]}">${xs.map(a => `<option value="${k}:${a.id}" ${S.artifact === `${k}:${a.id}` ? "selected" : ""}>${esc(a.name)}</option>`).join("")}</optgroup>` : "";
      }).join("")}</select><div class="regs" id="regs"></div></div>` : ""}
    <div class="box"><textarea id="q" rows="1" maxlength="2000" placeholder="${fresh ? "Ask a question…" : "Ask a follow-up…"}"></textarea>
      <div class="box-row"><div class="modes" role="radiogroup" aria-label="Mode">
        <button type="button" data-mode="quick" role="radio">Quick</button><button type="button" data-mode="deep" role="radio">Deep research</button></div>
        <button class="send" type="submit" aria-label="Send" disabled>↑</button></div></div>
    <p class="hint" id="hint"></p>`;
  if (fresh) renderRegs();
  setMode(S.mode);
}

function renderRegs() {
  const [kind] = S.artifact.split(":"), dom = DOMAIN[kind];
  const rs = S.ctx.regulations.filter(r => !dom || r.domain === dom);
  $("#regs").innerHTML = rs.map(r => `<button type="button" class="reg ${S.regs.has(r.id) ? "on" : ""}" data-reg="${r.id}" aria-pressed="${S.regs.has(r.id)}">§ ${esc(r.name)}</button>`).join("")
    || (dom ? '<span class="muted">No compiled regulation for this kind yet</span>' : "");
}

function setArtifact(v) {
  S.artifact = v;
  const a = S.ctx.artifacts.find(x => `${x.kind}:${x.id}` === v);
  S.regs = new Set(a ? a.regulations : []);
  if ($("#artifact")) { $("#artifact").value = v; renderRegs(); }
}

function setMode(m) {
  S.mode = m;
  document.querySelectorAll(".modes button").forEach(b => { b.classList.toggle("on", b.dataset.mode === m); b.setAttribute("aria-checked", b.dataset.mode === m); });
  $("#hint").textContent = m === "deep" ? "Deep research reads all of the material and follows its references: a few minutes."
    : "A quick answer reads what the question's words find: seconds. Every claim is checked against the text it cites.";
}

function grow() { const q = $("#q"); q.style.height = "auto"; q.style.height = Math.min(q.scrollHeight, 220) + "px"; $(".send").disabled = q.value.trim().length < 3; }

async function send(e) {
  e?.preventDefault();
  const q = $("#q").value.trim();
  if (q.length < 3) return;
  $(".send").disabled = true;
  try {
    if (!S.chat) {
      if (!S.artifact && !S.regs.size) throw new Error("Choose what to ask about: a codebase, building or documents, or a regulation.");
      const r = await api("/api/chats", {question: q, mode: S.mode, artifact: S.artifact, regulations: [...S.regs]});
      history.pushState({}, "", `/chat/${r.id}`);
      S.chat = await api(`/api/chats/${r.id}`);
      S.chats = await api("/api/chats");
      renderAll();
      loadChecks();
    } else {
      await api(`/api/chats/${S.chat.id}/turns`, {question: q, mode: S.mode});
      S.chat = await api(`/api/chats/${S.chat.id}`);
      $("#q").value = "";
      renderThread();
    }
    grow();
    poll();
  } catch (err) {
    toast(err.message);
    $(".send").disabled = false;
  }
}

function poll() {
  clearTimeout(S.timer);
  if (!S.chat || S.chat.turns.every(t => t.state === "done" || t.state === "error")) return;
  S.timer = setTimeout(async () => {
    try {
      const c = await api(`/api/chats/${S.chat.id}`);
      if (JSON.stringify(c.turns) !== JSON.stringify(S.chat.turns)) { S.chat = c; renderThread(true); }
    } catch { /* try again */ }
    poll();
  }, 1500);
}

// ---------------------------------------------------------------- the preview pane

function pane(title, sub, body, {flush = false, after} = {}) {
  const p = $("#pane");
  S.dispose?.(); S.dispose = null;
  p.hidden = false;
  p.innerHTML = `<div class="pane-bar">${S.stack.length > 1 ? '<button class="icon" data-act="back" aria-label="Back">←</button>' : ""}
      <div class="pane-title"><b>${esc(title)}</b>${sub ? `<span>${sub}</span>` : ""}</div>
      <button class="icon" data-act="close-pane" aria-label="Close">✕</button></div>
    <div class="pane-body${flush ? " flush" : ""}">${body}</div>`;
  after?.($(".pane-body", p));
}
function show(view) { S.stack.push(view); view(); }
function back() { S.stack.pop(); (S.stack.at(-1) || closePane)(); }
function closePane() { S.dispose?.(); S.dispose = null; S.stack = []; $("#pane").hidden = true; document.querySelectorAll(".cite.on").forEach(x => x.classList.remove("on")); }

async function openRef(ref, label) {
  show(async () => {
    pane(label || ref.at, KIND[ref.kind]?.[0], '<div class="loading">Opening…</div>');
    let p;
    try { p = await api(`/api/preview?kind=${ref.kind}&id=${ref.id}&at=${encodeURIComponent(ref.at)}`); }
    catch (err) { pane(label || ref.at, "", `<div class="loading">${esc(err.message)}</div>`); return; }
    (VIEWS[p.type] || VIEWS.text)(p, ref);
  });
}

const link = (href, text) => href ? `<a href="${href}" target="_blank" rel="noopener">${text} ↗</a>` : "";
const focusIn = body => { const f = $(".hit", body); f?.scrollIntoView({block: "center"}); };

const VIEWS = {
  code(p) {
    const [a, b] = p.focus || [0, 0];
    pane(p.path, `${p.focus ? `lines ${a}${b !== a ? "–" + b : ""} · ` : ""}${p.total} lines · ${link(p.href, "GitHub")}`,
      `<pre class="code">${p.lines.map((l, i) => { const n = p.start + i;
        return `<span class="ln${n >= a && n <= b ? " hit" : ""}"><span>${n}</span>${esc(l) || " "}</span>`; }).join("")}</pre>`, {after: focusIn});
  },
  document(p) {
    const [a, b] = p.focus || [0, 0];
    const text = () => { let pg = null; return `<div class="doc">${p.lines.map(([n, page, t]) => {
      const head = page && page !== pg ? `<div class="pg">Page ${pg = page}</div>` : "";
      return `${head}<div class="ln${n >= a && n <= b ? " hit" : ""}"><span>${n}</span><div>${esc(t)}</div></div>`; }).join("")}</div>`; };
    const pages = () => `<div class="pages">${p.images.map(src => `<img src="${src}" alt="Page" loading="lazy">`).join("")}</div>`;
    const sub = `${p.pages.length ? `page ${p.pages.join("–")} of ${p.page_count} · ` : ""}lines ${a}${b !== a ? "–" + b : ""} · ${link(p.href, "report")}`;
    const render = tab => pane(p.file, sub, `${p.images.length ? `<div class="tabs"><button data-tab="text" class="${tab === "text" ? "on" : ""}">Cited text</button>
        <button data-tab="page" class="${tab === "page" ? "on" : ""}">PDF page</button></div>` : ""}${tab === "page" ? pages() : text()}`,
      {after: body => { if (tab === "text") focusIn(body); body.querySelectorAll("[data-tab]").forEach(x => x.onclick = () => render(x.dataset.tab)); }});
    render("text");
  },
  sheet(p) {
    pane(p.label, link(p.href, "report"), `<div class="sheet"><h4>Cited region</h4><a href="${p.img}" target="_blank"><img src="${p.img}" alt="Cited region"></a>
      <h4>Whole sheet</h4><a href="${p.full}" target="_blank"><img src="${p.full}" alt="Sheet" loading="lazy"></a></div>`);
  },
  model(p) {
    pane(p.element ? `${p.element.type} ${p.element.id}` : p.label, `IFC element ${esc(p.gid)} · ${link(p.href, "report")}`,
      `<div class="model"><div class="loading">Loading the model…</div></div>`, {flush: true, after: body => model($(".model", body), p)});
  },
  clause(p) {
    pane(p.label, esc(p.regulation), `<div class="clause"><div class="small muted">${esc(p.at || "")} · ${link(p.href, "compiled regulation")}</div>
      <blockquote>${esc(p.text)}</blockquote>
      ${p.checks.length ? `<div class="small"><b>Checks compiled from this clause</b></div>${p.checks.map(k => `<div class="kcheck">
        <span class="pill ${k.kind === "computed" ? "pass" : k.kind === "assessed" ? "unc" : "na"}">${esc(k.kind)}</span> ${esc(k.summary)}
        ${k.question ? `<div class="small muted" style="margin-top:4px">Asks you: ${esc(k.question)}</div>` : ""}</div>`).join("")}` : ""}</div>`);
  },
  text(p) { pane(p.label, link(p.href, "report"), `<div class="clause">${esc(p.text || p.label)}</div>`); },
};

// the cited element highlighted in its model; the rest as a translucent context
async function model(el, p) {
  let THREE, OrbitControls;
  try {
    THREE = await import("three");
    ({OrbitControls} = await import("three/addons/controls/OrbitControls.js"));
  } catch { el.innerHTML = '<div class="loading">The 3D viewer could not load.</div>'; return; }
  let data;
  try { data = S.mesh[p.model] ??= await decodeMesh(await api(p.model)); }
  catch (err) { el.innerHTML = `<div class="loading">${esc(err.message)}</div>`; return; }
  if (!el.isConnected) return;
  el.innerHTML = "";
  const renderer = new THREE.WebGLRenderer({antialias: true, preserveDrawingBuffer: true});
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  el.appendChild(renderer.domElement);
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0xf3f5f8);
  const cam = new THREE.PerspectiveCamera(40, 1, 0.05, 5000);
  cam.up.set(0, 0, 1);
  scene.add(new THREE.HemisphereLight(0xffffff, 0x8a96a8, 2.4));
  const sun = new THREE.DirectionalLight(0xffffff, 1.4); sun.position.set(2, -3, 5); scene.add(sun);
  const ghost = new THREE.MeshLambertMaterial({color: 0xb8c0cc, transparent: true, opacity: 0.22, depthWrite: false});
  const solid = new THREE.MeshLambertMaterial({color: 0xd4d9e1});
  const hit = new THREE.MeshLambertMaterial({color: 0xe5484d, emissive: 0x5a0d10});
  let target = null;
  const meshes = [];
  for (const e of data.elements) {
    if (e.t === "IfcSpace" && e.g !== p.gid) continue;
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(e.v, 3));
    g.setIndex(new THREE.BufferAttribute(e.i, 1));
    g.computeVertexNormals();
    const m = new THREE.Mesh(g, e.g === p.gid ? hit : ghost);
    if (e.g === p.gid) { target = m; m.renderOrder = 2; }
    meshes.push(m); scene.add(m);
  }
  if (!target) meshes.forEach(m => m.material = solid);
  const controls = new OrbitControls(cam, renderer.domElement);
  const draw = () => renderer.render(scene, cam);
  controls.addEventListener("change", draw);
  const fit = obj => {
    const box = obj ? new THREE.Box3().setFromObject(obj) : new THREE.Box3(new THREE.Vector3(...data.bbox[0]), new THREE.Vector3(...data.bbox[1]));
    const c = box.getCenter(new THREE.Vector3()), r = Math.max(box.getSize(new THREE.Vector3()).length() / 2, 1);
    // an element is framed with its surroundings, so the reader sees where in the building it is
    cam.position.copy(c).add(new THREE.Vector3(1, -1.3, 0.9).normalize().multiplyScalar(obj ? Math.max(r * 4, 18) : r * 2.6));
    controls.target.copy(c); controls.update(); draw();
  };
  const size = () => { const w = el.clientWidth, h = el.clientHeight; renderer.setSize(w, h, false); cam.aspect = w / h; cam.updateProjectionMatrix(); draw(); };
  const ro = new ResizeObserver(size); ro.observe(el);
  size(); fit(target);
  const info = document.createElement("div");
  info.className = "model-info";
  const facts = Object.entries(p.element?.facts || {});
  info.innerHTML = target ? `<b>${esc(p.element?.type || "Element")} ${esc(p.element?.id || "")}</b>${facts.length ? `<table>${facts.map(([k, v]) =>
      `<tr><td>${esc(k)}</td><td>${esc(v.join(" / "))}</td></tr>`).join("")}</table>` : ""}`
    : `The cited element ${esc(p.gid)} has no geometry in the model; the whole model is shown.`;
  const tools = document.createElement("div");
  tools.className = "model-tools";
  tools.innerHTML = `${target ? '<button data-v="el">Element</button><button data-v="xray">X-ray</button>' : ""}<button data-v="all">Whole model</button>`;
  tools.onclick = e => {
    const v = e.target.dataset.v;
    if (v === "el") fit(target);
    if (v === "all") fit(null);
    if (v === "xray") { const on = ghost.opacity < 0.5; ghost.opacity = on ? 0.85 : 0.22; ghost.depthWrite = on; ghost.needsUpdate = true; draw(); }
  };
  el.append(info, tools);
  S.dispose = () => { ro.disconnect(); controls.dispose(); renderer.dispose(); meshes.forEach(m => m.geometry.dispose()); };
}

async function decodeMesh(d) {
  const bytes = s => { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u.buffer; };
  for (const e of d.elements) { e.v = new Float32Array(bytes(e.v)); e.i = new Uint32Array(bytes(e.i)); }
  return d;
}

// ---------------------------------------------------------------- the context's checks

async function loadChecks() {
  if (!S.chat?.artifact) return;
  try { S.checks = await api(`/api/checks?kind=${S.chat.artifact.kind}&id=${S.chat.artifact.id}`); renderBar(); } catch { /* the report is not ready */ }
}

function checksView() {
  const c = S.checks;
  if (!c) { pane("Checks", "", '<div class="loading">No finished report for this material.</div>'); return; }
  const groups = {attention: ["Needs attention", e => ["fail", "uncertain"].includes(e.verdict)], fail: ["Fails", e => e.verdict === "fail"],
                  open: ["Open", e => e.verdict === "unknown" || e.verdict === "uncertain"], pass: ["Passes", e => e.verdict === "pass"], all: ["All", () => true]};
  const shown = c.entries.filter(groups[S.cfilter][1]);
  const t = c.totals;
  pane("Checks", c.standards.map(s => esc(s.label)).join(" · "),
    `<div class="cfilter">${Object.entries(groups).map(([k, [l, f]]) => `<button data-f="${k}" class="${S.cfilter === k ? "on" : ""}">${l} ${c.entries.filter(f).length}</button>`).join("")}</div>
     <div class="std">${t.fail || 0} fail · ${(t.unknown || 0) + (t.uncertain || 0)} open · ${t.pass || 0} pass · ${t.not_applicable || 0} do not apply</div>
     ${shown.map((e, i) => `<details class="check"${i === 0 && e.verdict === "fail" ? " open" : ""}><summary>${pill(e.verdict)}<span class="t"><b>${esc(e.section || "")}</b>${esc(e.title)}</span></summary>
       <div class="body">${e.quote ? `<blockquote>${esc(e.quote)}</blockquote>` : ""}
       ${e.reasons.map(r => `<div class="reason">${esc(r)}</div>`).join("")}
       ${e.open.length ? `<div class="reason muted">Open: ${e.open.map(esc).join(", ")}</div>` : ""}
       ${e.at.length ? `<div class="locs">${e.at.map(a => `<button class="loc" data-at="${esc(a.at)}" title="${esc(a.at)}">${esc(a.label)}</button>`).join("")}</div>` : ""}
       <button class="askit" data-ask="${esc(`Why does ${e.section ? e.section + " (" + e.title + ")" : e.title} ${e.verdict === "pass" ? "pass" : e.verdict === "fail" ? "fail" : "stay open"}? Show where.`)}">Ask about this</button></div></details>`).join("")
       || '<div class="loading">No checks here.</div>'}`,
    {after: body => {
      body.querySelectorAll("[data-f]").forEach(b => b.onclick = () => { S.cfilter = b.dataset.f; checksView(); });
      body.querySelectorAll(".loc").forEach(b => b.onclick = () => openRef({...S.chat.artifact, at: b.dataset.at}, b.textContent));
      body.querySelectorAll("[data-ask]").forEach(b => b.onclick = () => {
        $("#q").value = b.dataset.ask; grow(); $("#q").focus(); if (matchMedia("(max-width: 860px)").matches) closePane(); });
    }});
}

// ---------------------------------------------------------------- hover card for citations

function card(el) {
  const c = citeOf(el), box = $("#card");
  if (!c) return;
  const body = c.lines ? `<pre>${c.lines.slice(0, 8).map(([n, t]) => `${String(n).padStart(4)}  ${esc(t)}`).join("\n")}</pre>`
    : c.img ? `<img src="${c.img}" alt="">` : c.text ? `<div class="q">${esc(c.text.slice(0, 500))}</div>` : "";
  box.innerHTML = `<b>${esc(c.label)}</b><span class="muted">${KIND[c.kind]?.[0] || ""}${c.part ? " · " + esc(c.part) : ""} · click to open</span>${body}`;
  box.hidden = false;
  const r = el.getBoundingClientRect(), w = box.offsetWidth, h = box.offsetHeight;
  box.style.left = Math.max(8, Math.min(r.left - 20, innerWidth - w - 8)) + "px";
  box.style.top = (r.top - h - 8 > 8 ? r.top - h - 8 : r.bottom + 8) + "px";
}

// ---------------------------------------------------------------- wiring

function renderAll() { renderSide(); renderBar(); renderThread(); renderComposer(); }

document.addEventListener("click", e => {
  const el = e.target.closest("[data-act], .cite, .src, [data-mode], [data-reg]");
  if (!el) return;
  if (el.matches(".cite, .src")) {
    const c = citeOf(el);
    if (!c) return;
    $("#card").hidden = true;
    document.querySelectorAll(".cite.on").forEach(x => x.classList.remove("on"));
    document.querySelectorAll(`.cite[data-q="${el.dataset.q}"]`).forEach(x => { if (x.dataset.loc === el.dataset.loc) x.classList.add("on"); });
    S.stack = [];
    openRef(c.ref, c.label);
    return;
  }
  if (el.dataset.mode) return setMode(el.dataset.mode);
  if (el.dataset.reg) { const id = el.dataset.reg; S.regs.has(id) ? S.regs.delete(id) : S.regs.add(id); renderRegs(); return; }
  const act = el.dataset.act;
  if (act === "open-side") $("#app").classList.add("side-open");
  if (act === "close-side") $("#app").classList.remove("side-open");
  if (act === "close-pane") closePane();
  if (act === "back") back();
  if (act === "checks") { S.stack = []; show(checksView); }
  if (act === "suggest") { setArtifact(el.dataset.art); $("#q").value = el.dataset.q; grow(); $("#q").focus(); }
  if (act === "copy") {
    const t = S.chat.turns.find(x => x.qid === el.dataset.q), a = t.answer;
    const text = [a.answer, ...(a.sections || []).flatMap(s => s.claims.map(c => `- ${c.text} [${c.at.join("; ")}]`))].filter(Boolean).join("\n");
    navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => toast("Could not copy"));
  }
});
document.addEventListener("change", e => { if (e.target.id === "artifact") setArtifact(e.target.value); });
document.addEventListener("input", e => { if (e.target.id === "q") grow(); });
document.addEventListener("keydown", e => {
  if (e.target.id === "q" && e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); }
  if (e.key === "Escape" && !$("#pane").hidden) closePane();
});
document.addEventListener("mouseover", e => { const c = e.target.closest?.(".cite"); if (c && matchMedia("(hover: hover)").matches) card(c); });
document.addEventListener("mouseout", e => { if (e.target.closest?.(".cite")) $("#card").hidden = true; });
$("#composer").addEventListener("submit", send);
addEventListener("popstate", () => location.reload());

if (!S.chat && S.artifact) setArtifact(S.artifact);
renderAll();
if (!S.chat && S.artifact) setArtifact(S.artifact);
if (S.chat) { loadChecks(); poll(); }
