// The TFPS dashboard: a read-only view built from this host's /v1 API.
//
// Every value shown comes from the API, and some of it is attacker-controlled
// (a block's detail is often a SIP User-Agent). So nothing is ever written as
// HTML: elements are built and filled with textContent only.
"use strict";

const REFRESH_MS = 10000;
const BLOCKS_EVERY = 3; // the full listing every third refresh (30 s): it is the heavy one
const MAX_ROWS = 500;
const TOKEN_KEY = "tfps-token";

let paused = false;
let tick = 0;
// Each refresh takes the next generation; only the newest may change the page,
// so a slow batch that finishes after a newer one (or after a token is entered)
// is dropped instead of overwriting it or reopening the token prompt.
let generation = 0;
let inFlight = false;
let windowName = "last_day";
let lastStats = null;
let lastBlocks = [];
let lastUpdate = 0;

const $ = (id) => document.getElementById(id);

function el(tag, props, ...children) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") e.className = v;
      else if (k === "title") e.title = v;
      else e.setAttribute(k, v);
    }
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    e.append(typeof c === "string" || typeof c === "number" ? String(c) : c);
  }
  return e;
}

function fill(node, ...children) {
  node.replaceChildren(...children);
}

function text(id, value) {
  $(id).textContent = value;
}

function token() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch (_) {
    return null;
  }
}

class AuthError extends Error {}

async function api(path) {
  const headers = { Accept: "application/json" };
  const t = token();
  if (t) headers.Authorization = "Bearer " + t;
  const r = await fetch(path, { headers, cache: "no-store", credentials: "omit" });
  if (r.status === 401) throw new AuthError("the API needs a token");
  let body = null;
  try {
    body = await r.json();
  } catch (_) {
    throw new Error("HTTP " + r.status + ": the answer was not JSON");
  }
  if (!r.ok) throw new Error((body && body.error) || "HTTP " + r.status);
  return body;
}

// ---------------------------------------------------------------- formatting

const nf = new Intl.NumberFormat();
const num = (n) => (n === null || n === undefined ? "–" : nf.format(n));

function compact(n) {
  if (n === null || n === undefined) return "–";
  if (n < 10000) return nf.format(n);
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

function span(secs) {
  if (secs === null || secs === undefined) return "–";
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return s + " s";
  if (s < 3600) return Math.floor(s / 60) + " min";
  if (s < 86400) return Math.floor(s / 3600) + " h " + Math.floor((s % 3600) / 60) + " min";
  return Math.floor(s / 86400) + " d " + Math.floor((s % 86400) / 3600) + " h";
}

const nowSecs = () => Math.floor(Date.now() / 1000);

function ago(ts) {
  return ts ? span(nowSecs() - ts) + " ago" : "–";
}

function until(ts) {
  if (ts === null || ts === undefined) return "never";
  const left = ts - nowSecs();
  return left <= 0 ? "now" : "in " + span(left);
}

function stamp(ts) {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function showError(id, err) {
  const p = $(id);
  if (err) {
    p.textContent = String(err.message || err);
    p.hidden = false;
  } else {
    p.hidden = true;
  }
}

// ---------------------------------------------------------------- rendering

function renderStatus(s) {
  const badge = $("enforcement");
  badge.textContent = s.enforcement === "active" ? "enforcing" : "not enforcing";
  badge.className = "badge " + (s.enforcement === "active" ? "ok" : "bad");
  text("version", "v" + s.version);
  text("k-blocked", compact(s.blocked_now));
  fill(
    $("status"),
    ...[
      ["enforcement", s.enforcement],
      ["block map", s.map || "–"],
      ["database", s.db],
      ["learned pairs", num(s.pairs)],
      ["last checkpoint", s.last_checkpoint ? ago(s.last_checkpoint) : "–"],
      ["version", s.version],
    ].map(([k, v]) => el("div", null, el("dt", null, k), el("dd", null, v)))
  );
}

function renderStats(st) {
  lastStats = st;
  const k = st.kernel;
  text("k-dropped", k ? compact(k.dropped) : "–");
  text("k-dropped-sub", k ? "of " + compact(k.seen) + " packets seen · " + compact(k.expired) + " expired" : "kernel counters unreadable");
  const c = st.condemnation;
  text(
    "k-blocked-sub",
    c ? num(c.perimeter_manual) + " perimeter / manual · " + num(c.apiban_feed_only) + " feed only" : ""
  );
  text("k-day", compact(st.blocks.last_day.total));
  text("k-day-sub", num(st.blocks.last_hour.total) + " in the last hour · " + num(st.blocks.last_week.total) + " in 7 d");
  text("k-feed", compact(st.blocks.apiban_feed));
  text("k-feed-sub", "addresses on the APIBAN list");
  text("k-up", st.running_for_secs === null ? "–" : span(st.running_for_secs));
  text("k-up-sub", "learned " + num(st.learned.pairs) + " pairs, " + num(st.learned.countries) + " countries");
  renderReasons();

  const t = st.traffic;
  text("traffic-age", t && t.age_secs !== null ? "checkpoint " + span(t.age_secs) + " ago" : "no checkpoint yet");
  const counters = t ? Object.entries(t.counters) : [];
  fill(
    $("traffic"),
    ...(counters.length
      ? counters.map(([name, v]) => el("div", { title: name }, el("dt", null, name), el("dd", null, num(v))))
      : [el("p", { class: "empty" }, "The daemon has not written its counters yet (every 5 minutes).")])
  );

  const ig = st.ignoreip ? Object.entries(st.ignoreip) : [];
  fill(
    $("ignoreip"),
    ...(ig.length
      ? ig.map(([rule, hits]) => el("div", null, el("dt", null, rule), el("dd", null, hits === 0 ? "never matched" : num(hits))))
      : [el("p", { class: "empty" }, "No exemptions matched yet.")])
  );
}

function renderReasons() {
  const st = lastStats;
  if (!st) return;
  const w = st.blocks[windowName];
  const rows = Object.entries(w.by_reason).sort((a, b) => b[1] - a[1]);
  const max = rows.length ? rows[0][1] : 0;
  fill(
    $("reasons"),
    ...(rows.length
      ? rows.map(([reason, n]) =>
          el(
            "div",
            { class: "bar-row" },
            el("span", { class: "what", title: reason }, reason),
            el("span", { class: "track" }, barFill(max ? n / max : 0)),
            el("span", { class: "n" }, num(n))
          )
        )
      : [el("p", { class: "empty" }, "No blocks in this window.")])
  );
}

function barFill(fraction) {
  const f = el("span", { class: "fill" });
  f.style.width = Math.max(2, Math.round(fraction * 100)) + "%";
  f.style.display = "block";
  return f;
}

function reasonCell(reason, source) {
  if (!reason) return el("td", null, el("span", { class: "tag" }, "unattributed"));
  return el("td", null, el("span", { class: "tag" }, reason), source ? " by " + source : null);
}

function renderBlocks() {
  const q = $("filter").value.trim().toLowerCase();
  const rows = q
    ? lastBlocks.filter((b) => [b.ip, b.reason, b.detail, b.source].some((v) => v && String(v).toLowerCase().includes(q)))
    : lastBlocks;
  const shown = rows.slice(0, MAX_ROWS);
  text(
    "blocks-count",
    rows.length > shown.length
      ? "showing " + num(shown.length) + " of " + num(rows.length)
      : num(rows.length) + (q ? " matching" : " in the map")
  );
  fill(
    $("blocks"),
    ...(shown.length
      ? shown.map((b) =>
          el(
            "tr",
            null,
            el("td", { class: "ip" }, b.ip),
            reasonCell(b.reason, b.source),
            el("td", { class: "detail" }, b.detail || ""),
            el("td", { class: "when", title: stamp(b.first_seen) }, ago(b.first_seen)),
            el("td", { class: "when", title: b.expires ? stamp(b.expires) : "no expiry" }, until(b.expires))
          )
        )
      : [el("tr", null, el("td", { colspan: "5", class: "empty" }, q ? "Nothing matches." : "Nothing is blocked."))])
  );
}

function renderLog(rows) {
  fill(
    $("log"),
    ...(rows.length
      ? rows.map((r) =>
          el(
            "tr",
            null,
            el("td", { class: "when", title: stamp(r.first_seen) }, ago(r.first_seen)),
            el("td", { class: "ip" }, r.ip),
            el("td", null, el("span", { class: "tag" }, r.reason)),
            el("td", { class: "detail" }, r.detail)
          )
        )
      : [el("tr", null, el("td", { colspan: "4", class: "empty" }, "The audit log is empty."))])
  );
}

// ---------------------------------------------------------------- refresh

function needToken(on, message) {
  $("auth").hidden = !on;
  showError("auth-error", on && token() ? new Error(message || "that token was refused") : null);
}

async function refresh() {
  const gen = ++generation;
  inFlight = true;
  try {
    await refreshAs(gen);
  } finally {
    if (gen === generation) inFlight = false;
  }
}

async function refreshAs(gen) {
  const withBlocks = tick % BLOCKS_EVERY === 0;
  tick++;
  const jobs = [api("/v1/status"), api("/v1/stats"), api("/v1/log?limit=50")];
  if (withBlocks) jobs.push(api("/v1/blocks"));
  const [status, stats, log, blocks] = await Promise.allSettled(jobs);
  if (gen !== generation) return; // superseded by a newer refresh
  const results = [status, stats, log, blocks].filter(Boolean);
  if (results.some((r) => r.status === "rejected" && r.reason instanceof AuthError)) {
    needToken(true);
    return;
  }
  needToken(false);

  if (status.status === "fulfilled") renderStatus(status.value);
  if (stats.status === "fulfilled") renderStats(stats.value);
  showError("stats-error", stats.status === "rejected" ? stats.reason : null);
  if (log.status === "fulfilled") renderLog(log.value);
  showError("log-error", log.status === "rejected" ? log.reason : null);
  if (blocks) {
    if (blocks.status === "fulfilled") {
      // The API lists blocks in kernel-map order; the table shows the newest
      // first, so the row limit keeps the newest. No first-seen sorts last.
      lastBlocks = blocks.value.slice().sort((a, b) => (b.first_seen || 0) - (a.first_seen || 0));
      renderBlocks();
    }
    showError("blocks-error", blocks.status === "rejected" ? blocks.reason : null);
  }
  lastUpdate = Date.now();
  showUpdated();
}

function showUpdated() {
  text("updated", lastUpdate ? (paused ? "paused · " : "") + "updated " + span((Date.now() - lastUpdate) / 1000) + " ago" : "");
}

function start() {
  text("host", location.host);
  $("pause").addEventListener("click", () => {
    paused = !paused;
    $("pause").textContent = paused ? "Resume" : "Pause";
    showUpdated();
  });
  $("refresh").addEventListener("click", () => {
    tick = 0; // include the block list
    refresh();
  });
  $("filter").addEventListener("input", renderBlocks);
  for (const b of document.querySelectorAll("#windows button")) {
    b.addEventListener("click", () => {
      windowName = b.dataset.window;
      for (const o of document.querySelectorAll("#windows button")) {
        o.setAttribute("aria-selected", String(o === b));
      }
      renderReasons();
    });
  }
  $("auth-form").addEventListener("submit", (e) => {
    e.preventDefault();
    try {
      sessionStorage.setItem(TOKEN_KEY, $("token").value.trim());
    } catch (_) {
      showError("auth-error", new Error("this browser will not keep the token (session storage is blocked)"));
      return;
    }
    $("token").value = "";
    tick = 0;
    refresh();
  });
  refresh();
  setInterval(() => {
    // A timer tick waits for the batch in flight; Refresh and a new token
    // start a newer one, which supersedes it.
    if (!paused && !inFlight) refresh();
  }, REFRESH_MS);
  setInterval(showUpdated, 1000);
}

start();
