// Login Analyser panel for Home Assistant.
// Everything shown here can be attacker-controlled (paths, user agents,
// usernames, passwords, headers) so EVERY dynamic value goes through esc().

const esc = (v) =>
  String(v ?? "").replace(/[&<>"'`]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" })[c]);

const flag = (cc) =>
  cc && /^[A-Z]{2}$/i.test(cc) ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0))) : "🏳️";

const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "—");
const ago = (ts, now) => {
  if (!ts) return "—";
  const s = Math.max(0, Math.round((now ?? Date.now() / 1000) - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};
const sevClass = (s) => (s >= 5 ? "sev5" : s >= 4 ? "sev4" : s >= 3 ? "sev3" : "sev1");
const top = (obj, n = 10) => Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, n);

class LoginAnalyserPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._tab = "attackers";
    this._filter = "";
    this._sort = "last_seen";
    this._selected = null;
    this._detail = null;
    this._data = null;
    this._error = null;
  }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    if (first) {
      this._load();
      this._timer = setInterval(() => this._load(), 15000);
    }
  }
  set narrow(v) { this._narrow = v; }
  set panel(v) { this._panel = v; }

  disconnectedCallback() { clearInterval(this._timer); }

  async _ws(msg) { return this._hass.callWS(msg); }

  async _load() {
    try {
      this._data = await this._ws({ type: "login_analyser/data", event_limit: 1500 });
      this._error = null;
      try {
        this._http = await this._ws({ type: "http/config" });
      } catch (e) {
        this._http = null; // older HA without UI-managed HTTP settings
      }
      if (this._selected) this._detail = await this._ws({ type: "login_analyser/ip", ip: this._selected });
    } catch (e) {
      this._error = e.message || String(e);
    }
    this._render();
  }

  async _open(ip) {
    this._selected = ip;
    this._detail = null;
    this._render();
    this._detail = await this._ws({ type: "login_analyser/ip", ip });
    this._render();
  }

  async _action(kind, ip, extra = {}) {
    try {
      if (kind === "ban") await this._ws({ type: "login_analyser/ban", ip, ...extra });
      if (kind === "unban") await this._ws({ type: "login_analyser/unban", ip });
      if (kind === "enrich") await this._ws({ type: "login_analyser/enrich", ip });
    } catch (e) {
      alert(`Failed: ${e.message || e}`);
    }
    await this._load();
  }

  // HA 2026.11+: HTTP settings live in Settings > System > Network and are
  // changed via http/config/configure (restart + 5 minute auto-revert).
  async _enableBlocking() {
    const h = this._http;
    const base = { ...((h.pending && !h.pending.error) ? h.pending : h.stable) };
    for (const k of ["created_at", "error", "error_message"]) delete base[k];
    base.ip_ban_enabled = true;
    base.login_attempts_threshold = -1;
    if (!confirm("Turn on IP blocking?\n\nThis sets ip_ban_enabled = true and login_attempts_threshold = -1 in Home Assistant's HTTP settings (all other settings are kept). Home Assistant will RESTART.\n\nAfter the restart, come back here (or to Settings > System > Network) within 5 minutes and confirm, otherwise HA automatically reverts the change.")) return;
    try {
      await this._ws({ type: "http/config/configure", config: base });
      alert("Saved. Home Assistant is restarting. Re-open this page afterwards and press 'Keep these HTTP settings'.");
    } catch (e) {
      alert(`Could not change HTTP settings: ${e.message || e}`);
    }
  }

  async _promoteHttp() {
    try {
      await this._ws({ type: "http/config/promote" });
      await this._load();
    } catch (e) {
      alert(`Could not confirm: ${e.message || e}`);
    }
  }

  _setupBanner(s) {
    const h = this._http;
    const pendingActive = h && h.active_config_type === "pending" && h.revert_at;
    if (pendingActive) {
      return `<div class="alert"><b>New HTTP settings are on trial.</b> Home Assistant reverts them automatically at
        ${esc(new Date(h.revert_at).toLocaleTimeString())} unless you confirm. <button id="promotehttp">Keep these HTTP settings</button></div>`;
    }
    if (s.ban_backend_available) return "";
    if (h) {
      return `<div class="alert bad"><b>Blocking is not active.</b> Attempts are being recorded, but IPs can't be blocked until
        Home Assistant's IP-ban layer is switched on. <button id="enableblocking">Enable blocking</button>
        <div class="small muted">Changes Settings → System → Network → HTTP server, then restarts HA.</div></div>`;
    }
    return `<div class="alert bad"><b>Blocking is not active.</b> Add <code>ip_ban_enabled: true</code> and
      <code>login_attempts_threshold: -1</code> under <code>http:</code> in configuration.yaml and restart.</div>`;
  }

  // ------------------------------------------------------------------ views
  _tiles(s, d) {
    const tc = s.top_countries?.[0];
    return `
      <div class="tiles">
        <div class="tile"><div class="n">${esc(s.events_24h)}</div><div class="l">attempts · 24h</div></div>
        <div class="tile"><div class="n">${esc(s.events_7d)}</div><div class="l">attempts · 7 days</div></div>
        <div class="tile"><div class="n">${esc(s.unique_ips_24h)}</div><div class="l">attacking IPs · 24h</div></div>
        <div class="tile"><div class="n">${esc(s.unique_ips)}</div><div class="l">IPs on record</div></div>
        <div class="tile"><div class="n">${esc(s.active_bans)}</div><div class="l">active bans</div></div>
        <div class="tile"><div class="n">${tc ? flag(tc[0]) + " " + esc(tc[0]) : "—"}</div><div class="l">top country</div></div>
      </div>`;
  }

  _chart(events, now) {
    const hours = 48;
    const buckets = new Array(hours).fill(0);
    const banned = new Array(hours).fill(0);
    for (const e of events) {
      const h = Math.floor((now - e.ts) / 3600);
      if (h >= 0 && h < hours) {
        buckets[hours - 1 - h]++;
        if (e.action === "banned") banned[hours - 1 - h]++;
      }
    }
    const max = Math.max(1, ...buckets);
    const bars = buckets
      .map((v, i) => {
        const hAgo = hours - 1 - i;
        return `<div class="bar" title="${esc(v)} attempts, ${esc(banned[i])} bans · ${hAgo}h ago"><div style="height:${(v / max) * 100}%"></div></div>`;
      })
      .join("");
    return `<div class="card"><div class="ct">Attempts per hour · last 48h <span class="muted">(peak ${max})</span></div><div class="chart">${bars}</div><div class="axis"><span>48h ago</span><span>24h ago</span><span>now</span></div></div>`;
  }

  _attackers(d) {
    const f = this._filter.toLowerCase();
    let rows = Object.entries(d.ips).map(([ip, r]) => ({ ip, ...r }));
    if (f) {
      rows = rows.filter((r) => {
        const g = r.enrichment?.geo || {};
        return [r.ip, r.enrichment?.rdns, g.country, g.city, g.isp, g.org, g.as, ...Object.keys(r.categories || {}), ...Object.keys(r.usernames || {})]
          .join(" ").toLowerCase().includes(f);
      });
    }
    const key = this._sort;
    rows.sort((a, b) => (b[key] ?? 0) - (a[key] ?? 0));
    const body = rows.slice(0, 500).map((r) => {
      const g = r.enrichment?.geo || {};
      const ab = r.enrichment?.abuse;
      const ban = d.bans[r.ip];
      const badges = [
        g.hosting ? `<span class="b warn">datacenter</span>` : "",
        g.proxy ? `<span class="b warn">proxy/VPN</span>` : "",
        g.mobile ? `<span class="b">mobile</span>` : "",
        ab?.score != null ? `<span class="b ${ab.score >= 50 ? "bad" : ""}">abuse ${esc(ab.score)}%</span>` : "",
        ...(r.enrichment?.shodan?.tags || []).map((t) => `<span class="b ${t === "compromised" || t === "malware" ? "bad" : ""}">${esc(t)}</span>`),
        r.likely_own_device ? `<span class="b ok">HA app?</span>` : "",
        r.successful_logins ? `<span class="b ok">logged in ok</span>` : "",
      ].join("");
      return `<tr data-ip="${esc(r.ip)}" class="${this._selected === r.ip ? "sel" : ""}">
        <td><span class="sev ${sevClass(r.max_severity)}"></span><code>${esc(r.ip)}</code><div class="muted small">${esc(r.enrichment?.rdns || "")}</div></td>
        <td>${flag(g.countryCode)} ${esc(g.country || (r.enrichment ? "" : "looking up…"))}<div class="muted small">${esc([g.city, g.regionName].filter(Boolean).join(", "))}</div></td>
        <td>${esc(g.isp || g.org || "")}<div class="muted small">${esc(g.as || "")}</div>${badges}</td>
        <td>${top(r.categories, 3).map(([c, n]) => `<div class="small">${esc(c)} <span class="muted">×${esc(n)}</span></div>`).join("")}</td>
        <td class="num">${esc(r.count)}</td>
        <td>${ago(r.last_seen, d.now)}<div class="muted small">first ${ago(r.first_seen, d.now)}</div></td>
        <td>${ban ? `<span class="b bad">${ban.expires ? "banned " + esc(this._until(ban.expires, d.now)) : "banned ∞"}</span>` : ""}</td>
      </tr>`;
    }).join("");
    return `
      <div class="toolbar">
        <input id="filter" placeholder="Filter by IP, country, ISP, category, username…" value="${esc(this._filter)}">
        <select id="sort">
          ${[["last_seen", "Most recent"], ["count", "Most attempts"], ["max_severity", "Most severe"], ["first_seen", "Newest attacker"]]
            .map(([v, l]) => `<option value="${v}" ${v === key ? "selected" : ""}>${l}</option>`).join("")}
        </select>
      </div>
      <div class="tablewrap"><table class="list">
        <thead><tr><th>IP / host</th><th>Location</th><th>Network</th><th>What they did</th><th>Hits</th><th>Seen</th><th>Status</th></tr></thead>
        <tbody>${body || `<tr><td colspan="7" class="muted">No failed attempts recorded yet. They will appear here as they happen.</td></tr>`}</tbody>
      </table></div>`;
  }

  _until(exp, now) {
    const s = exp - now;
    if (s <= 0) return "expiring";
    if (s < 3600) return `${Math.ceil(s / 60)}m`;
    if (s < 86400) return `${Math.round(s / 3600)}h`;
    return `${Math.round(s / 86400)}d`;
  }

  _feed(d) {
    const ev = [...d.events].reverse().slice(0, 300);
    return `<div class="tablewrap"><table class="list">
      <thead><tr><th>When</th><th>IP</th><th>Request</th><th>Category</th><th>Credentials</th><th>Action</th></tr></thead>
      <tbody>${ev.map((e) => {
        const g = d.ips[e.ip]?.enrichment?.geo || {};
        return `<tr data-ip="${esc(e.ip)}">
          <td class="nowrap">${esc(fmtTime(e.ts))}</td>
          <td>${flag(g.countryCode)} <code>${esc(e.ip)}</code></td>
          <td><code class="path">${esc(e.method)} ${esc(e.path)}</code><div class="muted small ua">${esc(e.user_agent)}</div></td>
          <td><span class="sev ${sevClass(e.classification?.severity)}"></span>${esc(e.classification?.label)}</td>
          <td>${e.username ? `👤 <code>${esc(e.username)}</code>` : ""}${e.password ? `<br>🔑 <code>${esc(e.password)}</code>` : e.password_reason === "hidden_real_username" ? `<br><span class="b warn">real username! pw hidden</span>` : ""}</td>
          <td>${e.action ? esc(e.action) : ""}</td></tr>`;
      }).join("") || `<tr><td colspan="6" class="muted">Nothing yet.</td></tr>`}</tbody></table></div>`;
  }

  _creds(d) {
    const s = d.summary;
    const known = d.events.filter((e) => e.known_user);
    const list = (arr, label) => `<div class="card half"><div class="ct">${label}</div>
      ${arr.length ? `<table class="kv">${arr.map(([k, n]) => `<tr><td><code>${esc(k)}</code></td><td class="num">${esc(n)}</td></tr>`).join("")}</table>` : `<div class="muted">None captured yet.</div>`}</div>`;
    return `
      ${known.length ? `<div class="alert">⚠️ <b>${known.length}</b> attempt(s) used a username that really exists in your Home Assistant
        (${[...new Set(known.map((e) => esc(e.username)))].join(", ")}). Someone knows or guessed a real account name — make sure its password is strong and enable 2FA (MFA).
        Passwords for real usernames are never stored.</div>` : ""}
      <div class="row">
        ${list(s.top_usernames, "Usernames tried")}
        ${list(s.top_passwords, "Passwords tried <span class='muted small'>(only for usernames that don't exist here)</span>")}
      </div>
      <div class="row">
        <div class="card half"><div class="ct">Attack types</div><table class="kv">${s.top_categories.map(([k, n]) => `<tr><td>${esc(k)}</td><td class="num">${esc(n)}</td></tr>`).join("") || "<tr><td class='muted'>—</td></tr>"}</table></div>
        <div class="card half"><div class="ct">Countries</div><table class="kv">${s.top_countries.map(([k, n]) => `<tr><td>${flag(k)} ${esc(k)}</td><td class="num">${esc(n)}</td></tr>`).join("") || "<tr><td class='muted'>—</td></tr>"}</table></div>
      </div>`;
  }

  _bans(d) {
    const rows = Object.entries(d.bans).sort((a, b) => b[1].banned_at - a[1].banned_at);
    return `
      <div class="toolbar">
        <input id="manualip" placeholder="IP to ban manually">
        <button id="manualban">Ban 24h</button><button id="manualperm" class="danger">Ban permanently</button>
      </div>
      <div class="tablewrap"><table class="list"><thead><tr><th>IP</th><th>Reason</th><th>Banned</th><th>Expires</th><th>#</th><th>Enforced</th><th></th></tr></thead>
      <tbody>${rows.map(([ip, b]) => `<tr data-ip="${esc(ip)}">
        <td><code>${esc(ip)}</code></td><td>${esc(b.reason)}</td><td>${esc(fmtTime(b.banned_at))}</td>
        <td>${b.expires ? esc(fmtTime(b.expires)) + ` <span class="muted">(${esc(this._until(b.expires, d.now))})</span>` : "never"}</td>
        <td>${esc(b.ban_number)}</td><td>${b.enforced ? "✅" : "❌"}</td>
        <td><button data-unban="${esc(ip)}">Unban</button></td></tr>`).join("") || `<tr><td colspan="7" class="muted">No bans.</td></tr>`}</tbody></table></div>`;
  }

  _success(d) {
    const rows = Object.entries(d.successes).sort((a, b) => b[1].last - a[1].last);
    return `<p class="muted">IPs that logged in successfully. These are trusted (never auto-banned) for 30 days if that option is on. Anything here you don't recognise is a red flag.</p>
      <div class="tablewrap"><table class="list"><thead><tr><th>IP</th><th>Logins</th><th>Last</th><th>User agent</th></tr></thead>
      <tbody>${rows.map(([ip, r]) => `<tr><td><code>${esc(ip)}</code></td><td>${esc(r.count)}</td><td>${esc(fmtTime(r.last))}</td><td class="small">${esc(r.user_agent)}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">None recorded since install.</td></tr>`}</tbody></table></div>`;
  }

  _drawer(d) {
    if (!this._selected) return "";
    const x = this._detail;
    const ip = this._selected;
    if (!x) return `<div class="drawer"><div class="dh"><b>${esc(ip)}</b><button id="close">✕</button></div><div class="muted">Loading…</div></div>`;
    const r = x.record || {};
    const en = r.enrichment || {};
    const g = en.geo || {};
    const sh = en.shodan;
    const ab = en.abuse;
    const ban = x.ban;
    const kv = (k, v) => (v === undefined || v === null || v === "" ? "" : `<tr><td>${k}</td><td>${v}</td></tr>`);
    const yes = (v) => (v ? "yes" : "no");
    const ipq = encodeURIComponent(ip);
    const events = [...(x.events || [])].reverse();
    return `<div class="drawer">
      <div class="dh"><div><b class="big"><code>${esc(ip)}</code></b> ${flag(g.countryCode)}
        <div class="muted">${esc(en.rdns || "no reverse DNS")}${en.rdns_confirmed === false ? " (rDNS not forward-confirmed — may be spoofed)" : ""}</div></div>
        <button id="close">✕</button></div>

      <div class="actions">
        ${ban ? `<button data-unban="${esc(ip)}">Unban</button>` : `
          <button data-ban="${esc(ip)}" data-min="60">Ban 1h</button>
          <button data-ban="${esc(ip)}" data-min="1440">Ban 24h</button>
          <button data-ban="${esc(ip)}" data-min="10080">Ban 7d</button>
          <button class="danger" data-ban="${esc(ip)}" data-perm="1">Ban forever</button>`}
        <button data-enrich="${esc(ip)}">Refresh lookup</button>
      </div>
      ${ban ? `<div class="alert bad">⛔ Banned: ${esc(ban.reason)} — ${ban.expires ? "until " + esc(fmtTime(ban.expires)) : "permanently"}${ban.enforced ? "" : " — <b>NOT enforced</b> (see setup)"}</div>` : ""}
      ${x.whitelisted ? `<div class="alert ok">Whitelisted: ${esc(x.whitelisted)}</div>` : ""}
      ${r.likely_own_device ? `<div class="alert ok">This IP used a Home Assistant app user agent — it may be one of your own devices with an expired token.</div>` : ""}

      <div class="ct">Where</div>
      <table class="kv">
        ${kv("Location", esc([g.district, g.city, g.regionName, g.zip, g.country, g.continent].filter(Boolean).join(", ")))}
        ${kv("Coordinates", g.lat != null ? `<a target="_blank" rel="noreferrer" href="https://www.openstreetmap.org/?mlat=${esc(g.lat)}&mlon=${esc(g.lon)}#map=8/${esc(g.lat)}/${esc(g.lon)}">${esc(g.lat)}, ${esc(g.lon)} 🗺️</a> <span class="muted small">(city-level, approximate)</span>` : "")}
        ${kv("Timezone", esc(g.timezone))}
        ${kv("ISP", esc(g.isp))}${kv("Organisation", esc(g.org))}${kv("ASN", esc(g.as))}${kv("AS name", esc(g.asname))}
        ${g.country ? kv("Datacenter / hosting", yes(g.hosting)) + kv("Proxy / VPN / Tor", yes(g.proxy)) + kv("Mobile network", yes(g.mobile)) : ""}
      </table>

      ${ab ? `<div class="ct">AbuseIPDB</div><table class="kv">
        ${kv("Abuse confidence", `<b class="${ab.score >= 50 ? "badt" : ""}">${esc(ab.score)}%</b>`)}${kv("Reports (90d)", esc(ab.total_reports))}
        ${kv("Distinct reporters", esc(ab.distinct_reporters))}${kv("Last reported", esc(ab.last_reported))}
        ${kv("Usage type", esc(ab.usage_type))}${kv("Domain", esc(ab.domain))}${kv("Tor exit", yes(ab.is_tor))}</table>` : ""}

      ${sh ? `<div class="ct">Shodan InternetDB <span class="muted small">(what this attacker's own machine exposes)</span></div><table class="kv">
        ${kv("Open ports", esc((sh.ports || []).join(", ") || "none known"))}
        ${kv("Tags", (sh.tags || []).map((t) => `<span class="b">${esc(t)}</span>`).join(" "))}
        ${kv("Hostnames", esc((sh.hostnames || []).join(", ")))}
        ${kv("Software", esc((sh.cpes || []).slice(0, 8).join(", ")))}
        ${kv("Known CVEs", esc((sh.vulns || []).slice(0, 12).join(", ")))}</table>` : ""}

      <div class="ct">Activity</div>
      <table class="kv">
        ${kv("Failed attempts", esc(r.count))}${kv("First seen", esc(fmtTime(r.first_seen)))}${kv("Last seen", esc(fmtTime(r.last_seen)))}
        ${kv("Times banned", esc(r.ban_count))}${kv("Successful logins", esc(x.success?.count || 0))}
        ${kv("Methods", esc(top(r.methods).map(([k, n]) => `${k}×${n}`).join(", ")))}
      </table>
      <div class="ct">What they tried</div>
      ${top(r.categories).map(([k, n]) => `<div>${esc(k)} <span class="muted">×${esc(n)}</span></div>`).join("")}
      ${Object.keys(r.usernames || {}).length ? `<div class="ct">Usernames</div><div>${top(r.usernames, 50).map(([k, n]) => `<code class="chip">${esc(k)} ×${esc(n)}</code>`).join(" ")}</div>` : ""}
      ${Object.keys(r.passwords || {}).length ? `<div class="ct">Passwords</div><div>${top(r.passwords, 50).map(([k, n]) => `<code class="chip">${esc(k)} ×${esc(n)}</code>`).join(" ")}</div>` : ""}
      <div class="ct">User agents</div>${top(r.user_agents, 10).map(([k, n]) => `<div class="small"><code>${esc(k || "(none)")}</code> ×${esc(n)}</div>`).join("")}
      <div class="ct">URLs requested</div>${top(r.paths, 40).map(([k, n]) => `<div class="small"><code class="path">${esc(k)}</code> ×${esc(n)}</div>`).join("")}

      <div class="ct">Investigate elsewhere</div>
      <div class="links">
        <a target="_blank" rel="noreferrer" href="https://www.abuseipdb.com/check/${ipq}">AbuseIPDB</a>
        <a target="_blank" rel="noreferrer" href="https://www.shodan.io/host/${ipq}">Shodan</a>
        <a target="_blank" rel="noreferrer" href="https://viz.greynoise.io/ip/${ipq}">GreyNoise</a>
        <a target="_blank" rel="noreferrer" href="https://www.virustotal.com/gui/ip-address/${ipq}">VirusTotal</a>
        <a target="_blank" rel="noreferrer" href="https://ipinfo.io/${ipq}">ipinfo</a>
        <a target="_blank" rel="noreferrer" href="https://bgp.he.net/ip/${ipq}">BGP (HE)</a>
      </div>

      <div class="ct">Every request (${events.length})</div>
      ${events.map((e) => `<details class="ev"><summary><span class="sev ${sevClass(e.classification?.severity)}"></span>
          <span class="nowrap">${esc(fmtTime(e.ts))}</span> · <code>${esc(e.method)} ${esc(e.path.slice(0, 90))}</code>
          ${e.username ? ` · 👤 <code>${esc(e.username)}</code>` : ""}${e.password ? ` 🔑 <code>${esc(e.password)}</code>` : ""}${e.action ? ` · <b>${esc(e.action)}</b>` : ""}</summary>
        <table class="kv">
          ${kv("Category", esc(e.classification?.label) + ` (severity ${esc(e.classification?.severity)}/5)`)}
          ${kv("Why", esc((e.classification?.descriptions || []).join(" ")))}
          ${kv("Source", esc(e.source))}${kv("Full URL", `<code class="path">${esc(e.scheme)}://${esc(e.host)}${esc(e.path)}</code>`)}
          ${kv("HTTP", esc(e.http_version))}${kv("Referer", esc(e.referer))}${kv("X-Forwarded-For", esc(e.forwarded_for))}
          ${kv("Password", e.password_reason === "hidden_real_username" ? "<span class='badt'>hidden — this username exists in your HA</span>" : esc(e.password_reason))}
        </table>
        <div class="small muted">Headers</div>
        <table class="kv small">${Object.entries(e.headers || {}).map(([k, v]) => `<tr><td>${esc(k)}</td><td><code>${esc(v)}</code></td></tr>`).join("")}</table>
      </details>`).join("")}
    </div>`;
  }

  _render() {
    const d = this._data;
    const s = d?.summary;
    const tabs = [["attackers", "Attackers"], ["feed", "Live feed"], ["creds", "Credentials & stats"], ["bans", "Bans"], ["success", "Successful logins"]];
    let body = "";
    if (this._error) body = `<div class="alert bad">${esc(this._error)}</div>`;
    else if (!d) body = `<div class="muted">Loading…</div>`;
    else {
      body = `
        ${this._setupBanner(s)}
        ${this._tiles(s, d)}
        ${this._chart(d.events, d.now)}
        <div class="tabs">${tabs.map(([k, l]) => `<button class="tab ${this._tab === k ? "on" : ""}" data-tab="${k}">${l}</button>`).join("")}</div>
        <div class="tabbody">${
          this._tab === "attackers" ? this._attackers(d) :
          this._tab === "feed" ? this._feed(d) :
          this._tab === "creds" ? this._creds(d) :
          this._tab === "bans" ? this._bans(d) : this._success(d)}</div>`;
    }

    const focusFilter = this.shadowRoot.activeElement?.id === "filter";
    const caret = focusFilter ? this.shadowRoot.activeElement.selectionStart : null;
    const drawerScroll = this.shadowRoot.querySelector(".drawer")?.scrollTop;
    const openDetails = [...this.shadowRoot.querySelectorAll("details.ev")].map((el) => el.open);
    const manualVal = this.shadowRoot.getElementById("manualip")?.value;

    this.shadowRoot.innerHTML = `<style>${STYLE}</style>
      <div class="top">
        <ha-menu-button></ha-menu-button>
        <div class="title">🛡️ Login Analyser</div>
        <div class="muted small">${d ? "updated " + new Date().toLocaleTimeString() : ""}</div>
        <button id="refresh">Refresh</button>
      </div>
      <div class="layout ${this._selected ? "withdrawer" : ""}"><div class="main">${body}</div>${d ? this._drawer(d) : ""}</div>`;

    const mb = this.shadowRoot.querySelector("ha-menu-button");
    if (mb) { mb.hass = this._hass; mb.narrow = this._narrow; }

    if (focusFilter) {
      const el = this.shadowRoot.getElementById("filter");
      el.focus();
      el.setSelectionRange(caret, caret);
    }
    const dr = this.shadowRoot.querySelector(".drawer");
    if (dr && drawerScroll) dr.scrollTop = drawerScroll;
    this.shadowRoot.querySelectorAll("details.ev").forEach((el, i) => { if (openDetails[i]) el.open = true; });
    const mi = this.shadowRoot.getElementById("manualip");
    if (mi && manualVal) mi.value = manualVal;
    this._bind();
  }

  _bind() {
    const $ = (sel) => this.shadowRoot.querySelector(sel);
    const $$ = (sel) => this.shadowRoot.querySelectorAll(sel);
    $("#refresh")?.addEventListener("click", () => this._load());
    $("#enableblocking")?.addEventListener("click", () => this._enableBlocking());
    $("#promotehttp")?.addEventListener("click", () => this._promoteHttp());
    $$(".tab").forEach((b) => b.addEventListener("click", () => { this._tab = b.dataset.tab; this._render(); }));
    $("#filter")?.addEventListener("input", (e) => { this._filter = e.target.value; this._render(); });
    $("#sort")?.addEventListener("change", (e) => { this._sort = e.target.value; this._render(); });
    $$("tr[data-ip]").forEach((tr) => tr.addEventListener("click", (ev) => {
      if (ev.target.closest("button")) return;
      this._open(tr.dataset.ip);
    }));
    $("#close")?.addEventListener("click", () => { this._selected = null; this._detail = null; this._render(); });
    $$("[data-ban]").forEach((b) => b.addEventListener("click", () => {
      const perm = !!b.dataset.perm;
      if (perm && !confirm(`Permanently ban ${b.dataset.ban}?`)) return;
      this._action("ban", b.dataset.ban, perm ? { permanent: true, reason: "Manual permanent ban" } : { minutes: Number(b.dataset.min), reason: "Manual ban" });
    }));
    $$("[data-unban]").forEach((b) => b.addEventListener("click", (ev) => { ev.stopPropagation(); this._action("unban", b.dataset.unban); }));
    $$("[data-enrich]").forEach((b) => b.addEventListener("click", () => this._action("enrich", b.dataset.enrich)));
    const manual = (perm) => {
      const ip = $("#manualip").value.trim();
      if (!ip) return;
      this._action("ban", ip, perm ? { permanent: true, reason: "Manual permanent ban" } : { minutes: 1440, reason: "Manual ban" });
    };
    $("#manualban")?.addEventListener("click", () => manual(false));
    $("#manualperm")?.addEventListener("click", () => manual(true));
  }
}

const STYLE = `
:host { display:block; height:100%; background: var(--primary-background-color); color: var(--primary-text-color);
  font-family: var(--ha-font-family-body, Roboto, sans-serif); --bad:#d93025; --warn:#e8a200; --ok:#1e8e3e; }
.top { display:flex; align-items:center; gap:12px; height:56px; padding:0 12px; background: var(--app-header-background-color, var(--primary-color));
  color: var(--app-header-text-color, #fff); position:sticky; top:0; z-index:3; }
.top .title { font-size:20px; flex:1; }
.top .muted { color: inherit; opacity:.8; }
.top button { background: rgba(255,255,255,.15); color:inherit; border:1px solid rgba(255,255,255,.4); }
.layout { display:flex; height: calc(100% - 56px); }
.main { flex:1; overflow:auto; padding:16px; min-width:0; }
.drawer { width: 520px; max-width: 100%; overflow:auto; padding:16px; border-left:1px solid var(--divider-color);
  background: var(--card-background-color); box-sizing:border-box; }
@media (max-width: 1000px) { .layout.withdrawer .main { display:none; } .drawer { width:100%; border:0; } }
.dh { display:flex; justify-content:space-between; align-items:flex-start; gap:8px; margin-bottom:8px; }
.big { font-size:20px; }
.tiles { display:grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr)); gap:12px; margin-bottom:12px; }
.tile, .card { background: var(--card-background-color); border-radius: var(--ha-card-border-radius, 12px); padding:14px;
  box-shadow: var(--ha-card-box-shadow, none); border:1px solid var(--divider-color); }
.tile .n { font-size:28px; font-weight:500; }
.tile .l, .muted { color: var(--secondary-text-color); }
.small { font-size:12px; }
.ct { font-weight:500; margin:14px 0 6px; }
.card .ct { margin-top:0; }
.chart { display:flex; align-items:flex-end; gap:2px; height:90px; }
.bar { flex:1; height:100%; display:flex; align-items:flex-end; }
.bar > div { width:100%; background: var(--primary-color); border-radius:2px 2px 0 0; min-height:1px; }
.axis { display:flex; justify-content:space-between; font-size:11px; color: var(--secondary-text-color); margin-top:4px; }
.tabs { display:flex; gap:4px; margin:16px 0 8px; flex-wrap:wrap; }
.tab { background:none; border:none; border-bottom:2px solid transparent; border-radius:0; padding:8px 12px; color: var(--secondary-text-color); }
.tab.on { color: var(--primary-color); border-bottom-color: var(--primary-color); }
.toolbar { display:flex; gap:8px; margin-bottom:8px; flex-wrap:wrap; }
input, select { padding:8px; border-radius:8px; border:1px solid var(--divider-color); background: var(--card-background-color);
  color: var(--primary-text-color); font:inherit; }
#filter { flex:1; min-width:200px; }
button { padding:6px 12px; border-radius:8px; border:1px solid var(--divider-color); background: var(--card-background-color);
  color: var(--primary-text-color); cursor:pointer; font:inherit; }
button:hover { border-color: var(--primary-color); }
button.danger { border-color: var(--bad); color: var(--bad); }
.actions { display:flex; gap:6px; flex-wrap:wrap; margin: 8px 0; }
.tablewrap { overflow-x:auto; }
table.list { width:100%; border-collapse:collapse; background: var(--card-background-color); border-radius:12px; overflow:hidden; }
table.list th { text-align:left; font-weight:500; font-size:12px; color: var(--secondary-text-color); padding:8px; border-bottom:1px solid var(--divider-color); }
table.list td { padding:8px; border-bottom:1px solid var(--divider-color); vertical-align:top; font-size:14px; }
table.list tbody tr { cursor:pointer; }
table.list tbody tr:hover, tr.sel { background: var(--secondary-background-color); }
table.kv { border-collapse:collapse; width:100%; }
table.kv td { padding:3px 6px; vertical-align:top; border-bottom:1px solid var(--divider-color); word-break:break-word; }
table.kv td:first-child { color: var(--secondary-text-color); width:38%; }
.num { text-align:right; font-variant-numeric: tabular-nums; }
.nowrap { white-space:nowrap; }
code { font-family: var(--ha-font-family-code, monospace); font-size:12.5px; word-break: break-all; }
code.path { color: var(--primary-text-color); }
.ua { max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.chip { display:inline-block; background: var(--secondary-background-color); padding:2px 6px; border-radius:6px; margin:2px; }
.b { display:inline-block; font-size:11px; padding:1px 6px; border-radius:10px; margin:2px 2px 0 0; background: var(--secondary-background-color); }
.b.warn { background: color-mix(in srgb, var(--warn) 22%, transparent); }
.b.bad { background: color-mix(in srgb, var(--bad) 22%, transparent); }
.b.ok { background: color-mix(in srgb, var(--ok) 22%, transparent); }
.badt { color: var(--bad); }
.sev { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle; }
.sev1 { background: var(--secondary-text-color); } .sev3 { background: var(--warn); } .sev4 { background:#f26b00; } .sev5 { background: var(--bad); }
.alert { padding:10px 12px; border-radius:10px; margin:8px 0; background: color-mix(in srgb, var(--warn) 18%, transparent); }
.alert.bad { background: color-mix(in srgb, var(--bad) 16%, transparent); }
.alert.ok { background: color-mix(in srgb, var(--ok) 16%, transparent); }
.row { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:12px; }
.half { flex:1; min-width:260px; }
.links a { margin-right:10px; color: var(--primary-color); }
details.ev { border-bottom:1px solid var(--divider-color); padding:6px 0; }
details.ev summary { cursor:pointer; font-size:13px; }
details.ev table { margin-top:6px; }
`;

customElements.define("login-analyser-panel", LoginAnalyserPanel);
