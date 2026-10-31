const state = { session: null, csrf: "", view: "outlets", generation: 0, outletRequest: 0, pduRequest: 0, dsviewRequest: 0, nisRequest: 0, helpLanguageRequest: 0, dataBufferingRequest: 0, applianceLoggingRequest: 0, timeZoneRequest: 0, acmeRequest: 0, helpLanguageWritePending: false, dataBufferingWritePending: false, applianceLoggingWritePending: false, timeZoneWritePending: false, acmeMutationPending: false, acmeRenewalPending: false, acmeLoaded: false, acmeConfigured: false, acmeCaInstalled: false, tokenRequest: 0, sysinfoRequest: 0, memoryRequest: 0, flashRequest: 0, netdevRequest: 0, route4Request: 0, route6Request: 0, serialRequest: 0, outlets: [], pdus: [], tokens: [], inventoryRevision: "", pduInventoryRevision: "", helpLanguageRevision: "", dataBufferingRevision: "", applianceLoggingRevision: "", timeZoneRevision: "", acmeRevision: "", acmeRenewalTimer: 0 };
const $ = (id) => document.getElementById(id);
const powerActionsEnabled = true;
let transitionTail = Promise.resolve();
let loginPending = false;
let logoutPending = false;
let bootstrapPending = true;
let tokenIssuancePending = false;

const supportedLocales = ["en", "de"];
const locale = (navigator.languages || [navigator.language || "en"])
  .map((value) => String(value).toLowerCase().split("-")[0])
  .find((value) => supportedLocales.includes(value)) || "en";
const messages = {
  en: {
    "acme.nav": "ACME certificates", "acme.eyebrow": "Certificates", "acme.title": "ACME certificates",
    "acme.description": "Configure automatic certificate issuance from a fresh settings read.", "acme.reload": "Reload",
    "acme.enabled": "Enable ACME", "acme.enabledHelp": "Allow automatic certificate issuance and renewal.",
    "acme.directory": "Directory URL", "acme.dns": "DNS names", "acme.dnsHelp": "One DNS name per line; 1–16 unique names, at most 253 bytes each.",
    "acme.loadFirst": "Load the current setting before saving.", "acme.loading": "Loading current ACME setting…",
    "acme.loaded": "Current ACME setting loaded. Saving replaces all editable fields.",
    "acme.firstRun": "First run: upload a CA bundle, then save the operator-supplied configuration.",
    "acme.caReady": "Managed CA bundle installed. Save the configuration to finish first-run setup.",
    "acme.unavailable": "Current ACME setting unavailable. Reload before saving.", "acme.invalidResponse": "The ACME settings response was invalid.",
    "acme.save": "Save setting", "acme.saved": "ACME setting saved.", "acme.reloadRequired": "The setting may have changed. Reload before trying again.",
    "acme.invalidDns": "Enter 1–16 unique DNS names, one per line, using at most 253 bytes per name.",
    "acme.invalidDirectory": "Enter an HTTPS directory URL without spaces.", "acme.caTitle": "Certificate authority",
    "acme.caPath": "Current CA file:", "acme.caUpload": "Managed CA bundle", "acme.caHelp": "PEM certificate bundles only; maximum 64 KiB. Private keys are rejected.",
    "acme.upload": "Upload CA bundle", "acme.caEmpty": "Choose a non-empty CA bundle.", "acme.caLarge": "The CA bundle must not exceed 64 KiB.", "acme.caSaved": "Managed CA bundle installed.",
    "acme.renewalTitle": "Renewal", "acme.status": "Status:", "acme.renew": "Start renewal", "acme.started": "Renewal started; completion has not yet been confirmed.",
    "acme.refreshStopped": "Automatic status refresh stopped. Use Reload for the latest status.",
    "acme.wait": "Wait for the ACME operation to finish before signing out.",
    "acme.renewal.never_run": "Never run", "acme.renewal.starting": "Starting", "acme.renewal.running": "Running",
    "acme.renewal.succeeded": "Succeeded", "acme.renewal.failed": "Failed", "acme.renewal.durability_uncertain": "Durability uncertain", "acme.renewal.unknown": "Unknown"
  },
  de: {
    "acme.nav": "ACME-Zertifikate", "acme.eyebrow": "Zertifikate", "acme.title": "ACME-Zertifikate",
    "acme.description": "Automatische Zertifikatsausstellung anhand frisch geladener Einstellungen konfigurieren.", "acme.reload": "Neu laden",
    "acme.enabled": "ACME aktivieren", "acme.enabledHelp": "Automatische Zertifikatsausstellung und -erneuerung erlauben.",
    "acme.directory": "Verzeichnis-URL", "acme.dns": "DNS-Namen", "acme.dnsHelp": "Ein DNS-Name pro Zeile; 1–16 eindeutige Namen mit höchstens 253 Byte.",
    "acme.loadFirst": "Vor dem Speichern die aktuellen Einstellungen laden.", "acme.loading": "Aktuelle ACME-Einstellungen werden geladen…",
    "acme.loaded": "Aktuelle ACME-Einstellungen geladen. Speichern ersetzt alle bearbeitbaren Felder.",
    "acme.firstRun": "Ersteinrichtung: CA-Bündel hochladen und anschließend die vom Betreiber angegebenen Einstellungen speichern.",
    "acme.caReady": "Verwaltetes CA-Bündel installiert. Zum Abschluss der Ersteinrichtung die Konfiguration speichern.",
    "acme.unavailable": "Aktuelle ACME-Einstellungen nicht verfügbar. Vor dem Speichern neu laden.", "acme.invalidResponse": "Die Antwort mit den ACME-Einstellungen war ungültig.",
    "acme.save": "Einstellung speichern", "acme.saved": "ACME-Einstellung gespeichert.", "acme.reloadRequired": "Die Einstellung könnte sich geändert haben. Vor einem neuen Versuch neu laden.",
    "acme.invalidDns": "1–16 eindeutige DNS-Namen eingeben, einen pro Zeile und höchstens 253 Byte je Name.",
    "acme.invalidDirectory": "Eine HTTPS-Verzeichnis-URL ohne Leerzeichen eingeben.", "acme.caTitle": "Zertifizierungsstelle",
    "acme.caPath": "Aktuelle CA-Datei:", "acme.caUpload": "Verwaltetes CA-Bündel", "acme.caHelp": "Nur PEM-Zertifikatsbündel; höchstens 64 KiB. Private Schlüssel werden abgelehnt.",
    "acme.upload": "CA-Bündel hochladen", "acme.caEmpty": "Ein nicht leeres CA-Bündel auswählen.", "acme.caLarge": "Das CA-Bündel darf höchstens 64 KiB groß sein.", "acme.caSaved": "Verwaltetes CA-Bündel installiert.",
    "acme.renewalTitle": "Erneuerung", "acme.status": "Status:", "acme.renew": "Erneuerung starten", "acme.started": "Erneuerung gestartet; der Abschluss ist noch nicht bestätigt.",
    "acme.refreshStopped": "Automatische Statusaktualisierung beendet. Für den aktuellen Status neu laden.",
    "acme.wait": "Vor dem Abmelden das Ende des ACME-Vorgangs abwarten.",
    "acme.renewal.never_run": "Noch nie ausgeführt", "acme.renewal.starting": "Wird gestartet", "acme.renewal.running": "Läuft",
    "acme.renewal.succeeded": "Erfolgreich", "acme.renewal.failed": "Fehlgeschlagen", "acme.renewal.durability_uncertain": "Dauerhaftigkeit ungewiss", "acme.renewal.unknown": "Unbekannt"
  }
};
const t = (key) => messages[locale][key] || messages.en[key] || key;
document.documentElement.lang = locale;

function serializeTransition(operation) {
  const current = transitionTail.then(operation, operation);
  transitionTail = current.catch(() => {});
  return current;
}

const menu = [
  ["units.topology", "Access"], ["units.overview", "System Tools"],
  ["units.powermanagement", "Power Management"], ["units.powermanagement.pdu_management", "PDUs"],
  ["units.powermanagement.powerprofile_login", "Settings"], ["units.powermanagement.outlet_groups", "Outlet Groups"],
  ["units.powermanagement.data_logging", "Data Logging"], ["units.applianceSettings", "System"],
  ["units.applianceSettings.security", "Security"], ["units.applianceSettings.security.SecurityProfileNav", "Security Profile"],
  ["units.applianceSettings.security.SecurityDSView", "DSView"], ["units.applianceSettings.date_and_time", "Date and Time"],
  ["units.applianceSettings.date_and_time.date_time", "Date and Time"], ["units.applianceSettings.date_and_time.time_zone", "Time Zone"],
  ["units.applianceSettings.help", "Help and Language"], ["units.applianceSettings.bootconfiguration", "Boot Configuration"],
  ["units.applianceSettings.information", "Information"], ["units.applianceSettings.usage", "Usage"],
  ["units.applianceSettings.usage.memory", "Memory"], ["units.applianceSettings.usage.flashUsage", "Flash Usage"],
  ["units.network", "Network"], ["units.network.networkSettings", "Settings"], ["units.network.devices", "Devices"],
  ["units.network.ipv4_st_routes", "IPv4 Static Routes"], ["units.network.ipv6_st_routes", "IPv6 Static Routes"],
  ["units.network.hosts", "Hosts"], ["units.network.firewall", "Firewall"],
  ["units.network.firewall.filter4Table", "IPv4 Filter Table"], ["units.network.firewall.filter6Table", "IPv6 Filter Table"],
  ["units.network.SNMP", "SNMP"], ["units.authentication", "Authentication"],
  ["units.authentication.unit_authentication", "Appliance Authentication"], ["units.authentication.authenticationservers", "Authentication Servers"],
  ["units.authentication.authenticationservers.radius", "RADIUS"], ["units.authentication.authenticationservers.Tacacsplus", "TACACS+"],
  ["units.authentication.authenticationservers.ldap_ad", "LDAP(S) / AD"], ["units.authentication.authenticationservers.kerberos", "Kerberos"],
  ["units.authentication.authenticationservers.nis", "NIS"], ["units.authentication.authenticationservers.dsviewsrv", "DSView"],
  ["units.users", "Users"], ["units.users.local_accounts", "Local Accounts"],
  ["units.users.local_accounts.user_names", "User Names"], ["units.users.local_accounts.password_rules", "Password Rules"],
  ["units.users.authorization", "Authorization"], ["units.users.authorization.authorgroups", "Groups"],
  ["units.event_notification", "Events and Logs"], ["units.event_notification.events", "Event List"],
  ["units.event_notification.settings", "Event Destinations"], ["units.event_notification.global_settings_databuffering", "Data Buffering"],
  ["units.event_notification.sessions", "Appliance Logging"], ["units.activeSessions", "Active Sessions"],
  ["units.monitoring", "Monitoring"], ["units.monitoring.networkmon", "Network"],
  ["units.monitoring.networkmon.monitoringDevice", "Devices"], ["units.monitoring.networkmon.monitoringIpv4RouteTable", "IPv4 Routing Table"],
  ["units.monitoring.networkmon.monitoringIpv6RouteTable", "IPv6 Routing Table"], ["units.monitoring.serialstatistics", "Serial Ports"],
  ["units.change_password", "Change Password"]
];

function apiErrorMessage(payload, fallback) {
  return payload && typeof payload.message === "string" ? payload.message : fallback;
}

async function api(path, options = {}) {
  const generation = state.generation;
  const headers = new Headers(options.headers || {});
  const method = options.method || "GET";
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (method !== "GET" && options.csrf !== false && state.csrf) headers.set("X-CSRF-Token", state.csrf);
  const response = await fetch(path, { ...options, method, headers, cache: "no-store", credentials: "same-origin" });
  let payload = null;
  if (response.status !== 204) { try { payload = await response.json(); } catch { /* handled below */ } }
  if (generation !== state.generation && !options.deliverAfterSessionChange) throw new Error("Session changed.");
  if (response.status === 401 && path !== "/api/v1/session") {
    disconnectLocal("Your PM3000 session has expired.");
    throw new Error("Session expired.");
  }
  if (!response.ok || (options.expectedStatus && response.status !== options.expectedStatus)) {
    const error = new Error(apiErrorMessage(payload, `Request failed (${response.status}).`));
    error.code = payload && typeof payload.code === "string" ? payload.code : "";
    error.status = response.status;
    throw error;
  }
  return payload;
}

function setText(id, value) { $(id).textContent = String(value); }
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function toast(message) {
  const node = $("toast"); node.textContent = message; node.hidden = false;
  window.clearTimeout(toast.timer); toast.timer = window.setTimeout(() => { node.hidden = true; }, 2800);
}
function clearOneTimeSecret() { setText("new-token-secret", ""); setText("copy-state", ""); }

function setLoginDisabled(disabled) {
  $("username-input").disabled = disabled; $("password-input").disabled = disabled;
  $("connect-form").querySelector('button[type="submit"]').disabled = disabled;
}

function disconnectLocal(message = "", enableLogin = true) {
  state.generation += 1; state.outletRequest += 1; state.pduRequest += 1; state.dsviewRequest += 1; state.nisRequest += 1; state.helpLanguageRequest += 1; state.dataBufferingRequest += 1; state.applianceLoggingRequest += 1; state.timeZoneRequest += 1; state.acmeRequest += 1; state.tokenRequest += 1; state.sysinfoRequest += 1; state.memoryRequest += 1; state.flashRequest += 1; state.netdevRequest += 1; state.route4Request += 1; state.route6Request += 1; state.serialRequest += 1;
  state.session = null; state.csrf = ""; state.outlets = []; state.pdus = []; state.tokens = []; state.inventoryRevision = ""; state.pduInventoryRevision = ""; state.helpLanguageRevision = ""; state.dataBufferingRevision = ""; state.applianceLoggingRevision = ""; state.timeZoneRevision = "";
  if ($("create-token-dialog").open) $("create-token-dialog").close();
  if ($("token-secret-dialog").open) $("token-secret-dialog").close();
  clearOneTimeSecret(); clear($("outlet-grid")); clear($("pdu-grid")); clear($("token-rows")); clear($("navigation"));
  setHelpLanguageLoaded(false); setDataBufferingLoaded(false); setApplianceLoggingLoaded(false); setTimeZoneLoaded(false); clearAcmeState();
  $("old-password").value = ""; $("new-password").value = ""; $("confirm-password").value = ""; $("password-change-error").textContent = "";
  $("authenticated").hidden = true; $("login-view").hidden = false; $("disconnect").hidden = true;
  setText("signed-in-user", ""); $("password-input").value = ""; $("login-error").textContent = message;
  const allowLogin = enableLogin && !tokenIssuancePending;
  setLoginDisabled(!allowLogin);
  if (allowLogin) $("username-input").focus();
}

async function logoutTransition() {
  state.generation += 1;
  const csrf = state.csrf;
  const request = fetch("/api/v1/session", {
    method: "DELETE", headers: { "X-CSRF-Token": csrf }, cache: "no-store", credentials: "same-origin"
  });
  disconnectLocal("", false);
  try {
    const response = await request;
    let payload = null;
    if (response.status !== 204) { try { payload = await response.json(); } catch { /* handled below */ } }
    if (!response.ok) throw new Error(apiErrorMessage(payload, `Request failed (${response.status}).`));
    state.generation += 1;
  } catch (error) { toast(error.message); }
  finally { logoutPending = false; setLoginDisabled(false); $("username-input").focus(); }
}

function showAuthenticated(session) {
  state.session = session; state.csrf = session.csrfToken;
  $("login-view").hidden = true; $("authenticated").hidden = false; $("disconnect").hidden = false;
  setText("signed-in-user", session.identity.username); renderNavigation(); switchView("outlets"); loadOutlets();
}

function navigationView(path) {
  return path === "units.change_password" ? "password" :
    path === "units.authentication.authenticationservers.nis" ? "nis" :
    path === "units.applianceSettings.security.SecurityDSView" ? "dsview" :
    path === "units.applianceSettings.help" ? "help-language" :
    path === "units.event_notification.global_settings_databuffering" ? "data-buffering" :
    path === "units.event_notification.sessions" ? "appliance-logging" :
    path === "units.applianceSettings.date_and_time.time_zone" ? "time-zone" :
    path === "units.powermanagement.pdu_management" ? "pdus" :
    path === "units.applianceSettings.information" ? "sysinfo" :
    path === "units.applianceSettings.usage.memory" ? "memory" :
    path === "units.applianceSettings.usage.flashUsage" ? "flash" :
    path === "units.monitoring.networkmon.monitoringDevice" ? "netdev" :
    path === "units.monitoring.networkmon.monitoringIpv4RouteTable" ? "route4" :
    path === "units.monitoring.networkmon.monitoringIpv6RouteTable" ? "route6" :
    path === "units.monitoring.serialstatistics" ? "serial" :
    path === "units.topology" ? "outlets" : "legacy";
}

function toggleNavigationGroup(button, children, expanded = null) {
  const open = expanded === null ? button.getAttribute("aria-expanded") !== "true" : expanded;
  button.setAttribute("aria-expanded", open ? "true" : "false");
  children.hidden = !open;
}

function expandNavigationPath(path) {
  if (!path) return;
  for (const button of document.querySelectorAll('.nav-item[aria-expanded][data-path]')) {
    if (path.startsWith(`${button.dataset.path}.`)) {
      const children = document.getElementById(button.getAttribute("aria-controls"));
      if (children) toggleNavigationGroup(button, children, true);
    }
  }
}

function renderNavigation() {
  const node = $("navigation"); clear(node);
  const allowed = new Set(state.session.navigation.paths || []);
  const entries = menu.map(([path, text]) => ({ path, text })).filter((entry) =>
    allowed.has(entry.path) || [...allowed].some((path) => path.startsWith(`${entry.path}.`)));
  const byPath = new Map(entries.map((entry) => [entry.path, { ...entry, children: [] }]));
  const roots = [];
  for (const entry of byPath.values()) {
    const parent = [...byPath.values()]
      .filter((candidate) => entry.path.startsWith(`${candidate.path}.`))
      .sort((left, right) => right.path.length - left.path.length)[0];
    if (parent) parent.children.push(entry); else roots.push(entry);
  }
  const label = document.createElement("p"); label.className = "nav-label"; label.textContent = "Authorized features"; node.appendChild(label);
  const tree = document.createElement("div"); tree.className = "nav-tree"; node.appendChild(tree);
  let groupSequence = 0;
  const appendEntry = (entry, container, depth) => {
    const wrapper = document.createElement("div"); wrapper.className = "nav-node";
    const button = document.createElement("button"); button.type = "button"; button.className = "nav-item legacy-nav";
    button.style.setProperty("--nav-depth", String(Math.min(depth, 3)));
    button.dataset.path = entry.path; button.textContent = entry.text;
    if (entry.children.length) {
      const children = document.createElement("div"); children.className = "nav-children"; children.hidden = true;
      const childId = `nav-group-${++groupSequence}`; children.id = childId;
      button.setAttribute("aria-expanded", "false"); button.setAttribute("aria-controls", childId);
      button.addEventListener("click", () => toggleNavigationGroup(button, children));
      wrapper.append(button, children);
      for (const child of entry.children) appendEntry(child, children, depth + 1);
    } else {
      button.addEventListener("click", () => switchView(navigationView(entry.path), entry.path, entry.text));
      wrapper.appendChild(button);
    }
    container.appendChild(wrapper);
  };
  for (const entry of roots) appendEntry(entry, tree, 0);
  if (state.session.navigation.canManageTokens) {
    const heading = document.createElement("p"); heading.className = "nav-label"; heading.textContent = "REST API"; node.appendChild(heading);
    const button = document.createElement("button"); button.type = "button"; button.className = "nav-item"; button.dataset.view = "tokens"; button.textContent = "Bearer tokens";
    button.addEventListener("click", () => switchView("tokens")); node.appendChild(button);
  }
  if (state.session.navigation.canManageAcme) {
    const heading = document.createElement("p"); heading.className = "nav-label"; heading.textContent = t("acme.eyebrow"); node.appendChild(heading);
    const button = document.createElement("button"); button.type = "button"; button.className = "nav-item"; button.dataset.view = "acme"; button.textContent = t("acme.nav");
    button.addEventListener("click", () => switchView("acme")); node.appendChild(button);
  }
}

function switchView(view, path = "", label = "") {
  if (view === "acme" && (!state.session || !state.session.navigation.canManageAcme)) view = "outlets";
  state.view = view;
  $("outlets-view").hidden = view !== "outlets"; $("pdus-view").hidden = view !== "pdus"; $("tokens-view").hidden = view !== "tokens"; $("nis-view").hidden = view !== "nis"; $("dsview-view").hidden = view !== "dsview"; $("help-language-view").hidden = view !== "help-language"; $("data-buffering-view").hidden = view !== "data-buffering"; $("appliance-logging-view").hidden = view !== "appliance-logging"; $("time-zone-view").hidden = view !== "time-zone"; $("acme-view").hidden = view !== "acme"; $("password-change-view").hidden = view !== "password"; $("sysinfo-view").hidden = view !== "sysinfo"; $("memory-view").hidden = view !== "memory"; $("flash-view").hidden = view !== "flash"; $("netdev-view").hidden = view !== "netdev"; $("route4-view").hidden = view !== "route4"; $("route6-view").hidden = view !== "route6"; $("serial-view").hidden = view !== "serial"; $("legacy-view").hidden = view !== "legacy";
  for (const button of document.querySelectorAll(".nav-item")) button.removeAttribute("aria-current");
  let active = view === "tokens" ? document.querySelector('[data-view="tokens"]') : view === "acme" ? document.querySelector('[data-view="acme"]') : null;
  if (!active && path) active = [...document.querySelectorAll("[data-path]")].find((button) => button.dataset.path === path);
  if (!active && view === "outlets") active = [...document.querySelectorAll("[data-path]")].find((button) => button.dataset.path === "units.topology");
  if (path) expandNavigationPath(path);
  if (active) active.setAttribute("aria-current", "page");
  if (view === "tokens") loadTokens();
  if (view === "pdus") loadPdus();
  if (view === "nis") loadNisSetting();
  if (view === "dsview") loadDsviewSetting();
  if (view === "help-language") loadHelpLanguageSetting();
  if (view === "data-buffering") loadDataBufferingSetting();
  if (view === "appliance-logging") loadApplianceLoggingSetting();
  if (view === "time-zone") loadTimeZoneSetting();
  if (view === "acme") loadAcmeSetting();
  if (view === "sysinfo") loadSysinfo();
  if (view === "memory") loadMemory();
  if (view === "flash") loadFlash();
  if (view === "netdev") loadNetdev();
  if (view === "route4") loadRoute4();
  if (view === "route6") loadRoute6();
  if (view === "serial") loadSerial();
  if (view === "legacy") { setText("legacy-title", label); setText("legacy-path", path); }
}

function statusLabel(value) { return value === "on" ? "On" : value === "off" ? "Off" : "Unknown"; }

function outletActionDisabled(outlet, action) {
  if (outlet.state === "off" && (action === "off" || action === "cycle")) return true;
  if (outlet.state === "on" && action === "on") return true;
  if (outlet.state !== "on" && outlet.state !== "off") return true;
  return false;
}

function actionButton(outlet, action) {
  const button = document.createElement("button"); button.type = "button"; button.className = `small-button action-${action}${action === "off" ? " danger" : ""}`; button.textContent = action === "cycle" ? "Cycle" : action === "on" ? "Switch on" : "Switch off";
  button.disabled = outletActionDisabled(outlet, action);
  button.addEventListener("click", async () => {
    if (!window.confirm(`${button.textContent} ${outlet.name || `outlet ${outlet.position}`}?`)) return;
    button.disabled = true;
    try {
      await api(`/api/v1/outlets/${encodeURIComponent(outlet.id)}/actions`, { method: "POST", body: JSON.stringify({ action, inventoryRevision: state.inventoryRevision }) });
      toast(`Outlet action ${action} accepted.`); await loadOutlets();
    } catch (error) { toast(error.message); button.disabled = false; }
  });
  return button;
}

function renderOutlets(collection) {
  const outlets = Array.isArray(collection.outlets) ? collection.outlets : [];
  state.outlets = outlets; state.inventoryRevision = collection.inventoryRevision || "";
  const grid = $("outlet-grid"); clear(grid);
  for (const outlet of outlets) {
    const article = document.createElement("article"); article.className = `outlet-card state-${outlet.state}`;
    const header = document.createElement("div"); header.className = "outlet-card-header";
    const position = document.createElement("span"); position.className = "outlet-position"; position.textContent = `OUTLET ${String(outlet.position).padStart(2, "0")}`;
    const status = document.createElement("span"); status.className = `status-chip${outlet.state === "off" ? " off" : outlet.state === "unknown" ? " unknown" : ""}`; status.textContent = statusLabel(outlet.state);
    const title = document.createElement("h3"); title.textContent = outlet.name || `Outlet ${outlet.position}`;
    const identifier = document.createElement("p"); identifier.textContent = outlet.id;
    header.append(position, status); article.append(header, title, identifier);
    if (powerActionsEnabled && state.session.navigation.canControlPower) { const actions = document.createElement("div"); actions.className = "row-actions"; actions.append(actionButton(outlet, "on"), actionButton(outlet, "off"), actionButton(outlet, "cycle")); article.appendChild(actions); }
    grid.appendChild(article);
  }
  setText("total-count", outlets.length); setText("on-count", outlets.filter((item) => item.state === "on").length); setText("unknown-count", outlets.filter((item) => item.state === "unknown").length);
  setText("inventory-revision", `Inventory revision ${state.inventoryRevision || "—"}`);
  setText("updated-at", `Updated ${new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`);
  $("outlet-empty").hidden = outlets.length !== 0;
}

async function loadOutlets() {
  const request = ++state.outletRequest;
  $("refresh-outlets").disabled = true;
  try { const payload = await api("/api/v1/outlets"); if (request === state.outletRequest) renderOutlets(payload); }
  catch (error) { if (request === state.outletRequest && state.session) toast(error.message); }
  finally { if (request === state.outletRequest) $("refresh-outlets").disabled = false; }
}

function pduActionButton(pdu, action) {
  const button = document.createElement("button"); button.type = "button"; button.className = `small-button action-${action}${action === "off" ? " danger" : ""}`; button.textContent = action === "cycle" ? "Cycle" : action === "on" ? "Switch on" : "Switch off";
  button.addEventListener("click", async () => {
    if (!window.confirm(`${button.textContent} ${pdu.name || `PDU ${pdu.position}`}?`)) return;
    button.disabled = true;
    try {
      await api(`/api/v1/pdus/${encodeURIComponent(pdu.id)}/actions`, { method: "POST", body: JSON.stringify({ action, inventoryRevision: state.pduInventoryRevision }) });
      toast(`PDU action ${action} accepted.`); await loadPdus();
    } catch (error) { toast(error.message); button.disabled = false; }
  });
  return button;
}

function renderPdus(collection) {
  const pdus = Array.isArray(collection.pdus) ? collection.pdus : [];
  state.pdus = pdus; state.pduInventoryRevision = collection.inventoryRevision || "";
  const grid = $("pdu-grid"); clear(grid);
  for (const pdu of pdus) {
    const article = document.createElement("article"); article.className = "outlet-card";
    const header = document.createElement("div"); header.className = "outlet-card-header";
    const position = document.createElement("span"); position.className = "outlet-position"; position.textContent = `PDU ${String(pdu.position).padStart(2, "0")}`;
    const alarm = document.createElement("span"); alarm.className = `status-chip${String(pdu.alarm).toLowerCase() === "normal" ? "" : " unknown"}`; alarm.textContent = String(pdu.alarm || "Unknown");
    const title = document.createElement("h3"); title.textContent = pdu.name || `${pdu.vendor} ${pdu.model}`;
    const model = document.createElement("p"); model.textContent = `${pdu.vendor} ${pdu.model}`;
    const load = document.createElement("p"); load.textContent = `${pdu.outletsOn}/${pdu.outletCount} outlets on · ${pdu.currentAmps} A · ${pdu.powerWatts} W`;
    header.append(position, alarm); article.append(header, title, model, load);
    const available = Array.isArray(pdu.availableActions) ? pdu.availableActions : [];
    if (powerActionsEnabled && state.session.navigation.canControlPower && available.length !== 0) {
      const actions = document.createElement("div"); actions.className = "row-actions";
      for (const action of ["on", "off", "cycle"]) if (available.includes(action)) actions.appendChild(pduActionButton(pdu, action));
      article.appendChild(actions);
    }
    grid.appendChild(article);
  }
  setText("pdu-inventory-revision", `Inventory revision ${state.pduInventoryRevision || "—"}`);
  setText("pdu-updated-at", `Updated ${new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`);
  $("pdu-empty").hidden = pdus.length !== 0;
}

async function loadPdus() {
  const request = ++state.pduRequest;
  $("refresh-pdus").disabled = true;
  try { const payload = await api("/api/v1/pdus"); if (request === state.pduRequest) renderPdus(payload); }
  catch (error) { if (request === state.pduRequest && state.session) toast(error.message); }
  finally { if (request === state.pduRequest) $("refresh-pdus").disabled = false; }
}

function tokenActionButton(record, action) {
  const button = document.createElement("button"); button.type = "button"; button.className = `small-button${action === "delete" ? " danger" : ""}`; button.textContent = action === "delete" ? "Delete" : record.enabled ? "Disable" : "Enable";
  button.addEventListener("click", async () => {
    if (action === "delete" && !window.confirm(`Delete token ${record.label}?`)) return;
    button.disabled = true;
    try { const method = action === "delete" ? "DELETE" : "POST"; const operation = action === "delete" ? "" : `/${record.enabled ? "disable" : "enable"}`; await api(`/api/v1/tokens/${encodeURIComponent(record.id)}${operation}`, { method }); toast(action === "delete" ? "Token deleted." : `Token ${record.enabled ? "disabled" : "enabled"}.`); await loadTokens(); }
    catch (error) { toast(error.message); button.disabled = false; }
  });
  return button;
}

function renderTokens(payload) {
  const records = Array.isArray(payload.tokens) ? payload.tokens : []; state.tokens = records; const body = $("token-rows"); clear(body);
  for (const record of records) {
    const row = document.createElement("tr"); const label = document.createElement("td"); label.textContent = record.label;
    const scopeCell = document.createElement("td"); const scope = document.createElement("span"); scope.className = "scope-badge"; scope.textContent = record.scope; scopeCell.appendChild(scope);
    const access = document.createElement("td"); access.textContent = record.outlets === null ? "All outlets" : `${record.outlets.length} selected`;
    const statusCell = document.createElement("td"); const enabled = document.createElement("span"); enabled.className = `enabled-badge${record.enabled ? "" : " disabled"}`; enabled.textContent = record.enabled ? "Enabled" : "Disabled"; statusCell.appendChild(enabled);
    const id = document.createElement("td"); id.textContent = record.id; const actions = document.createElement("td"); const group = document.createElement("div"); group.className = "row-actions"; group.append(tokenActionButton(record, "toggle"), tokenActionButton(record, "delete")); actions.appendChild(group);
    row.append(label, scopeCell, access, statusCell, id, actions); body.appendChild(row);
  }
  $("token-empty").hidden = records.length !== 0;
}

async function loadTokens() {
  const request = ++state.tokenRequest; $("refresh-tokens").disabled = true;
  try { const payload = await api("/api/v1/tokens"); if (request === state.tokenRequest) renderTokens(payload); }
  catch (error) { if (request === state.tokenRequest) toast(error.message); }
  finally { if (request === state.tokenRequest) $("refresh-tokens").disabled = false; }
}

async function loadNisSetting() {
  const request = ++state.nisRequest;
  const button = $("save-nis"); let loaded = false;
  button.disabled = true; $("nis-error").textContent = "";
  try {
    const payload = await api("/api/v1/settings/authentication/nis");
    if (request === state.nisRequest) {
      $("nis-domain").value = payload.domainName;
      $("nis-address").value = payload.address;
      loaded = true;
    }
  } catch (error) {
    if (request === state.nisRequest) {
      $("nis-domain").value = ""; $("nis-address").value = "";
      if (state.session) $("nis-error").textContent = error.message;
    }
  } finally {
    if (request === state.nisRequest) button.disabled = !loaded;
  }
}

$("nis-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("save-nis"); if (button.disabled) return;
  button.disabled = true; $("nis-error").textContent = "";
  try {
    await api("/api/v1/settings/authentication/nis", { method: "PUT", body: JSON.stringify({ domainName: $("nis-domain").value, address: $("nis-address").value }) });
    toast("NIS setting saved."); await loadNisSetting();
  } catch (error) {
    const message = error.message;
    await loadNisSetting();
    $("nis-error").textContent = message;
  }
});

async function loadDsviewSetting() {
  const request = ++state.dsviewRequest;
  const button = $("save-dsview"); let loaded = false;
  button.disabled = true; $("dsview-error").textContent = "";
  try {
    const payload = await api("/api/v1/settings/security/dsview");
    if (request === state.dsviewRequest) {
      $("allow-dsview").checked = payload.allowDSView === true;
      loaded = true;
    }
  } catch (error) {
    if (request === state.dsviewRequest) {
      $("allow-dsview").checked = false;
      if (state.session) $("dsview-error").textContent = error.message;
    }
  } finally {
    if (request === state.dsviewRequest) button.disabled = !loaded;
  }
}

$("dsview-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("save-dsview"); if (button.disabled) return;
  button.disabled = true; $("dsview-error").textContent = "";
  try {
    await api("/api/v1/settings/security/dsview", { method: "PUT", body: JSON.stringify({ allowDSView: $("allow-dsview").checked }) });
    toast("DSView setting saved."); await loadDsviewSetting();
  } catch (error) {
    const message = error.message;
    await loadDsviewSetting();
    $("dsview-error").textContent = message;
  }
});

const bufferingFacilities = ["LOG_LOCAL0", "LOG_LOCAL1", "LOG_LOCAL2", "LOG_LOCAL3", "LOG_LOCAL4", "LOG_LOCAL5"];
const strongRevision = (value) => typeof value === "string" && /^"[0-9a-f]{64}"$/u.test(value);

function setHelpLanguageLoaded(loaded) {
  const disabled = !loaded || state.helpLanguageWritePending;
  $("help-language").disabled = disabled; $("help-url").disabled = disabled; $("save-help-language").disabled = disabled;
  if (!loaded) {
    state.helpLanguageRevision = ""; $("help-language").value = ""; $("help-url").value = ""; clear($("help-language"));
  }
}

async function loadHelpLanguageSetting(writeReadback = false) {
  if (state.helpLanguageWritePending && !writeReadback) return;
  const request = ++state.helpLanguageRequest;
  setHelpLanguageLoaded(false); $("help-language-error").textContent = ""; setText("help-language-status", "Loading current setting…");
  try {
    const payload = await api("/api/v1/settings/help-language");
    if (request !== state.helpLanguageRequest) return;
    if (!strongRevision(payload.revision) || typeof payload.applianceLanguage !== "string" || typeof payload.url !== "string" || !Array.isArray(payload.allowedLanguages) || !payload.allowedLanguages.every((language) => typeof language === "string") || !payload.allowedLanguages.includes(payload.applianceLanguage)) throw new Error("The settings response was invalid.");
    for (const language of payload.allowedLanguages) {
      const option = document.createElement("option"); option.value = language; option.textContent = language; $("help-language").appendChild(option);
    }
    $("help-language").value = payload.applianceLanguage; $("help-url").value = payload.url;
    state.helpLanguageRevision = payload.revision;
    setHelpLanguageLoaded(true); setText("help-language-status", "Current setting loaded. Saving replaces both fields.");
  } catch (error) {
    if (request === state.helpLanguageRequest) {
      setHelpLanguageLoaded(false); setText("help-language-status", "Current setting unavailable. Reload before saving.");
      if (state.session) $("help-language-error").textContent = error.message;
    }
  }
}

$("help-language-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.helpLanguageWritePending || $("save-help-language").disabled || !state.helpLanguageRevision) return;
  const generation = state.generation;
  state.helpLanguageWritePending = true; $("reload-help-language").disabled = true; $("disconnect").disabled = true;
  $("save-help-language").disabled = true; $("help-language-error").textContent = "";
  let message = "";
  try {
    await api("/api/v1/settings/help-language", { method: "PUT", headers: { "If-Match": state.helpLanguageRevision }, body: JSON.stringify({ applianceLanguage: $("help-language").value, url: $("help-url").value }) });
    toast("Help and Language setting saved.");
  } catch (error) { message = error.message; }
  finally {
    await loadHelpLanguageSetting(true);
    state.helpLanguageWritePending = false; $("reload-help-language").disabled = false;
    setHelpLanguageLoaded(Boolean(state.helpLanguageRevision));
    if (!state.dataBufferingWritePending && !state.applianceLoggingWritePending && !state.timeZoneWritePending && !tokenIssuancePending && !logoutPending && state.session) $("disconnect").disabled = false;
    if (message && state.session && generation === state.generation) $("help-language-error").textContent = message;
  }
});

function setDataBufferingLoaded(loaded) {
  const disabled = !loaded || state.dataBufferingWritePending;
  for (const id of ["buffer-local-size", "buffer-local-segments", "buffer-nfs-server", "buffer-nfs-path", "buffer-nfs-size", "buffer-nfs-segments", "buffer-syslog-facility", "save-data-buffering"]) $(id).disabled = disabled;
  if (!loaded) {
    state.dataBufferingRevision = "";
    for (const id of ["buffer-local-size", "buffer-local-segments", "buffer-nfs-server", "buffer-nfs-path", "buffer-nfs-size", "buffer-nfs-segments"]) $(id).value = "";
    clear($("buffer-syslog-facility"));
  }
}

async function loadDataBufferingSetting(writeReadback = false) {
  if (state.dataBufferingWritePending && !writeReadback) return;
  const request = ++state.dataBufferingRequest;
  setDataBufferingLoaded(false); $("data-buffering-error").textContent = ""; setText("data-buffering-status", "Loading current setting…");
  try {
    const payload = await api("/api/v1/settings/data-buffering");
    if (request !== state.dataBufferingRequest) return;
    const integerFields = ["localSize", "localSegments", "nfsSize", "nfsSegments"];
    if (!strongRevision(payload.revision) || !integerFields.every((field) => Number.isInteger(payload[field])) || typeof payload.nfsServer !== "string" || typeof payload.nfsPath !== "string" || !bufferingFacilities.includes(payload.syslogFacility)) throw new Error("The settings response was invalid.");
    $("buffer-local-size").value = String(payload.localSize); $("buffer-local-segments").value = String(payload.localSegments);
    $("buffer-nfs-server").value = payload.nfsServer; $("buffer-nfs-path").value = payload.nfsPath;
    $("buffer-nfs-size").value = String(payload.nfsSize); $("buffer-nfs-segments").value = String(payload.nfsSegments);
    for (const facility of bufferingFacilities) {
      const option = document.createElement("option"); option.value = facility; option.textContent = facility; $("buffer-syslog-facility").appendChild(option);
    }
    $("buffer-syslog-facility").value = payload.syslogFacility;
    state.dataBufferingRevision = payload.revision;
    setDataBufferingLoaded(true); setText("data-buffering-status", "Current setting loaded. Saving replaces all seven fields.");
  } catch (error) {
    if (request === state.dataBufferingRequest) {
      setDataBufferingLoaded(false); setText("data-buffering-status", "Current setting unavailable. Reload before saving.");
      if (state.session) $("data-buffering-error").textContent = error.message;
    }
  }
}

$("data-buffering-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.dataBufferingWritePending || $("save-data-buffering").disabled || !state.dataBufferingRevision) return;
  const generation = state.generation;
  state.dataBufferingWritePending = true; $("reload-data-buffering").disabled = true; $("disconnect").disabled = true;
  $("save-data-buffering").disabled = true; $("data-buffering-error").textContent = "";
  const replacement = {
    localSize: $("buffer-local-size").valueAsNumber, localSegments: $("buffer-local-segments").valueAsNumber,
    nfsServer: $("buffer-nfs-server").value, nfsPath: $("buffer-nfs-path").value,
    nfsSize: $("buffer-nfs-size").valueAsNumber, nfsSegments: $("buffer-nfs-segments").valueAsNumber,
    syslogFacility: $("buffer-syslog-facility").value
  };
  let message = "";
  try {
    await api("/api/v1/settings/data-buffering", { method: "PUT", headers: { "If-Match": state.dataBufferingRevision }, body: JSON.stringify(replacement) });
    toast("Data Buffering setting saved.");
  } catch (error) { message = error.message; }
  finally {
    await loadDataBufferingSetting(true);
    state.dataBufferingWritePending = false; $("reload-data-buffering").disabled = false;
    setDataBufferingLoaded(Boolean(state.dataBufferingRevision));
    if (!state.helpLanguageWritePending && !state.applianceLoggingWritePending && !state.timeZoneWritePending && !tokenIssuancePending && !logoutPending && state.session) $("disconnect").disabled = false;
    if (message && state.session && generation === state.generation) $("data-buffering-error").textContent = message;
  }
});

const loggingDestinations = ["local", "nfs", "syslog", "dsview"];
const loggingAlertIds = Array.from({ length: 10 }, (_, index) => `logging-alert-${index + 1}`);

function updateApplianceLoggingConditional() {
  const loaded = Boolean(state.applianceLoggingRevision) && !state.applianceLoggingWritePending;
  const enabled = loaded && $("logging-enabled").checked;
  const alertsEnabled = enabled && $("logging-alerts-enabled").checked;
  $("logging-options").hidden = !enabled;
  $("logging-alert-strings").hidden = !alertsEnabled;
  $("logging-destination").disabled = !enabled; $("logging-timestamp").disabled = !enabled;
  $("logging-alerts-enabled").disabled = !enabled;
  for (const id of loggingAlertIds) $(id).disabled = !alertsEnabled;
}

function setApplianceLoggingLoaded(loaded) {
  const disabled = !loaded || state.applianceLoggingWritePending;
  $("logging-enabled").disabled = disabled; $("save-appliance-logging").disabled = disabled;
  if (!loaded) {
    state.applianceLoggingRevision = ""; $("logging-enabled").checked = false;
    $("logging-timestamp").checked = false; $("logging-alerts-enabled").checked = false;
    clear($("logging-destination"));
    for (const id of loggingAlertIds) $(id).value = "";
  }
  updateApplianceLoggingConditional();
}

async function loadApplianceLoggingSetting(writeReadback = false) {
  if (state.applianceLoggingWritePending && !writeReadback) return;
  const request = ++state.applianceLoggingRequest;
  setApplianceLoggingLoaded(false); $("appliance-logging-error").textContent = ""; setText("appliance-logging-status", "Loading current setting…");
  try {
    const payload = await api("/api/v1/settings/appliance-logging");
    if (request !== state.applianceLoggingRequest) return;
    if (!strongRevision(payload.revision) || typeof payload.sessionLoggingEnabled !== "boolean" ||
        typeof payload.timestampEnabled !== "boolean" || typeof payload.alertsEnabled !== "boolean" ||
        typeof payload.destination !== "string" || !Array.isArray(payload.allowedDestinations) ||
        payload.allowedDestinations.length !== loggingDestinations.length ||
        !payload.allowedDestinations.every((value, index) => value === loggingDestinations[index]) ||
        !payload.allowedDestinations.includes(payload.destination) || !Array.isArray(payload.alertStrings) ||
        payload.alertStrings.length !== 10 || !payload.alertStrings.every((value) => typeof value === "string" && new TextEncoder().encode(value).length <= 64))
      throw new Error("The settings response was invalid.");
    for (const destination of loggingDestinations) {
      const option = document.createElement("option"); option.value = destination; option.textContent = destination; $("logging-destination").appendChild(option);
    }
    $("logging-enabled").checked = payload.sessionLoggingEnabled; $("logging-destination").value = payload.destination;
    $("logging-timestamp").checked = payload.timestampEnabled; $("logging-alerts-enabled").checked = payload.alertsEnabled;
    payload.alertStrings.forEach((value, index) => { $(loggingAlertIds[index]).value = value; });
    state.applianceLoggingRevision = payload.revision;
    setApplianceLoggingLoaded(true); setText("appliance-logging-status", "Current setting loaded. Inactive nested values are preserved.");
  } catch (error) {
    if (request === state.applianceLoggingRequest) {
      setApplianceLoggingLoaded(false); setText("appliance-logging-status", "Current setting unavailable. Reload before saving.");
      if (state.session) $("appliance-logging-error").textContent = error.message;
    }
  }
}

$("logging-enabled").addEventListener("change", updateApplianceLoggingConditional);
$("logging-alerts-enabled").addEventListener("change", updateApplianceLoggingConditional);
$("appliance-logging-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.applianceLoggingWritePending || $("save-appliance-logging").disabled || !state.applianceLoggingRevision) return;
  const generation = state.generation;
  const enabled = $("logging-enabled").checked;
  const replacement = { sessionLoggingEnabled: enabled };
  if (enabled) {
    replacement.destination = $("logging-destination").value;
    replacement.timestampEnabled = $("logging-timestamp").checked;
    replacement.alertsEnabled = $("logging-alerts-enabled").checked;
    if (replacement.alertsEnabled) {
      replacement.alertStrings = loggingAlertIds.map((id) => $(id).value);
      if (replacement.alertStrings.some((value) => new TextEncoder().encode(value).length > 64)) {
        $("appliance-logging-error").textContent = "Each alert string must be at most 64 UTF-8 bytes.";
        return;
      }
    }
  }
  state.applianceLoggingWritePending = true; $("reload-appliance-logging").disabled = true; $("disconnect").disabled = true;
  $("save-appliance-logging").disabled = true; updateApplianceLoggingConditional(); $("appliance-logging-error").textContent = "";
  let message = "";
  try {
    await api("/api/v1/settings/appliance-logging", { method: "PUT", headers: { "If-Match": state.applianceLoggingRevision }, body: JSON.stringify(replacement) });
    toast("Appliance Logging setting saved.");
  } catch (error) { message = error.message; }
  finally {
    await loadApplianceLoggingSetting(true);
    state.applianceLoggingWritePending = false; $("reload-appliance-logging").disabled = false;
    setApplianceLoggingLoaded(Boolean(state.applianceLoggingRevision));
    if (!state.helpLanguageWritePending && !state.dataBufferingWritePending && !state.timeZoneWritePending && !tokenIssuancePending && !logoutPending && state.session) $("disconnect").disabled = false;
    if (message && state.session && generation === state.generation) $("appliance-logging-error").textContent = message;
  }
});

const timeZoneSelectIds = ["time-zone-predefined", "time-zone-start-month", "time-zone-start-week", "time-zone-start-weekday", "time-zone-end-month", "time-zone-end-week", "time-zone-end-weekday"];
const timeZoneCustomInputIds = ["time-zone-name", "time-zone-standard-acronym", "time-zone-gmt-offset", "time-zone-dst-enabled"];
const timeZoneDstInputIds = ["time-zone-dst-acronym", "time-zone-save-time", "time-zone-start-month", "time-zone-start-week", "time-zone-start-weekday", "time-zone-start-hour", "time-zone-end-month", "time-zone-end-week", "time-zone-end-weekday", "time-zone-end-hour"];

function fillSelect(id, values) {
  clear($(id));
  for (const value of values) { const option = document.createElement("option"); option.value = value; option.textContent = value; $(id).appendChild(option); }
}

function updateTimeZoneConditional() {
  const loaded = Boolean(state.timeZoneRevision) && !state.timeZoneWritePending;
  const custom = loaded && $("time-zone-mode-custom").checked;
  const dst = custom && $("time-zone-dst-enabled").checked;
  $("time-zone-mode-predefined").disabled = !loaded; $("time-zone-mode-custom").disabled = !loaded;
  $("time-zone-predefined-options").hidden = custom; $("time-zone-custom-options").hidden = !custom; $("time-zone-dst-options").hidden = !dst;
  $("time-zone-predefined").disabled = !loaded || custom;
  for (const id of timeZoneCustomInputIds) $(id).disabled = !custom;
  for (const id of timeZoneDstInputIds) $(id).disabled = !dst;
  $("save-time-zone").disabled = !loaded;
}

function setTimeZoneLoaded(loaded) {
  if (!loaded) {
    state.timeZoneRevision = "";
    $("time-zone-mode-predefined").checked = false; $("time-zone-mode-custom").checked = false;
    for (const id of timeZoneSelectIds) clear($(id));
    for (const id of ["time-zone-name", "time-zone-standard-acronym", "time-zone-gmt-offset", "time-zone-dst-acronym", "time-zone-save-time", "time-zone-start-hour", "time-zone-end-hour"]) $(id).value = "";
    $("time-zone-dst-enabled").checked = false;
  }
  updateTimeZoneConditional();
}

function validTimeZonePayload(payload) {
  const transition = (value) => value && ["month", "week", "weekday", "hour"].every((key) => typeof value[key] === "string");
  return payload && strongRevision(payload.revision) && ["predefined", "custom"].includes(payload.mode) &&
    payload.predefined && typeof payload.predefined.selected === "string" && Array.isArray(payload.predefined.choices) &&
    payload.predefined.choices.length >= 1 && payload.predefined.choices.length <= 521 &&
    payload.predefined.choices.every((value) => typeof value === "string" && value.length > 0 && value.length <= 32) &&
    new Set(payload.predefined.choices).size === payload.predefined.choices.length && payload.predefined.choices.includes(payload.predefined.selected) &&
    payload.custom && typeof payload.custom.name === "string" && typeof payload.custom.standardAcronym === "string" &&
    typeof payload.custom.gmtOffset === "string" && payload.custom.dst && typeof payload.custom.dst.enabled === "boolean" &&
    typeof payload.custom.dst.acronym === "string" && typeof payload.custom.dst.saveTime === "string" &&
    transition(payload.custom.dst.start) && transition(payload.custom.dst.end);
}

async function loadTimeZoneSetting(writeReadback = false) {
  if (state.timeZoneWritePending && !writeReadback) return;
  const request = ++state.timeZoneRequest;
  setTimeZoneLoaded(false); $("time-zone-error").textContent = ""; setText("time-zone-status", "Loading current setting…");
  try {
    const payload = await api("/api/v1/settings/time-zone");
    if (request !== state.timeZoneRequest) return;
    if (!validTimeZonePayload(payload)) throw new Error("The settings response was invalid.");
    fillSelect("time-zone-predefined", payload.predefined.choices);
    fillSelect("time-zone-start-month", Array.from({ length: 12 }, (_, index) => String(index + 1)));
    fillSelect("time-zone-end-month", Array.from({ length: 12 }, (_, index) => String(index + 1)));
    fillSelect("time-zone-start-week", ["1", "2", "3", "4", "5"]); fillSelect("time-zone-end-week", ["1", "2", "3", "4", "5"]);
    fillSelect("time-zone-start-weekday", ["1", "2", "3", "4", "5", "6", "7"]); fillSelect("time-zone-end-weekday", ["1", "2", "3", "4", "5", "6", "7"]);
    $("time-zone-mode-predefined").checked = payload.mode === "predefined"; $("time-zone-mode-custom").checked = payload.mode === "custom";
    $("time-zone-predefined").value = payload.predefined.selected; $("time-zone-name").value = payload.custom.name;
    $("time-zone-standard-acronym").value = payload.custom.standardAcronym; $("time-zone-gmt-offset").value = payload.custom.gmtOffset;
    $("time-zone-dst-enabled").checked = payload.custom.dst.enabled; $("time-zone-dst-acronym").value = payload.custom.dst.acronym;
    $("time-zone-save-time").value = payload.custom.dst.saveTime;
    for (const edge of ["start", "end"]) for (const field of ["month", "week", "weekday", "hour"]) $(
      `time-zone-${edge}-${field}`
    ).value = payload.custom.dst[edge][field];
    state.timeZoneRevision = payload.revision; setTimeZoneLoaded(true);
    setText("time-zone-status", "Current controller setting loaded. Runtime timezone effects are not confirmed.");
  } catch (error) {
    if (request === state.timeZoneRequest) { setTimeZoneLoaded(false); setText("time-zone-status", "Current setting unavailable. Reload before saving."); if (state.session) $("time-zone-error").textContent = error.message; }
  }
}

$("time-zone-mode-predefined").addEventListener("change", updateTimeZoneConditional);
$("time-zone-mode-custom").addEventListener("change", updateTimeZoneConditional);
$("time-zone-dst-enabled").addEventListener("change", updateTimeZoneConditional);
$("time-zone-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.timeZoneWritePending || $("save-time-zone").disabled || !state.timeZoneRevision) return;
  const generation = state.generation;
  const customMode = $("time-zone-mode-custom").checked;
  let replacement = { mode: "predefined", predefinedZone: $("time-zone-predefined").value };
  if (customMode) {
    const dstEnabled = $("time-zone-dst-enabled").checked;
    const custom = { name: $("time-zone-name").value, standardAcronym: $("time-zone-standard-acronym").value, gmtOffset: $("time-zone-gmt-offset").value, dst: { enabled: dstEnabled } };
    if (new TextEncoder().encode(custom.name).length > 256) { $("time-zone-error").textContent = "The custom name must be at most 256 UTF-8 bytes."; return; }
    if (dstEnabled) {
      custom.dst.acronym = $("time-zone-dst-acronym").value; custom.dst.saveTime = $("time-zone-save-time").value;
      custom.dst.start = { month: $("time-zone-start-month").value, week: $("time-zone-start-week").value, weekday: $("time-zone-start-weekday").value, hour: $("time-zone-start-hour").value };
      custom.dst.end = { month: $("time-zone-end-month").value, week: $("time-zone-end-week").value, weekday: $("time-zone-end-weekday").value, hour: $("time-zone-end-hour").value };
    }
    replacement = { mode: "custom", custom };
  }
  state.timeZoneWritePending = true; $("reload-time-zone").disabled = true; $("disconnect").disabled = true; $("save-time-zone").disabled = true; updateTimeZoneConditional(); $("time-zone-error").textContent = "";
  let message = "";
  try {
    await api("/api/v1/settings/time-zone", { method: "PUT", headers: { "If-Match": state.timeZoneRevision }, body: JSON.stringify(replacement) });
    toast("Time Zone setting saved. Runtime effect is not yet validated.");
  } catch (error) { message = error.message; }
  finally {
    await loadTimeZoneSetting(true);
    state.timeZoneWritePending = false; $("reload-time-zone").disabled = false;
    setTimeZoneLoaded(Boolean(state.timeZoneRevision));
    if (!state.helpLanguageWritePending && !state.dataBufferingWritePending && !state.applianceLoggingWritePending && !tokenIssuancePending && !logoutPending && state.session) $("disconnect").disabled = false;
    if (message && state.session && generation === state.generation) $("time-zone-error").textContent = message;
  }
});

$("reload-help-language").addEventListener("click", loadHelpLanguageSetting);
$("reload-data-buffering").addEventListener("click", loadDataBufferingSetting);
$("reload-appliance-logging").addEventListener("click", loadApplianceLoggingSetting);
$("reload-time-zone").addEventListener("click", loadTimeZoneSetting);

const ACME_MAX_DNS_NAMES = 16;
const ACME_MAX_DNS_NAME_BYTES = 253;
const ACME_MAX_CA_BYTES = 65536;
const ACME_RENEWAL_STATES = ["never_run", "starting", "running", "succeeded", "failed", "durability_uncertain", "unknown"];
const ACME_FAILURE_PHASES = ["directory", "nonce", "account", "order", "authorization", "challenge_publication", "challenge_acceptance", "challenge_poll", "finalize", "certificate_download", "certificate_validation", "certificate_publication"];
const ACME_FAILURE_REASONS = ["tls", "http", "parse", "io", "rejected", "timeout", "validation", "publication"];
const acmeTerminalStates = ["succeeded", "failed", "durability_uncertain", "unknown"];
const acmeTextIds = {
  "acme-eyebrow": "acme.eyebrow", "acme-title": "acme.title", "acme-description": "acme.description",
  "reload-acme": "acme.reload", "acme-enabled-label": "acme.enabled", "acme-enabled-help": "acme.enabledHelp",
  "acme-directory-label": "acme.directory", "acme-dns-label": "acme.dns", "acme-dns-help": "acme.dnsHelp",
  "save-acme": "acme.save", "acme-ca-title": "acme.caTitle", "acme-ca-path-label": "acme.caPath",
  "acme-ca-upload-label": "acme.caUpload", "acme-ca-help": "acme.caHelp", "upload-acme-ca": "acme.upload",
  "acme-renewal-title": "acme.renewalTitle", "acme-renewal-label": "acme.status", "acme-renew": "acme.renew"
};
for (const [id, key] of Object.entries(acmeTextIds)) setText(id, t(key));
setText("acme-status", t("acme.loadFirst"));
setText("acme-renewal-status", t("acme.renewal.unknown"));

function acmeOperationPending() { return state.acmeMutationPending || state.acmeRenewalPending; }

function setAcmeLoaded(loaded, preserveDraft = false) {
  state.acmeLoaded = loaded;
  const disabled = !loaded || acmeOperationPending();
  for (const id of ["acme-enabled", "acme-directory-url", "acme-dns-names"]) $(id).disabled = disabled;
  $("save-acme").disabled = disabled || (!state.acmeConfigured && !state.acmeCaInstalled);
  for (const id of ["acme-ca-file", "upload-acme-ca"]) $(id).disabled = disabled || (!state.acmeConfigured && state.acmeCaInstalled);
  $("acme-renew").disabled = disabled || !state.acmeConfigured;
  $("reload-acme").disabled = acmeOperationPending() || !state.session || !state.session.navigation.canManageAcme;
  if (!loaded && !preserveDraft) {
    state.acmeRevision = ""; state.acmeConfigured = false; state.acmeCaInstalled = false;
    $("acme-enabled").checked = false; $("acme-directory-url").value = ""; $("acme-dns-names").value = "";
    setText("acme-ca-path", ""); setText("acme-renewal-status", t("acme.renewal.unknown"));
  }
}

function clearAcmeState() {
  state.acmeRequest += 1; state.acmeRevision = ""; state.acmeMutationPending = false; state.acmeRenewalPending = false;
  if (state.acmeRenewalTimer) window.clearTimeout(state.acmeRenewalTimer); state.acmeRenewalTimer = 0;
  $("acme-ca-form").reset(); setAcmeLoaded(false); $("reload-acme").disabled = true;
  setText("acme-status", t("acme.loadFirst")); setText("acme-error", ""); setText("acme-renewal-note", "");
}

function validAcmeBootstrapPayload(payload) {
  const keys = payload && typeof payload === "object" ? Object.keys(payload).sort().join(",") : "";
  const renewalKeys = payload && payload.renewal && typeof payload.renewal === "object" ? Object.keys(payload.renewal).join(",") : "";
  return keys === "caInstalled,configured,renewal" && payload.configured === false &&
    typeof payload.caInstalled === "boolean" && renewalKeys === "state" &&
    payload.renewal.state === "never_run";
}

function validAcmePayload(payload) {
  if (payload && payload.configured === false) return validAcmeBootstrapPayload(payload);
  const keys = payload && typeof payload === "object" ? Object.keys(payload).sort().join(",") : "";
  const renewalKeys = payload && payload.renewal && typeof payload.renewal === "object" ? Object.keys(payload.renewal).sort().join(",") : "";
  const renewalValid = renewalKeys === "state" ||
    (renewalKeys === "phase,reason,state" && payload.renewal.state === "failed" &&
     ACME_FAILURE_PHASES.includes(payload.renewal.phase) && ACME_FAILURE_REASONS.includes(payload.renewal.reason));
  const dnsPattern = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/u;
  return keys === "caFile,directoryUrl,dnsNames,enabled,renewal,revision" && renewalValid &&
    typeof payload.enabled === "boolean" && typeof payload.directoryUrl === "string" && /^https:\/\/[^\u0000-\u0020\u007F]+$/u.test(payload.directoryUrl) && new TextEncoder().encode(payload.directoryUrl).length <= 1291 &&
    typeof payload.caFile === "string" && /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/u.test(payload.caFile) && new TextEncoder().encode(payload.caFile).length <= 1024 &&
    Array.isArray(payload.dnsNames) && payload.dnsNames.length >= 1 && payload.dnsNames.length <= ACME_MAX_DNS_NAMES &&
    new Set(payload.dnsNames).size === payload.dnsNames.length && payload.dnsNames.every((name) => typeof name === "string" && dnsPattern.test(name) && new TextEncoder().encode(name).length <= ACME_MAX_DNS_NAME_BYTES) &&
    strongRevision(payload.revision) && ACME_RENEWAL_STATES.includes(payload.renewal.state);
}

function renderAcme(payload) {
  if (payload.configured === false) {
    state.acmeConfigured = false; state.acmeCaInstalled = payload.caInstalled; state.acmeRevision = "";
    setText("acme-ca-path", payload.caInstalled ? "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem" : "");
    setText("acme-renewal-status", t("acme.renewal.never_run"));
    return;
  }
  state.acmeConfigured = true; state.acmeCaInstalled = pm3000ManagedCaPath(payload.caFile);
  $("acme-enabled").checked = payload.enabled; $("acme-directory-url").value = payload.directoryUrl;
  $("acme-dns-names").value = payload.dnsNames.join("\n"); setText("acme-ca-path", payload.caFile);
  setText("acme-renewal-status", t(`acme.renewal.${payload.renewal.state}`));
  if (acmeTerminalStates.includes(payload.renewal.state)) {
    setText("acme-renewal-note", payload.renewal.state === "failed" && payload.renewal.phase ?
      `Failure: ${payload.renewal.phase} / ${payload.renewal.reason}` : "");
  }
  state.acmeRevision = payload.revision;
}

function pm3000ManagedCaPath(path) {
  return path === "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem";
}

async function loadAcmeSetting(writeReadback = false, renewalPoll = false) {
  if (!state.session || !state.session.navigation.canManageAcme || (state.acmeMutationPending && !writeReadback) || (state.acmeRenewalPending && !renewalPoll)) return false;
  const request = ++state.acmeRequest;
  if (!renewalPoll) { setAcmeLoaded(false, writeReadback && !state.acmeConfigured); setText("acme-error", ""); setText("acme-status", t("acme.loading")); }
  try {
    const payload = await api("/api/v1/settings/acme");
    if (request !== state.acmeRequest) return false;
    if (!validAcmePayload(payload)) throw new Error(t("acme.invalidResponse"));
    renderAcme(payload); setAcmeLoaded(true);
    setText("acme-status", payload.configured === false ? t(payload.caInstalled ? "acme.caReady" : "acme.firstRun") : t("acme.loaded"));
    return true;
  } catch (error) {
    if (request === state.acmeRequest) {
      setAcmeLoaded(false); setText("acme-status", t("acme.unavailable"));
      if (state.session) setText("acme-error", error.message);
    }
    return false;
  }
}

function acmeDnsNames() {
  const names = $("acme-dns-names").value.split(/\r?\n/u).map((name) => name.trim()).filter(Boolean);
  const pattern = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/u;
  if (names.length < 1 || names.length > ACME_MAX_DNS_NAMES || new Set(names).size !== names.length || names.some((name) => !pattern.test(name) || new TextEncoder().encode(name).length > ACME_MAX_DNS_NAME_BYTES)) return null;
  return names;
}

async function runAcmeMutation(path, options, successKey) {
  if (acmeOperationPending() || !state.acmeLoaded || (state.acmeConfigured && !state.acmeRevision)) return;
  const generation = state.generation; state.acmeMutationPending = true; setAcmeLoaded(true); setText("acme-error", ""); $("disconnect").disabled = true;
  try {
    await api(path, { ...options, expectedStatus: 204 });
    if (generation !== state.generation) return;
    const loaded = await loadAcmeSetting(true);
    if (generation === state.generation && loaded) { toast(t(successKey)); if (state.acmeConfigured) setText("acme-status", t("acme.loaded")); }
  } catch (error) {
    if (generation === state.generation && state.session) {
      setAcmeLoaded(false); setText("acme-status", t("acme.reloadRequired")); setText("acme-error", error.message);
    }
  } finally {
    if (generation === state.generation) {
      state.acmeMutationPending = false; setAcmeLoaded(state.acmeLoaded);
      if (!state.helpLanguageWritePending && !state.dataBufferingWritePending && !state.applianceLoggingWritePending && !state.timeZoneWritePending && !tokenIssuancePending && !logoutPending && state.session) $("disconnect").disabled = false;
    }
  }
}

$("acme-form").addEventListener("submit", (event) => {
  event.preventDefault(); if ($("save-acme").disabled || acmeOperationPending() || !state.acmeLoaded || (state.acmeConfigured && !state.acmeRevision)) return;
  const directoryUrl = $("acme-directory-url").value; const dnsNames = acmeDnsNames();
  if (!/^https:\/\/[^\u0000-\u0020\u007F]+$/u.test(directoryUrl) || new TextEncoder().encode(directoryUrl).length > 1291) { setText("acme-error", t("acme.invalidDirectory")); return; }
  if (!dnsNames) { setText("acme-error", t("acme.invalidDns")); return; }
  const headers = state.acmeConfigured ? { "If-Match": state.acmeRevision } : { "If-None-Match": "*" };
  runAcmeMutation("/api/v1/settings/acme", { method: "PUT", headers, body: JSON.stringify({ enabled: $("acme-enabled").checked, directoryUrl: directoryUrl, dnsNames }) }, "acme.saved");
});

$("acme-ca-form").addEventListener("submit", async (event) => {
  event.preventDefault(); if ($("upload-acme-ca").disabled || acmeOperationPending() || !state.acmeLoaded || (state.acmeConfigured && !state.acmeRevision)) return;
  const file = $("acme-ca-file").files[0];
  if (!file || file.size === 0) { setText("acme-error", t("acme.caEmpty")); $("acme-ca-form").reset(); return; }
  if (file.size > ACME_MAX_CA_BYTES) { setText("acme-error", t("acme.caLarge")); $("acme-ca-form").reset(); return; }
  const revision = state.acmeRevision; const configured = state.acmeConfigured; const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length === 0 || bytes.length > ACME_MAX_CA_BYTES || revision !== state.acmeRevision || configured !== state.acmeConfigured || acmeOperationPending()) { setText("acme-error", bytes.length ? t("acme.caLarge") : t("acme.caEmpty")); $("acme-ca-form").reset(); return; }
  const headers = configured ? { "If-Match": revision, "Content-Type": "application/x-pem-file" } : { "If-None-Match": "*", "Content-Type": "application/x-pem-file" };
  try { await runAcmeMutation("/api/v1/settings/acme/ca", { method: "PUT", headers, body: bytes }, "acme.caSaved"); }
  finally { $("acme-ca-form").reset(); }
});

function scheduleAcmeRenewalRefresh(generation, remaining) {
  if (!state.acmeRenewalPending || generation !== state.generation) return;
  if (remaining === 0) {
    state.acmeRenewalPending = false; state.acmeRenewalTimer = 0; setAcmeLoaded(Boolean(state.acmeRevision)); setText("acme-renewal-note", t("acme.refreshStopped"));
    if (state.session) $("disconnect").disabled = false;
    return;
  }
  state.acmeRenewalTimer = window.setTimeout(async () => {
    state.acmeRenewalTimer = 0; const loaded = await loadAcmeSetting(false, true);
    if (generation !== state.generation || !state.session) return;
    const label = $("acme-renewal-status").textContent;
    const terminal = acmeTerminalStates.some((status) => label === t(`acme.renewal.${status}`));
    if (loaded && terminal) { state.acmeRenewalPending = false; setAcmeLoaded(true); $("disconnect").disabled = false; return; }
    scheduleAcmeRenewalRefresh(generation, remaining - 1);
  }, 2000);
}

$("acme-renew").addEventListener("click", async () => {
  if ($("acme-renew").disabled || acmeOperationPending() || !state.acmeRevision) return;
  const generation = state.generation; state.acmeRenewalPending = true; setAcmeLoaded(true); setText("acme-error", ""); setText("acme-renewal-note", ""); $("disconnect").disabled = true;
  try {
    await api("/api/v1/settings/acme/renew", { method: "POST", expectedStatus: 202 });
    if (generation !== state.generation) return;
    setText("acme-renewal-note", t("acme.started")); scheduleAcmeRenewalRefresh(generation, 6);
  } catch (error) {
    if (generation !== state.generation || !state.session) return;
    state.acmeRenewalPending = false;
    if (error.code === "action_outcome_unknown") { setAcmeLoaded(false); setText("acme-status", t("acme.reloadRequired")); }
    else setAcmeLoaded(Boolean(state.acmeRevision));
    setText("acme-error", error.message); $("disconnect").disabled = false;
  }
});

$("reload-acme").addEventListener("click", () => loadAcmeSetting());

$("password-change-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("submit-password-change");
  if (button.disabled) return;
  let oldPassword = $("old-password").value;
  let newPassword = $("new-password").value;
  let confirmation = $("confirm-password").value;
  $("password-change-error").textContent = "";
  if (newPassword !== confirmation) {
    $("password-change-error").textContent = "The new passwords do not match.";
    return;
  }
  let requestBody = JSON.stringify({ oldPassword, newPassword, confirmation });
  oldPassword = ""; newPassword = ""; confirmation = "";
  $("old-password").value = ""; $("new-password").value = ""; $("confirm-password").value = "";
  button.disabled = true;
  try {
    const request = api("/api/v1/session/password", { method: "POST", body: requestBody });
    requestBody = "";
    await request;
    toast("Password changed.");
  } catch (error) {
    $("password-change-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

async function loginTransition() {
  $("login-error").textContent = ""; state.generation += 1;
  const username = $("username-input").value; let password = $("password-input").value;
  const requestBody = JSON.stringify({ username, password });
  password = "";
  $("password-input").value = "";
  const session = await api("/api/v1/session", { method: "POST", csrf: false, body: requestBody });
  showAuthenticated(session);
}

$("connect-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (bootstrapPending || tokenIssuancePending || loginPending || logoutPending) return;
  loginPending = true; setLoginDisabled(true);
  serializeTransition(loginTransition).catch((error) => {
    $("login-error").textContent = error.message;
  }).finally(() => {
    loginPending = false;
    if (!logoutPending && !state.session) setLoginDisabled(false);
  });
});

$("disconnect").addEventListener("click", () => {
  if (tokenIssuancePending) { toast("Wait for token creation to finish before signing out."); return; }
  if (state.acmeMutationPending || state.acmeRenewalPending) { toast(t("acme.wait")); return; }
  if (state.helpLanguageWritePending || state.dataBufferingWritePending || state.applianceLoggingWritePending || state.timeZoneWritePending) { toast("Wait for the settings save to finish before signing out."); return; }
  if (bootstrapPending || logoutPending || loginPending || !state.session) return;
  logoutPending = true; setLoginDisabled(true); serializeTransition(logoutTransition);
}); $("refresh-outlets").addEventListener("click", loadOutlets); $("refresh-pdus").addEventListener("click", loadPdus); $("refresh-tokens").addEventListener("click", loadTokens);
$("open-create-token").addEventListener("click", () => { $("create-error").textContent = ""; $("create-token-dialog").showModal(); $("token-label").focus(); });
$("cancel-create").addEventListener("click", () => $("create-token-dialog").close()); $("close-create-title").addEventListener("click", () => $("create-token-dialog").close());
$("all-outlets").addEventListener("change", () => { $("token-outlets").disabled = $("all-outlets").checked; if (!$("token-outlets").disabled) $("token-outlets").focus(); });
$("create-token-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const button = event.submitter; if (!button || button.type !== "submit" || button.disabled) return; button.disabled = true;
  let outlets = null;
  if (!$("all-outlets").checked) { outlets = $("token-outlets").value.split(/\s+/u).filter(Boolean); if (outlets.length > 256 || new Set(outlets).size !== outlets.length || outlets.some((id) => !/^[A-Za-z0-9_-]{22}$/u.test(id))) { $("create-error").textContent = "Use at most 256 unique, 22-character opaque outlet IDs."; button.disabled = false; return; } outlets.sort(); }
  const payload = { label: $("token-label").value, scope: $("token-scope").value }; if (outlets !== null) payload.outlets = outlets;
  tokenIssuancePending = true; $("disconnect").disabled = true;
  try { const created = await api("/api/v1/tokens", { method: "POST", body: JSON.stringify(payload), deliverAfterSessionChange: true }); $("create-token-dialog").close(); $("create-token-form").reset(); $("token-outlets").disabled = true; $("token-outlets").value = ""; setText("new-token-secret", created.token); $("copy-state").textContent = ""; $("token-secret-dialog").showModal(); if (state.session) await loadTokens(); }
  catch (error) { $("create-error").textContent = error.message; } finally { tokenIssuancePending = false; $("disconnect").disabled = false; button.disabled = false; if (!state.session) { setLoginDisabled(false); $("username-input").focus(); } }
});
$("copy-secret").addEventListener("click", async () => { try { await navigator.clipboard.writeText($("new-token-secret").textContent); setText("copy-state", "Copied to clipboard."); } catch { setText("copy-state", "Copy was blocked. Select and copy the value manually."); } });
$("token-secret-dialog").addEventListener("close", clearOneTimeSecret); $("close-secret").addEventListener("click", () => $("token-secret-dialog").close());

async function loadSysinfo() {
  const request = ++state.sysinfoRequest; $("refresh-sysinfo").disabled = true;
  setText("sysinfo-status", "Loading…"); $("sysinfo-fields").hidden = true;
  try {
    const payload = await api("/api/v1/system/information");
    if (request === state.sysinfoRequest) {
      setText("si-model", payload.modelNumber); setText("si-boot-code", payload.bootCodeVersion);
      setText("si-firmware", payload.firmwareVersion); setText("si-booted-from", payload.bootedFrom);
      setText("si-cpu", payload.cpu); setText("si-revision", payload.revision); setText("si-bogomips", payload.bogomips);
      setText("sysinfo-status", ""); $("sysinfo-fields").hidden = false;
    }
  } catch (error) { if (request === state.sysinfoRequest && state.session) setText("sysinfo-status", error.message); }
  finally { if (request === state.sysinfoRequest) $("refresh-sysinfo").disabled = false; }
}
async function loadMemory() {
  const request = ++state.memoryRequest; $("refresh-memory").disabled = true;
  setText("memory-status", "Loading…"); $("memory-table-wrap").hidden = true; $("memory-empty").hidden = true;
  try {
    const payload = await api("/api/v1/system/usage/memory");
    if (request === state.memoryRequest) {
      const rows = Array.isArray(payload.rows) ? payload.rows : []; const body = $("memory-rows"); clear(body);
      for (const row of rows) { const tr = document.createElement("tr"); const td1 = document.createElement("td"); td1.textContent = row.name; const td2 = document.createElement("td"); td2.textContent = row.value; tr.append(td1, td2); body.appendChild(tr); }
      setText("memory-status", ""); $("memory-table-wrap").hidden = false; $("memory-empty").hidden = rows.length !== 0;
    }
  } catch (error) { if (request === state.memoryRequest && state.session) setText("memory-status", error.message); }
  finally { if (request === state.memoryRequest) $("refresh-memory").disabled = false; }
}
async function loadFlash() {
  const request = ++state.flashRequest; $("refresh-flash").disabled = true;
  setText("flash-status", "Loading…"); $("flash-table-wrap").hidden = true; $("flash-empty").hidden = true;
  try {
    const payload = await api("/api/v1/system/usage/flash");
    if (request === state.flashRequest) {
      const rows = Array.isArray(payload.rows) ? payload.rows : []; const body = $("flash-rows"); clear(body);
      for (const row of rows) { const tr = document.createElement("tr"); ["filesystem","blocks1k","used","available","usePercentage","mountedOn"].forEach((k) => { const td = document.createElement("td"); td.textContent = String(row[k] ?? ""); tr.appendChild(td); }); body.appendChild(tr); }
      setText("flash-status", ""); $("flash-table-wrap").hidden = false; $("flash-empty").hidden = rows.length !== 0;
    }
  } catch (error) { if (request === state.flashRequest && state.session) setText("flash-status", error.message); }
  finally { if (request === state.flashRequest) $("refresh-flash").disabled = false; }
}
async function loadNetdev() {
  const request = ++state.netdevRequest; $("refresh-netdev").disabled = true;
  setText("netdev-status", "Loading…"); $("netdev-table-wrap").hidden = true; $("netdev-empty").hidden = true;
  try {
    const payload = await api("/api/v1/monitoring/network/devices");
    if (request === state.netdevRequest) {
      const rows = Array.isArray(payload.devices) ? payload.devices : []; const body = $("netdev-rows"); clear(body);
      for (const row of rows) { const tr = document.createElement("tr"); ["name","status","ipv4Address","ipv4Mask","ipv6Address"].forEach((k) => { const td = document.createElement("td"); td.textContent = String(row[k] ?? ""); tr.appendChild(td); }); body.appendChild(tr); }
      setText("netdev-status", ""); $("netdev-table-wrap").hidden = false; $("netdev-empty").hidden = rows.length !== 0;
    }
  } catch (error) { if (request === state.netdevRequest && state.session) setText("netdev-status", error.message); }
  finally { if (request === state.netdevRequest) $("refresh-netdev").disabled = false; }
}
async function loadRoute4() {
  const request = ++state.route4Request; $("refresh-route4").disabled = true;
  setText("route4-status", "Loading…"); $("route4-table-wrap").hidden = true; $("route4-empty").hidden = true;
  try {
    const payload = await api("/api/v1/monitoring/network/routes/ipv4");
    if (request === state.route4Request) {
      const rows = Array.isArray(payload.routes) ? payload.routes : []; const body = $("route4-rows"); clear(body);
      for (const row of rows) { const tr = document.createElement("tr"); ["destination","gateway","genmask","flags","metric","ref","use","iface"].forEach((k) => { const td = document.createElement("td"); td.textContent = String(row[k] ?? ""); tr.appendChild(td); }); body.appendChild(tr); }
      setText("route4-status", ""); $("route4-table-wrap").hidden = false; $("route4-empty").hidden = rows.length !== 0;
    }
  } catch (error) { if (request === state.route4Request && state.session) setText("route4-status", error.message); }
  finally { if (request === state.route4Request) $("refresh-route4").disabled = false; }
}
async function loadRoute6() {
  const request = ++state.route6Request; $("refresh-route6").disabled = true;
  setText("route6-status", "Loading…"); $("route6-table-wrap").hidden = true; $("route6-empty").hidden = true;
  try {
    const payload = await api("/api/v1/monitoring/network/routes/ipv6");
    if (request === state.route6Request) {
      const rows = Array.isArray(payload.routes) ? payload.routes : []; const body = $("route6-rows"); clear(body);
      for (const row of rows) { const tr = document.createElement("tr"); ["destination","nextHop","flags","metric","ref","use","iface"].forEach((k) => { const td = document.createElement("td"); td.textContent = String(row[k] ?? ""); tr.appendChild(td); }); body.appendChild(tr); }
      setText("route6-status", ""); $("route6-table-wrap").hidden = false; $("route6-empty").hidden = rows.length !== 0;
    }
  } catch (error) { if (request === state.route6Request && state.session) setText("route6-status", error.message); }
  finally { if (request === state.route6Request) $("refresh-route6").disabled = false; }
}
async function loadSerial() {
  const request = ++state.serialRequest; $("refresh-serial").disabled = true;
  setText("serial-status", "Loading…"); $("serial-table-wrap").hidden = true; $("serial-empty").hidden = true;
  try {
    const payload = await api("/api/v1/monitoring/serial-ports");
    if (request === state.serialRequest) {
      const rows = Array.isArray(payload.ports) ? payload.ports : []; const body = $("serial-rows"); clear(body);
      for (const row of rows) { const tr = document.createElement("tr"); ["deviceName","portProfile","speed","signals","txBytes","rxBytes","frameError","parityError","brk","overrun"].forEach((k) => { const td = document.createElement("td"); td.textContent = String(row[k] ?? ""); tr.appendChild(td); }); body.appendChild(tr); }
      setText("serial-status", ""); $("serial-table-wrap").hidden = false; $("serial-empty").hidden = rows.length !== 0;
    }
  } catch (error) { if (request === state.serialRequest && state.session) setText("serial-status", error.message); }
  finally { if (request === state.serialRequest) $("refresh-serial").disabled = false; }
}
$("refresh-sysinfo").addEventListener("click", loadSysinfo); $("refresh-memory").addEventListener("click", loadMemory); $("refresh-flash").addEventListener("click", loadFlash); $("refresh-netdev").addEventListener("click", loadNetdev); $("refresh-route4").addEventListener("click", loadRoute4); $("refresh-route6").addEventListener("click", loadRoute6); $("refresh-serial").addEventListener("click", loadSerial);

fetch("/api/v1/health", { cache: "no-store" }).then((response) => { if (!response.ok) throw new Error(); setText("health-label", "Adapter ready"); }).catch(() => setText("health-label", "Adapter unavailable"));
async function bootstrapTransition() {
  const generation = state.generation;
  try {
    const session = await api("/api/v1/session");
    if (generation !== state.generation) return;
    showAuthenticated(session);
  } catch {
    if (generation !== state.generation) return;
    disconnectLocal();
  }
}
setLoginDisabled(true);
serializeTransition(bootstrapTransition).finally(() => {
  bootstrapPending = false;
  if (!state.session) setLoginDisabled(false);
});
