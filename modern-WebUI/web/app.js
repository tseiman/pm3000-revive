const state = { token: "", view: "outlets", generation: 0, tokenRequest: 0, outlets: [], tokens: [] };
const $ = (id) => document.getElementById(id);

function apiErrorMessage(payload, fallback) {
  if (payload && typeof payload.message === "string") return payload.message;
  if (payload && payload.error && typeof payload.error.message === "string") return payload.error.message;
  return fallback;
}

async function api(path, options = {}) {
  const generation = state.generation;
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  let payload = null;
  try { payload = await response.json(); } catch { /* closed below */ }
  if (generation !== state.generation) throw new Error("Session changed.");
  if (response.status === 401) {
    disconnect("The token is no longer authorized.");
    throw new Error("Unauthorized.");
  }
  if (!response.ok) throw new Error(apiErrorMessage(payload, `Request failed (${response.status}).`));
  return payload;
}

function setText(id, value) { $(id).textContent = String(value); }
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function toast(message) {
  const node = $("toast"); node.textContent = message; node.hidden = false;
  window.clearTimeout(toast.timer); toast.timer = window.setTimeout(() => { node.hidden = true; }, 2600);
}

function disconnect(message = "") {
  state.generation += 1; state.token = ""; state.outlets = []; state.tokens = [];
  if ($("create-token-dialog").open) $("create-token-dialog").close();
  if ($("token-secret-dialog").open) $("token-secret-dialog").close();
  clearOneTimeSecret();
  clear($("outlet-grid")); clear($("token-rows")); $("authenticated").hidden = true;
  $("login-view").hidden = false; $("token-input").value = ""; $("login-error").textContent = message;
  $("token-input").focus();
}

function statusLabel(value) {
  if (value === "on") return "On";
  if (value === "off") return "Off";
  return "Unknown";
}

function renderOutlets(collection) {
  const outlets = Array.isArray(collection.outlets) ? collection.outlets : [];
  state.outlets = outlets;
  const grid = $("outlet-grid"); clear(grid);
  for (const outlet of outlets) {
    const article = document.createElement("article"); article.className = "outlet-card";
    const header = document.createElement("div"); header.className = "outlet-card-header";
    const position = document.createElement("span"); position.className = "outlet-position";
    position.textContent = `OUTLET ${String(outlet.position).padStart(2, "0")}`;
    const status = document.createElement("span"); status.className = `status-chip${outlet.state === "unknown" ? " unknown" : ""}`;
    status.textContent = statusLabel(outlet.state);
    const title = document.createElement("h3"); title.textContent = outlet.name || `Outlet ${outlet.position}`;
    const identifier = document.createElement("p"); identifier.textContent = outlet.id;
    header.append(position, status); article.append(header, title, identifier); grid.appendChild(article);
  }
  const onCount = outlets.filter((item) => item.state === "on").length;
  const unknownCount = outlets.filter((item) => item.state === "unknown").length;
  setText("total-count", outlets.length); setText("on-count", onCount); setText("unknown-count", unknownCount);
  setText("inventory-revision", `Inventory revision ${collection.inventoryRevision || "—"}`);
  setText("updated-at", `Updated ${new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date())}`);
  $("outlet-empty").hidden = outlets.length !== 0;
}

async function loadOutlets() {
  $("refresh-outlets").disabled = true;
  try { renderOutlets(await api("/api/v1/outlets")); }
  catch (error) { if (state.token) toast(error.message); }
  finally { $("refresh-outlets").disabled = false; }
}

function tokenActionButton(record, action) {
  const button = document.createElement("button"); button.type = "button"; button.className = `small-button${action === "revoke" ? " danger" : ""}`;
  button.textContent = action === "revoke" ? "Revoke" : record.enabled ? "Disable" : "Enable";
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const method = action === "revoke" ? "DELETE" : "POST";
      const operation = action === "revoke" ? "" : `/${record.enabled ? "disable" : "enable"}`;
      await api(`/api/v1/tokens/${encodeURIComponent(record.id)}${operation}`, { method });
      toast(action === "revoke" ? "Token revoked." : `Token ${record.enabled ? "disabled" : "enabled"}.`);
      await loadTokens();
    } catch (error) { toast(error.message); button.disabled = false; }
  });
  return button;
}

function renderTokens(payload) {
  const records = Array.isArray(payload.tokens) ? payload.tokens : [];
  state.tokens = records; const body = $("token-rows"); clear(body);
  for (const record of records) {
    const row = document.createElement("tr");
    const label = document.createElement("td"); label.textContent = record.label;
    const scopeCell = document.createElement("td"); const scope = document.createElement("span"); scope.className = "scope-badge"; scope.textContent = record.scope; scopeCell.appendChild(scope);
    const access = document.createElement("td"); access.textContent = record.outlets === null ? "All outlets" : `${record.outlets.length} selected`;
    const statusCell = document.createElement("td"); const enabled = document.createElement("span"); enabled.className = `enabled-badge${record.enabled ? "" : " disabled"}`; enabled.textContent = record.enabled ? "Enabled" : "Disabled"; statusCell.appendChild(enabled);
    const id = document.createElement("td"); id.textContent = record.id;
    const actions = document.createElement("td"); const group = document.createElement("div"); group.className = "row-actions"; group.append(tokenActionButton(record, "toggle"), tokenActionButton(record, "revoke")); actions.appendChild(group);
    row.append(label, scopeCell, access, statusCell, id, actions); body.appendChild(row);
  }
  $("token-empty").hidden = records.length !== 0;
}

async function loadTokens() {
  const request = ++state.tokenRequest;
  $("refresh-tokens").disabled = true;
  try { const payload = await api("/api/v1/tokens"); if (request === state.tokenRequest) renderTokens(payload); }
  catch (error) { if (request === state.tokenRequest) toast(error.message); }
  finally { if (request === state.tokenRequest) $("refresh-tokens").disabled = false; }
}

function switchView(view) {
  state.view = view;
  for (const button of document.querySelectorAll("[data-view]")) {
    const active = button.dataset.view === view; button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  }
  $("outlets-view").hidden = view !== "outlets"; $("tokens-view").hidden = view !== "tokens";
  if (view === "tokens") loadTokens();
}

$("connect-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const button = event.submitter; button.disabled = true; $("login-error").textContent = "";
  state.generation += 1; state.token = $("token-input").value;
  try {
    const collection = await api("/api/v1/outlets");
    $("login-view").hidden = true; $("authenticated").hidden = false; renderOutlets(collection); switchView("outlets");
  } catch (error) { if (state.token) { state.token = ""; $("login-error").textContent = error.message; } }
  finally { button.disabled = false; }
});

$("disconnect").addEventListener("click", () => disconnect());
$("refresh-outlets").addEventListener("click", loadOutlets);
$("refresh-tokens").addEventListener("click", loadTokens);
for (const button of document.querySelectorAll("[data-view]")) button.addEventListener("click", () => switchView(button.dataset.view));

$("open-create-token").addEventListener("click", () => { $("create-error").textContent = ""; $("create-token-dialog").showModal(); $("token-label").focus(); });
$("cancel-create").addEventListener("click", () => $("create-token-dialog").close());
$("close-create-title").addEventListener("click", () => $("create-token-dialog").close());
$("all-outlets").addEventListener("change", () => {
  $("token-outlets").disabled = $("all-outlets").checked;
  if (!$("token-outlets").disabled) $("token-outlets").focus();
});
$("create-token-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  if (!button || button.type !== "submit" || button.disabled) return;
  button.disabled = true;
  let outlets = null;
  if (!$("all-outlets").checked) {
    outlets = $("token-outlets").value.split(/\s+/u).filter(Boolean);
    if (outlets.length > 256 || new Set(outlets).size !== outlets.length || outlets.some((id) => !/^[A-Za-z0-9_-]{22}$/u.test(id))) {
      $("create-error").textContent = "Use at most 256 unique, 22-character opaque outlet IDs.";
      button.disabled = false;
      return;
    }
    outlets.sort();
  }
  const payload = { label: $("token-label").value, scope: $("token-scope").value };
  if (outlets !== null) payload.outlets = outlets;
  try {
    const created = await api("/api/v1/tokens", { method: "POST", body: JSON.stringify(payload) });
    $("create-token-dialog").close(); $("create-token-form").reset(); $("token-outlets").disabled = true; $("token-outlets").value = ""; setText("new-token-secret", created.token); $("copy-state").textContent = ""; $("token-secret-dialog").showModal(); await loadTokens();
  } catch (error) { $("create-error").textContent = error.message; }
  finally { button.disabled = false; }
});
$("copy-secret").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("new-token-secret").textContent); setText("copy-state", "Copied to clipboard."); }
  catch { setText("copy-state", "Copy was blocked. Select and copy the value manually."); }
});
function clearOneTimeSecret() {
  setText("new-token-secret", "");
  setText("copy-state", "");
}
$("token-secret-dialog").addEventListener("close", clearOneTimeSecret);
$("close-secret").addEventListener("click", () => $("token-secret-dialog").close());
window.addEventListener("pagehide", () => { state.token = ""; $("token-input").value = ""; clearOneTimeSecret(); });

fetch("/api/v1/health", { cache: "no-store" }).then((response) => { if (!response.ok) throw new Error(); setText("health-label", "Adapter ready"); }).catch(() => setText("health-label", "Adapter unavailable"));
