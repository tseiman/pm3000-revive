const fs = require("fs");
const vm = require("vm");
const scenario = process.argv[3];
if (!["bootstrap", "save", "stale", "ca", "renew", "teardown", "german"].includes(scenario)) throw new Error("scenario required");

class Element {
  constructor(id = "") {
    this.id = id; this.disabled = false; this.value = ""; this.textContent = "";
    this.hidden = false; this.open = false; this.checked = false; this.files = [];
    this.dataset = {}; this.style = { setProperty() {} }; this.listeners = {}; this.firstChild = null;
  }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  appendChild(child) { this.firstChild ||= child; } append(...children) { if (children.length) this.firstChild ||= children[0]; }
  removeChild() { this.firstChild = null; } setAttribute() {} removeAttribute() {} focus() {}
  reset() { this.value = ""; this.files = []; if (this.id === "acme-ca-form") { get("acme-ca-file").value = ""; get("acme-ca-file").files = []; } }
  close() { this.open = false; } showModal() { this.open = true; }
  querySelector() { return get("__submit"); }
}
const elements = new Map();
const get = (id) => elements.get(id) || (elements.set(id, new Element(id)), elements.get(id));
const document = {
  getElementById: get, querySelector() { return null; }, querySelectorAll() { return []; },
  createElement() { return new Element(); }, documentElement: new Element("documentElement")
};
const calls = [];
const pending = [];
const timers = [];
const revA = `"${"a".repeat(64)}"`; const revB = `"${"b".repeat(64)}"`;
let current = scenario === "bootstrap"
  ? { configured: false, caInstalled: false, renewal: { state: "never_run" } }
  : { enabled: true, directoryUrl: "https://acme.example/directory", caFile: "/etc/ssl/ca.pem", dnsNames: ["pdu.example"], revision: revA, renewal: { state: "never_run" } };
function response(status, payload = null) { return { status, ok: status >= 200 && status < 300, json: async () => payload }; }
function deferred(path, method, options) { return new Promise((resolve) => pending.push({ path, method, options, resolve })); }
function fetch(path, options = {}) {
  const method = options.method || "GET"; calls.push({ path, method, headers: Object.fromEntries(new Headers(options.headers || {})), body: options.body });
  if (path === "/api/v1/health") return Promise.resolve(response(200, { status: "live" }));
  if (path === "/api/v1/session") return Promise.resolve(response(401, { code: "unauthorized", message: "none" }));
  if (path === "/api/v1/settings/acme") {
    if (method === "GET" && scenario === "renew" && calls.filter((c) => c.path === path && c.method === "GET").length > 1) {
      current = { ...current, renewal: { state: "failed", phase: "directory", reason: "tls" } }; return Promise.resolve(response(200, current));
    }
    if (method === "GET" && calls.filter((c) => c.path === path && c.method === "GET").length === 1) return Promise.resolve(response(200, current));
    return deferred(path, method, options);
  }
  if (path === "/api/v1/settings/acme/ca" || path === "/api/v1/settings/acme/renew") return deferred(path, method, options);
  return Promise.resolve(response(500, { message: "unexpected" }));
}
const languageList = scenario === "german" ? ["fr-FR", "de-DE", "en-US"] : ["en-US"];
const context = {
  console, require, fetch, document, Headers, TextEncoder, Intl, Promise,
  navigator: { languages: languageList, language: languageList[0], clipboard: { writeText: async () => {} } },
  setTimeout(fn) { timers.push(fn); return timers.length; }, clearTimeout() {},
  window: { confirm: () => true, setTimeout(fn) { timers.push(fn); return timers.length; }, clearTimeout() {} }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context, { filename: process.argv[2] });
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function settle(item, status, payload = null) { item.resolve(response(status, payload)); for (let index = 0; index < 8; index += 1) await tick(); }

(async () => {
  await tick(); await tick();
  vm.runInContext(`state.session={identity:{username:'u'},navigation:{paths:[],canManageTokens:false,canControlPower:false,canManageAcme:true}};state.csrf='csrf';renderNavigation();`, context);
  if (get("save-acme").disabled !== true) throw new Error("ACME form was initially editable");
  await vm.runInContext("loadAcmeSetting()", context);
  if (scenario !== "bootstrap" && (get("save-acme").disabled || get("acme-ca-file").disabled || get("acme-renew").disabled)) throw new Error("fresh GET did not enable controls");
  if (scenario === "bootstrap") {
    if (get("acme-directory-url").disabled || get("acme-dns-names").disabled || get("acme-ca-file").disabled || !get("save-acme").disabled || !get("acme-renew").disabled) throw new Error("first-run controls are not correctly gated");
    if (get("acme-directory-url").value || get("acme-dns-names").value || get("acme-ca-path").textContent) throw new Error("first-run UI invented operational values");
    get("acme-directory-url").value = "https://operator.example/directory"; get("acme-dns-names").value = "pdu.operator.example";
    get("acme-enabled").checked = true;
    const bytes = Uint8Array.from([45, 45, 45]); get("acme-ca-file").files = [{ size: bytes.length, arrayBuffer: async () => bytes.buffer }];
    get("acme-ca-form").listeners.submit[0]({ preventDefault() {} }); await tick(); await tick();
    const caPut = pending.find((item) => item.path.endsWith("/ca")); if (!caPut) throw new Error("first-run CA PUT missing");
    if (new Headers(caPut.options.headers).get("If-None-Match") !== "*" || new Headers(caPut.options.headers).has("If-Match")) throw new Error("first-run CA precondition wrong");
    await settle(caPut, 204); const caRead = pending.find((item) => item.method === "GET"); current = { ...current, caInstalled: true }; await settle(caRead, 200, current);
    if (get("save-acme").disabled) throw new Error("CA readback did not enable first-run save");
    get("acme-form").listeners.submit[0]({ preventDefault() {} }); await tick();
    const configPut = pending.find((item) => item.path === "/api/v1/settings/acme" && item.method === "PUT"); if (!configPut) throw new Error("first-run config PUT missing");
    if (new Headers(configPut.options.headers).get("If-None-Match") !== "*" || new Headers(configPut.options.headers).has("If-Match")) throw new Error("first-run config precondition wrong");
    if (JSON.parse(configPut.options.body).enabled !== true) throw new Error("explicit first-run enabled choice was not preserved");
    await settle(configPut, 204); const configRead = pending.filter((item) => item.method === "GET").at(-1);
    current = { enabled: true, directoryUrl: "https://operator.example/directory", caFile: "/mnt/hdUser/pm3000-revive/acme/trust/managed-ca.pem", dnsNames: ["pdu.operator.example"], revision: revB, renewal: { state: "never_run" } };
    await settle(configRead, 200, current);
    if (get("save-acme").disabled || get("acme-renew").disabled) throw new Error("configured readback did not complete bootstrap");
  } else if (scenario === "german") {
    if (document.documentElement.lang !== "de" || !/geladen|erneuern/i.test(get("acme-status").textContent + get("acme-renew").textContent)) throw new Error("German locale not applied");
  } else if (scenario === "save" || scenario === "stale") {
    get("acme-directory-url").value = "https://new.example/directory"; get("acme-dns-names").value = "pdu.example\nalt.example";
    get("acme-form").listeners.submit[0]({ preventDefault() {} }); await tick();
    const put = pending.find((item) => item.method === "PUT" && item.path === "/api/v1/settings/acme"); if (!put) throw new Error("save PUT missing");
    get("reload-acme").listeners.click[0]({}); get("acme-form").listeners.submit[0]({ preventDefault() {} }); get("disconnect").listeners.click[0]({}); await tick();
    if (calls.filter((c) => c.path === put.path && c.method === "PUT").length !== 1) throw new Error("save not single-flight");
    if (scenario === "stale") {
      await settle(put, 412, { code: "revision_changed", message: "stale" });
      if (!get("save-acme").disabled || calls.filter((c) => c.path === put.path && c.method === "GET").length !== 1) throw new Error("stale write auto-reloaded or enabled");
      get("reload-acme").listeners.click[0]({}); await tick(); const read = pending.find((item) => item.method === "GET"); current = { ...current, revision: revB }; await settle(read, 200, current);
      if (get("save-acme").disabled) throw new Error("deliberate reload did not recover");
    } else {
      await settle(put, 204); const read = pending.find((item) => item.method === "GET");
      if (!read || !get("reload-acme").disabled) throw new Error("post-write readback was not locked");
      get("reload-acme").listeners.click[0]({}); get("acme-form").listeners.submit[0]({ preventDefault() {} }); await tick();
      current = { ...current, revision: revB }; await settle(read, 200, current);
      if (get("save-acme").disabled) throw new Error(`post-write readback did not unlock: status=${get("acme-status").textContent} error=${get("acme-error").textContent} state=${vm.runInContext("JSON.stringify({generation:state.generation,request:state.acmeRequest,pending:state.acmeMutationPending,revision:state.acmeRevision,session:!!state.session})", context)}`);
    }
  } else if (scenario === "ca") {
    get("acme-ca-file").value = "empty.pem"; get("acme-ca-file").files = [{ size: 0, arrayBuffer: async () => new ArrayBuffer(0) }];
    get("acme-ca-form").listeners.submit[0]({ preventDefault() {} }); await tick();
    if (get("acme-ca-file").value !== "" || get("acme-ca-file").files.length !== 0 || pending.some((item) => item.path.endsWith("/ca"))) throw new Error("empty CA file was not rejected and cleared");
    get("acme-ca-file").value = "large.pem"; get("acme-ca-file").files = [{ size: 65537, arrayBuffer: async () => new ArrayBuffer(65537) }];
    get("acme-ca-form").listeners.submit[0]({ preventDefault() {} }); await tick();
    if (get("acme-ca-file").value !== "" || get("acme-ca-file").files.length !== 0 || pending.some((item) => item.path.endsWith("/ca"))) throw new Error("oversize CA file was not rejected and cleared");
    const bytes = Uint8Array.from([45, 45, 45]); get("acme-ca-file").files = [{ size: bytes.length, arrayBuffer: async () => bytes.buffer }];
    get("acme-ca-form").listeners.submit[0]({ preventDefault() {} }); await tick(); await tick();
    const put = pending.find((item) => item.path.endsWith("/ca")); if (!put) throw new Error("CA PUT missing");
    if (new Headers(put.options.headers).get("Content-Type") !== "application/x-pem-file" || Object.prototype.toString.call(put.options.body) !== "[object Uint8Array]") throw new Error("CA body/media type wrong");
    await settle(put, 204); const read = pending.find((item) => item.method === "GET"); current = { ...current, caFile: "/managed/ca.pem", revision: revB }; await settle(read, 200, current);
    if (get("acme-ca-file").value !== "" || get("acme-ca-path").textContent !== "/managed/ca.pem") throw new Error("CA readback/clear failed");
  } else if (scenario === "renew") {
    get("acme-renew").listeners.click[0]({}); await tick(); const post = pending.find((item) => item.path.endsWith("/renew")); if (!post || post.options.body) throw new Error("zero-body renewal missing");
    await settle(post, 202); if (!/started/i.test(get("acme-renewal-note").textContent)) throw new Error("202 was not described as started");
    while (timers.length) { timers.shift()(); await tick(); await tick(); }
    if (!/failed/i.test(get("acme-renewal-status").textContent)) throw new Error("renewal status not refreshed");
    if (/started/i.test(get("acme-renewal-note").textContent) || !/directory \/ tls/i.test(get("acme-renewal-note").textContent)) throw new Error("terminal failure retained stale startup text or omitted diagnostics");
  } else if (scenario === "teardown") {
    vm.runInContext("disconnectLocal()", context);
    if (get("acme-ca-path").textContent || get("acme-dns-names").value || !get("save-acme").disabled) throw new Error("ACME state survived teardown");
  }
  console.log(JSON.stringify({ scenario, passed: true }));
})().catch((error) => { console.error(error.stack); process.exitCode = 1; });