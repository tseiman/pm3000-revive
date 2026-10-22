const fs = require("fs");
const vm = require("vm");
const setting = process.argv[3];
const outcome = process.argv[4] || "pending";
if (!["help-language", "data-buffering", "appliance-logging", "time-zone"].includes(setting)) throw new Error("setting argument required");
if (!["pending", "unknown"].includes(outcome)) throw new Error("outcome must be pending or unknown");
const endpoint = `/api/v1/settings/${setting}`;
const stem = setting;
const formId = `${stem}-form`;
const reloadId = `reload-${stem}`;
const saveId = `save-${stem}`;
const loader = setting === "help-language" ? "loadHelpLanguageSetting()" : setting === "data-buffering" ? "loadDataBufferingSetting()" : setting === "appliance-logging" ? "loadApplianceLoggingSetting()" : "loadTimeZoneSetting()";

class Element {
  constructor(id = "") {
    this.id = id; this.disabled = false; this.value = ""; this.valueAsNumber = 0;
    this.textContent = ""; this.hidden = false; this.open = false; this.checked = false;
    this.dataset = {}; this.style = {}; this.listeners = {}; this.firstChild = null;
  }
  addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
  appendChild() {} append() {} removeChild() { this.firstChild = null; }
  setAttribute() {} removeAttribute() {} focus() {} reset() {}
  close() { this.open = false; for (const listener of this.listeners.close || []) listener({}); }
  showModal() { this.open = true; }
  querySelector() { return elements.get("__submit") || make("__submit"); }
}

const elements = new Map();
function make(id) { const element = new Element(id); elements.set(id, element); return element; }
const document = {
  getElementById(id) { return elements.get(id) || make(id); },
  querySelector() { return null; },
  querySelectorAll() { return []; },
  createElement() { return new Element(); },
  documentElement: new Element("documentElement")
};
const pendingPuts = [];
const pendingReadbacks = [];
const calls = [];
let putSettled = false;
function response(status, payload) { return { status, ok: status >= 200 && status < 300, json: async () => payload }; }
function fetch(path, options = {}) {
  const method = options.method || "GET";
  calls.push({ path, method, body: options.body });
  if (path === "/api/v1/health") return Promise.resolve(response(200, { status: "live" }));
  if (path === "/api/v1/session") return Promise.resolve(response(401, { code: "unauthorized", message: "none" }));
  if (path === endpoint && method === "GET") {
    const payload = setting === "help-language"
      ? { applianceLanguage: "en", url: "https://help.example", allowedLanguages: ["en"], revision: `"${"a".repeat(64)}"` }
      : setting === "data-buffering"
        ? { localSize: 1024, localSegments: 4, nfsServer: "nfs.example", nfsPath: "/buffer", nfsSize: 4096, nfsSegments: 8, syslogFacility: "LOG_LOCAL2", revision: `"${"b".repeat(64)}"` }
        : setting === "appliance-logging"
          ? { sessionLoggingEnabled: true, destination: "local", timestampEnabled: true, alertsEnabled: false, alertStrings: Array(10).fill(""), allowedDestinations: ["local", "nfs", "syslog", "dsview"], revision: `"${"c".repeat(64)}"` }
          : { mode: "predefined", predefined: { selected: "UTC", choices: ["UTC", "Europe/Berlin"] }, custom: { name: "Example", standardAcronym: "EX", gmtOffset: "-7:00", dst: { enabled: false, acronym: "EDT", saveTime: "1:00", start: { month: "3", week: "2", weekday: "1", hour: "2:00" }, end: { month: "11", week: "1", weekday: "1", hour: "2:00" } } }, revision: `"${"d".repeat(64)}"` };
    if (putSettled) return new Promise((resolve) => pendingReadbacks.push({ resolve, payload }));
    return Promise.resolve(response(200, payload));
  }
  if (path === endpoint && method === "PUT") {
    return new Promise((resolve) => pendingPuts.push({ resolve(value) { putSettled = true; resolve(value); } }));
  }
  return Promise.resolve(response(500, { message: "unexpected" }));
}

const context = {
  console, require, fetch, document, Headers, TextEncoder, Intl, setTimeout, clearTimeout,
  window: { confirm: () => true, setTimeout, clearTimeout },
  navigator: { clipboard: { writeText: async () => {} } }, Promise
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context, { filename: process.argv[2] });
const tick = () => new Promise((resolve) => setImmediate(resolve));

(async () => {
  await tick(); await tick();
  vm.runInContext("state.session={identity:{username:'u'},navigation:{paths:[],canManageTokens:false,canControlPower:false}}; state.csrf='csrf';", context);
  await vm.runInContext(loader, context);
  const form = elements.get(formId);
  form.listeners.submit[0]({ preventDefault() {} });
  await tick();
  if (pendingPuts.length !== 1) throw new Error("first PUT did not start");
  if (!elements.get(reloadId).disabled) throw new Error("reload remained enabled during PUT");
  await vm.runInContext(loader, context);
  if (!elements.get(saveId).disabled) throw new Error("programmatic reload re-enabled save during PUT");
  form.listeners.submit[0]({ preventDefault() {} });
  await tick();
  elements.get("disconnect").listeners.click[0]({});
  await tick();
  if (outcome === "unknown") {
    pendingPuts[0].resolve(response(503, { code: "action_outcome_unknown", message: "The write outcome is unknown." }));
    await tick(); await tick(); await tick();
    if (pendingReadbacks.length !== 1) throw new Error("post-write readback did not start");
    if (!elements.get(reloadId).disabled) throw new Error("reload enabled before readback completed");
    await vm.runInContext(loader, context);
    form.listeners.submit[0]({ preventDefault() {} });
    elements.get("disconnect").listeners.click[0]({});
    await tick();
    if (calls.filter((call) => call.path === endpoint && call.method === "GET").length !== 2) throw new Error("reload started during readback");
    if (calls.filter((call) => call.path === endpoint && call.method === "PUT").length !== 1) throw new Error("second PUT started during readback");
    if (calls.some((call) => call.path === "/api/v1/session" && call.method === "DELETE")) throw new Error("logout started during readback");
    pendingReadbacks[0].resolve(response(200, pendingReadbacks[0].payload));
    await tick(); await tick(); await tick();
  }
  const settingsCalls = calls.filter((call) => call.path === endpoint);
  const logoutCalls = calls.filter((call) => call.path === "/api/v1/session" && call.method === "DELETE");
  console.log(JSON.stringify({ setting, outcome, pendingPuts: pendingPuts.length, settingsCalls, logoutCalls }));
  const expectedGets = outcome === "unknown" ? 2 : 1;
  if (pendingPuts.length !== 1 || settingsCalls.filter((call) => call.method === "PUT").length !== 1 ||
      settingsCalls.filter((call) => call.method === "GET").length !== expectedGets || logoutCalls.length !== 0) process.exitCode = 2;
})();
