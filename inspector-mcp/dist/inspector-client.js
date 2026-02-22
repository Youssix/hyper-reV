const BASE_URL = "http://127.0.0.1:9742";
async function apiGet(path) {
    const res = await fetch(`${BASE_URL}${path}`);
    return res.json();
}
async function apiPost(path, body = {}) {
    const res = await fetch(`${BASE_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    return res.json();
}
export async function getStatus() {
    return apiGet("/api/status");
}
export async function listProcesses() {
    return apiGet("/api/processes");
}
export async function attachProcess(nameOrPid) {
    const pid = parseInt(nameOrPid, 10);
    if (!isNaN(pid)) {
        return apiPost("/api/attach", { pid });
    }
    return apiPost("/api/attach", { name: nameOrPid });
}
export async function detachProcess() {
    return apiPost("/api/detach");
}
export async function readMemory(address, size) {
    return apiPost("/api/memory/read", { address, size });
}
export async function writeMemory(address, bytes) {
    return apiPost("/api/memory/write", { address, bytes });
}
export async function readValue(address, type) {
    return apiPost("/api/memory/read_value", { address, type });
}
export async function writeValue(address, type, value) {
    return apiPost("/api/memory/write_value", { address, type, value });
}
export async function disassemble(address, count) {
    return apiPost("/api/disassemble", { address, count });
}
export async function resolveAddress(address) {
    return apiPost("/api/resolve_address", { address });
}
export async function listModules() {
    return apiGet("/api/modules");
}
export async function findExport(name, module) {
    const body = { name };
    if (module)
        body.module = module;
    return apiPost("/api/modules/find_export", body);
}
export async function startCodeFilter(address) {
    return apiPost("/api/code_filter/start", { address });
}
export async function stopCodeFilter() {
    return apiPost("/api/code_filter/stop");
}
export async function getCodeFilterResults() {
    return apiGet("/api/code_filter/results");
}
export async function addBreakpoint(address, label) {
    const body = { address };
    if (label)
        body.label = label;
    return apiPost("/api/breakpoints/add", body);
}
export async function removeBreakpoint(address) {
    return apiPost("/api/breakpoints/remove", { address });
}
export async function listBreakpoints() {
    return apiGet("/api/breakpoints");
}
export async function getBreakpointLogs(limit = 200) {
    return apiGet(`/api/breakpoints/logs?limit=${limit}`);
}
// --- Function Filter ---
export async function ffLoadFunctions(module, source) {
    return apiPost("/api/func_filter/load", { module, source });
}
export async function ffStartMonitoring() {
    return apiPost("/api/func_filter/start");
}
export async function ffStopMonitoring() {
    return apiPost("/api/func_filter/stop");
}
export async function ffKeepExecuted() {
    return apiPost("/api/func_filter/keep_executed");
}
export async function ffRemoveExecuted() {
    return apiPost("/api/func_filter/remove_executed");
}
export async function ffStatus() {
    return apiGet("/api/func_filter/status");
}
export async function ffGetFunctions(limit = 500) {
    return apiGet(`/api/func_filter/functions?limit=${limit}`);
}
