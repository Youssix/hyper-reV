const BASE_URL = "http://127.0.0.1:9742";

interface ApiResponse {
  ok: boolean;
  data?: any;
  error?: string;
}

async function apiGet(path: string): Promise<ApiResponse> {
  const res = await fetch(`${BASE_URL}${path}`);
  return res.json() as Promise<ApiResponse>;
}

async function apiPost(path: string, body: Record<string, unknown> = {}): Promise<ApiResponse> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json() as Promise<ApiResponse>;
}

export async function getStatus(): Promise<ApiResponse> {
  return apiGet("/api/status");
}

export async function listProcesses(): Promise<ApiResponse> {
  return apiGet("/api/processes");
}

export async function attachProcess(nameOrPid: string): Promise<ApiResponse> {
  const pid = parseInt(nameOrPid, 10);
  if (!isNaN(pid)) {
    return apiPost("/api/attach", { pid });
  }
  return apiPost("/api/attach", { name: nameOrPid });
}

export async function detachProcess(): Promise<ApiResponse> {
  return apiPost("/api/detach");
}

export async function readMemory(address: string, size: number): Promise<ApiResponse> {
  return apiPost("/api/memory/read", { address, size });
}

export async function writeMemory(address: string, bytes: string): Promise<ApiResponse> {
  return apiPost("/api/memory/write", { address, bytes });
}

export async function readValue(address: string, type: string): Promise<ApiResponse> {
  return apiPost("/api/memory/read_value", { address, type });
}

export async function writeValue(address: string, type: string, value: number | string): Promise<ApiResponse> {
  return apiPost("/api/memory/write_value", { address, type, value });
}

export async function disassemble(address: string, count: number): Promise<ApiResponse> {
  return apiPost("/api/disassemble", { address, count });
}

export async function resolveAddress(address: string): Promise<ApiResponse> {
  return apiPost("/api/resolve_address", { address });
}

export async function listModules(): Promise<ApiResponse> {
  return apiGet("/api/modules");
}

export async function findExport(name: string, module?: string): Promise<ApiResponse> {
  const body: Record<string, unknown> = { name };
  if (module) body.module = module;
  return apiPost("/api/modules/find_export", body);
}

export async function startCodeFilter(address: string): Promise<ApiResponse> {
  return apiPost("/api/code_filter/start", { address });
}

export async function stopCodeFilter(): Promise<ApiResponse> {
  return apiPost("/api/code_filter/stop");
}

export async function getCodeFilterResults(): Promise<ApiResponse> {
  return apiGet("/api/code_filter/results");
}

export async function addBreakpoint(address: string, label?: string): Promise<ApiResponse> {
  const body: Record<string, unknown> = { address };
  if (label) body.label = label;
  return apiPost("/api/breakpoints/add", body);
}

export async function removeBreakpoint(address: string): Promise<ApiResponse> {
  return apiPost("/api/breakpoints/remove", { address });
}

export async function listBreakpoints(): Promise<ApiResponse> {
  return apiGet("/api/breakpoints");
}

export async function getBreakpointLogs(limit: number = 200): Promise<ApiResponse> {
  return apiGet(`/api/breakpoints/logs?limit=${limit}`);
}

// --- Function Filter ---

export async function ffLoadFunctions(module: string, source: string): Promise<ApiResponse> {
  return apiPost("/api/func_filter/load", { module, source });
}

export async function ffStartMonitoring(): Promise<ApiResponse> {
  return apiPost("/api/func_filter/start");
}

export async function ffStopMonitoring(): Promise<ApiResponse> {
  return apiPost("/api/func_filter/stop");
}

export async function ffKeepExecuted(): Promise<ApiResponse> {
  return apiPost("/api/func_filter/keep_executed");
}

export async function ffRemoveExecuted(): Promise<ApiResponse> {
  return apiPost("/api/func_filter/remove_executed");
}

export async function ffStatus(): Promise<ApiResponse> {
  return apiGet("/api/func_filter/status");
}

export async function ffGetFunctions(limit: number = 500): Promise<ApiResponse> {
  return apiGet(`/api/func_filter/functions?limit=${limit}`);
}
