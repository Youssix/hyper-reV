#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as client from "./inspector-client.js";
const server = new McpServer({
    name: "hyperrev-inspector",
    version: "1.0.0",
});
function formatResponse(res) {
    if (!res.ok) {
        return `Error: ${res.error || "Unknown error"}`;
    }
    if (res.data === undefined || res.data === null) {
        return "OK";
    }
    if (typeof res.data === "string") {
        return res.data;
    }
    return JSON.stringify(res.data, null, 2);
}
// --- Status ---
server.tool("get_status", "Get HyperREV Inspector status: hypervisor connection state and attached process info", {}, async () => {
    const res = await client.getStatus();
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Process Management ---
server.tool("list_processes", "List all running processes visible to the hypervisor. Returns PID, name, CR3, base address.", {}, async () => {
    const res = await client.listProcesses();
    if (res.ok && Array.isArray(res.data)) {
        const lines = res.data.map((p) => `${String(p.pid).padStart(6)}  ${p.name.padEnd(30)}  Base: ${p.base}  CR3: ${p.cr3}`);
        return {
            content: [{ type: "text", text: `Processes (${res.data.length}):\n${lines.join("\n")}` }],
        };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("attach_process", "Attach to a process by name (substring match) or PID. Required before memory operations.", { process: z.string().describe("Process name (substring) or PID number") }, async ({ process }) => {
    const res = await client.attachProcess(process);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Memory Operations ---
server.tool("read_memory", "Read raw memory from the attached process. Returns hex dump with ASCII. Use for examining data structures, strings, vtables.", {
    address: z.string().describe("Virtual address in hex (e.g. '7FF6A1B20000')"),
    size: z.number().optional().default(256).describe("Bytes to read (max 4096)"),
}, async ({ address, size }) => {
    const res = await client.readMemory(address, size);
    if (res.ok && res.data?.hex_dump) {
        return { content: [{ type: "text", text: res.data.hex_dump }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("write_memory", "Write raw bytes to memory in the attached process. Bytes as hex string (e.g. '90909090' for NOPs).", {
    address: z.string().describe("Virtual address in hex"),
    bytes: z.string().describe("Hex byte string to write (e.g. '4831C0C3' for xor rax,rax; ret)"),
}, async ({ address, bytes }) => {
    const res = await client.writeMemory(address, bytes);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("read_value", "Read a typed value from memory. Types: int8, uint8, int16, uint16, int32, uint32, int, float, double, uint64, ptr64.", {
    address: z.string().describe("Virtual address in hex"),
    type: z.string().optional().default("uint64").describe("Value type"),
}, async ({ address, type }) => {
    const res = await client.readValue(address, type);
    if (res.ok && res.data) {
        return {
            content: [{
                    type: "text",
                    text: `[${res.data.address}] (${res.data.type}) = ${res.data.value}${res.data.value_decimal !== undefined ? ` (${res.data.value_decimal})` : ""}`,
                }],
        };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("write_value", "Write a typed value to memory.", {
    address: z.string().describe("Virtual address in hex"),
    type: z.string().describe("Value type (int32, float, uint64, etc.)"),
    value: z.union([z.number(), z.string()]).describe("Value to write (number or hex string for uint64)"),
}, async ({ address, type, value }) => {
    const res = await client.writeValue(address, type, value);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Disassembly & Resolution ---
server.tool("disassemble", "Disassemble instructions at an address. Returns IDA-style listing with module+offset, bytes, and Intel syntax.", {
    address: z.string().describe("Virtual address in hex"),
    count: z.number().optional().default(20).describe("Number of instructions (max 200)"),
}, async ({ address, count }) => {
    const res = await client.disassemble(address, count);
    if (res.ok && res.data?.listing) {
        return { content: [{ type: "text", text: res.data.listing }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("resolve_address", "Resolve a virtual address to module+offset and export name (if at an export entry point).", { address: z.string().describe("Virtual address in hex") }, async ({ address }) => {
    const res = await client.resolveAddress(address);
    if (res.ok && res.data) {
        let text = `${res.data.address} => ${res.data.module_address}`;
        if (res.data.export_name)
            text += ` (${res.data.export_name})`;
        return { content: [{ type: "text", text }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Module Operations ---
server.tool("list_modules", "List all loaded modules in the attached process with base address and size.", {}, async () => {
    const res = await client.listModules();
    if (res.ok && Array.isArray(res.data)) {
        const lines = res.data.map((m) => `${m.base}  ${m.size.padStart(10)}  ${m.name}`);
        return {
            content: [{ type: "text", text: `Modules (${res.data.length}):\n${"Base".padEnd(18)}  ${"Size".padStart(10)}  Name\n${lines.join("\n")}` }],
        };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("find_export", "Search for exported functions across all modules (or a specific module). Substring match on export name.", {
    name: z.string().describe("Export name to search for (substring, case-insensitive)"),
    module: z.string().optional().describe("Filter to a specific module name"),
}, async ({ name, module }) => {
    const res = await client.findExport(name, module);
    if (res.ok && Array.isArray(res.data)) {
        const lines = res.data.map((e) => `${e.address}  ${e.module}!${e.name}`);
        return {
            content: [{ type: "text", text: `Exports matching "${name}" (${res.data.length}):\n${lines.join("\n")}` }],
        };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- CodeFilter (Find What Accesses) ---
server.tool("start_code_filter", "Start monitoring a memory address via EPT page monitoring. Collects all instructions (RIPs) that read/write/execute the address. Like CE's 'Find what accesses this address'.", { address: z.string().describe("Virtual address to monitor in hex") }, async ({ address }) => {
    const res = await client.startCodeFilter(address);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("stop_code_filter", "Stop the current CodeFilter monitoring session.", {}, async () => {
    const res = await client.stopCodeFilter();
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("get_code_filter_results", "Get CodeFilter results: all unique instruction addresses that accessed the monitored address, with instruction text, access type (Read/Write/Execute), and hit count.", {}, async () => {
    const res = await client.getCodeFilterResults();
    if (res.ok && res.data) {
        let text = `CodeFilter: monitoring=${res.data.monitoring}, target=${res.data.target_address}, entries=${res.data.count}\n\n`;
        if (res.data.entries && res.data.entries.length > 0) {
            text += `${"RIP".padEnd(30)}  ${"Instruction".padEnd(40)}  ${"Type".padEnd(12)}  Hits\n`;
            text += "-".repeat(90) + "\n";
            for (const e of res.data.entries) {
                text += `${e.module_rip.padEnd(30)}  ${e.instruction.padEnd(40)}  ${e.access_type.padEnd(12)}  ${e.hit_count}\n`;
            }
        }
        else {
            text += "(no accesses recorded yet)";
        }
        return { content: [{ type: "text", text }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Breakpoints (EPT Page Monitoring) ---
server.tool("add_breakpoint", "Add an EPT breakpoint on a virtual address. Monitors the physical page — logs all trap frames (registers + stack) when any code on that page executes.", {
    address: z.string().describe("Virtual address in hex"),
    label: z.string().optional().describe("Human-readable label for this breakpoint"),
}, async ({ address, label }) => {
    const res = await client.addBreakpoint(address, label);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("remove_breakpoint", "Remove an EPT breakpoint by virtual address.", { address: z.string().describe("Virtual address of breakpoint to remove") }, async ({ address }) => {
    const res = await client.removeBreakpoint(address);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("list_breakpoints", "List all EPT breakpoints with their status, hit counts, and page GPA.", {}, async () => {
    const res = await client.listBreakpoints();
    if (res.ok && Array.isArray(res.data)) {
        if (res.data.length === 0) {
            return { content: [{ type: "text", text: "No breakpoints set." }] };
        }
        const lines = res.data.map((bp) => `${bp.active ? "[ON] " : "[OFF]"}  ${bp.address}  Page: ${bp.page_gpa}  Hits: ${bp.hit_count}  ${bp.label}`);
        return {
            content: [{ type: "text", text: `Breakpoints (${res.data.length}):\n${lines.join("\n")}` }],
        };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("get_breakpoint_logs", "Get trap frame logs from EPT breakpoints. Each log entry contains full register state (RAX-R15, RIP, RSP, CR3) and 5 stack values. Most recent entries first.", {
    limit: z.number().optional().default(50).describe("Max number of log entries to return"),
}, async ({ limit }) => {
    const res = await client.getBreakpointLogs(limit);
    if (res.ok && res.data) {
        let text = `Breakpoint logs (${res.data.count} entries):\n\n`;
        if (res.data.logs && res.data.logs.length > 0) {
            for (const log of res.data.logs) {
                text += `RIP: ${log.rip_module}  CR3: ${log.cr3}\n`;
                text += `  RAX=${log.rax} RCX=${log.rcx} RDX=${log.rdx}\n`;
                text += `  R8=${log.r8} R9=${log.r9} RSP=${log.rsp} RBP=${log.rbp}\n`;
                text += `  Stack: ${log.stack.join(" ")}\n\n`;
            }
        }
        else {
            text += "(no logs yet)";
        }
        return { content: [{ type: "text", text }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Function Filter (CE-style function discovery) ---
server.tool("ff_load_functions", "Load function addresses from a module using the specified source. Sources: 'combined' (pdata + CALL scan merged, maximum coverage — RECOMMENDED), 'pdata' (PE exception directory, fast), 'call_scan' (disassemble .text for CALL targets, thorough), 'trace' (EPT execute monitoring, finds everything that runs).", {
    module: z.string().describe("Module name (substring match, e.g. 'ntdll' or 'game.exe')"),
    source: z.enum(["combined", "pdata", "call_scan", "trace"]).describe("Function discovery source (default: combined)"),
}, async ({ module, source }) => {
    const res = await client.ffLoadFunctions(module, source);
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("ff_start_monitoring", "Start EPT monitoring on all loaded function pages. After starting, interact with the target to trigger functions, then use ff_keep_executed or ff_remove_executed to filter.", {}, async () => {
    const res = await client.ffStartMonitoring();
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("ff_stop_monitoring", "Stop EPT monitoring (or trace collection). Preserves the current function list and executed flags.", {}, async () => {
    const res = await client.ffStopMonitoring();
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("ff_keep_executed", "Filter: keep only functions that were executed since last reset. Removes all non-executed functions. Resets executed flags afterwards.", {}, async () => {
    const res = await client.ffKeepExecuted();
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("ff_remove_executed", "Filter: remove functions that were executed since last reset. Keeps only non-executed functions. Resets executed flags afterwards.", {}, async () => {
    const res = await client.ffRemoveExecuted();
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("ff_status", "Get current Function Filter state: phase (idle/loading/loaded/monitoring), source, module, function count, executed count, page count.", {}, async () => {
    const res = await client.ffStatus();
    if (res.ok && res.data?.status) {
        return { content: [{ type: "text", text: res.data.status }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
server.tool("ff_get_functions", "Get the function list with executed status. Returns address, name, and whether each function was executed.", {
    limit: z.number().optional().default(500).describe("Max functions to return (default 500)"),
}, async ({ limit }) => {
    const res = await client.ffGetFunctions(limit);
    if (res.ok && res.data) {
        let text = `Functions (${res.data.count}): ${res.data.status}\n\n`;
        if (res.data.functions && res.data.functions.length > 0) {
            text += `${"Address".padEnd(20)}  ${"Name".padEnd(40)}  Exec\n`;
            text += "-".repeat(65) + "\n";
            for (const fn of res.data.functions) {
                text += `${fn.address.padEnd(20)}  ${fn.name.padEnd(40)}  ${fn.executed ? "*" : ""}\n`;
            }
        }
        else {
            text += "(no functions loaded)";
        }
        return { content: [{ type: "text", text }] };
    }
    return { content: [{ type: "text", text: formatResponse(res) }] };
});
// --- Start server ---
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
