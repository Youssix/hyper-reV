// httplib.h MUST be included first to define WIN32_LEAN_AND_MEAN before windows.h
#include <httplib.h>

#include "http_server.h"
#include "command_queue.h"

#include "../app.h"
#include "../memory/memory_reader.h"
#include "../panels/code_filter.h"
#include "../panels/breakpoints.h"
#include "../panels/function_filter.h"
#include "../widgets/module_resolver.h"
#include "hypercall/hypercall.h"
#include "system/system.h"
#include <structures/trap_frame.h>

#include <Zydis/Zydis.h>
#include <nlohmann/json.hpp>

#include <thread>
#include <print>
#include <cstring>

namespace server
{
	using json = nlohmann::json;

	static httplib::Server* s_server = nullptr;
	static std::thread s_thread;
	static command_queue_t s_queue;

	static json ok_response(json data = nullptr)
	{
		json r = { {"ok", true} };
		if (!data.is_null())
			r["data"] = std::move(data);
		return r;
	}

	static json error_response(const std::string& msg)
	{
		return { {"ok", false}, {"error", msg} };
	}

	// wait on a queued future with timeout
	static json wait_result(std::future<json>& f, int timeout_ms = 5000)
	{
		if (f.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::timeout)
			return error_response("Command timed out (main thread may be blocked)");
		return f.get();
	}

	// parse JSON body from request, returns empty json on failure
	static json parse_body(const httplib::Request& req)
	{
		if (req.body.empty()) return json::object();
		try { return json::parse(req.body); }
		catch (...) { return json::object(); }
	}

	static uint64_t json_uint64(const json& j, const std::string& key, uint64_t def = 0)
	{
		if (!j.contains(key)) return def;
		auto& v = j[key];
		if (v.is_string())
		{
			std::string s = v.get<std::string>();
			return strtoull(s.c_str(), nullptr, 16);
		}
		if (v.is_number_unsigned()) return v.get<uint64_t>();
		if (v.is_number_integer()) return (uint64_t)v.get<int64_t>();
		return def;
	}

	// ---- Route handlers ----

	static void route_status(const httplib::Request&, httplib::Response& res)
	{
		auto& st = app::state();
		json data = {
			{"hv_connected", st.hv_connected},
			{"hv_status", st.hv_status},
			{"process_attached", st.process_attached}
		};
		if (st.process_attached)
		{
			data["process"] = {
				{"name", st.attached_process.name},
				{"pid", st.attached_process.pid},
				{"cr3", std::format("0x{:X}", st.attached_process.cr3)},
				{"base", std::format("0x{:X}", st.attached_process.base_address)},
				{"eprocess", std::format("0x{:X}", st.attached_process.eprocess)}
			};
		}
		res.set_content(ok_response(data).dump(), "application/json");
	}

	static void route_processes(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			auto procs = sys::process::enumerate_processes();
			json arr = json::array();
			for (auto& p : procs)
			{
				arr.push_back({
					{"name", p.name},
					{"pid", p.pid},
					{"cr3", std::format("0x{:X}", p.cr3)},
					{"base", std::format("0x{:X}", p.base_address)},
					{"eprocess", std::format("0x{:X}", p.eprocess)}
				});
			}
			return ok_response(arr);
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_attach(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		std::string name = body.value("name", "");
		uint64_t pid = json_uint64(body, "pid");

		auto f = s_queue.enqueue([name, pid]() -> json {
			auto procs = sys::process::enumerate_processes();
			for (auto& p : procs)
			{
				if (pid && p.pid == pid)
				{
					app::attach_process(p);
					return ok_response({{"name", p.name}, {"pid", p.pid}});
				}
				if (!name.empty())
				{
					// case-insensitive substring match
					std::string pname = p.name;
					std::string target = name;
					std::transform(pname.begin(), pname.end(), pname.begin(), ::tolower);
					std::transform(target.begin(), target.end(), target.begin(), ::tolower);
					if (pname.find(target) != std::string::npos)
					{
						app::attach_process(p);
						return ok_response({{"name", p.name}, {"pid", p.pid}});
					}
				}
			}
			return error_response("Process not found");
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_detach(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			if (!app::state().process_attached)
				return error_response("No process attached");
			app::detach_process();
			return ok_response();
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	// ---- Direct (thread-safe) memory routes ----

	static void route_memory_read(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");
		int size = body.value("size", 256);

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}
		if (size <= 0 || size > 4096) size = 256;

		uint64_t cr3 = memory::get_cr3();
		if (!cr3)
		{
			res.set_content(error_response("No process attached").dump(), "application/json");
			return;
		}

		std::vector<uint8_t> buf(size);
		uint64_t ok = hypercall::read_guest_virtual_memory(buf.data(), address, cr3, size);

		if (!ok)
		{
			res.set_content(error_response("Read failed").dump(), "application/json");
			return;
		}

		// format as hex dump
		std::string hex_dump;
		for (int i = 0; i < size; i += 16)
		{
			hex_dump += std::format("{:016X}  ", address + i);

			// hex bytes
			for (int j = 0; j < 16 && (i + j) < size; j++)
			{
				hex_dump += std::format("{:02X} ", buf[i + j]);
				if (j == 7) hex_dump += " ";
			}

			// pad if last line is short
			int remaining = size - i;
			if (remaining < 16)
			{
				for (int j = remaining; j < 16; j++)
				{
					hex_dump += "   ";
					if (j == 7) hex_dump += " ";
				}
			}

			// ASCII
			hex_dump += " |";
			for (int j = 0; j < 16 && (i + j) < size; j++)
			{
				uint8_t b = buf[i + j];
				hex_dump += (b >= 0x20 && b < 0x7F) ? (char)b : '.';
			}
			hex_dump += "|\n";
		}

		json data = {
			{"address", std::format("0x{:X}", address)},
			{"size", size},
			{"hex_dump", hex_dump}
		};
		// also include raw bytes as hex string
		std::string raw_hex;
		for (int i = 0; i < size; i++)
			raw_hex += std::format("{:02X}", buf[i]);
		data["bytes"] = raw_hex;

		res.set_content(ok_response(data).dump(), "application/json");
	}

	static void route_memory_write(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");
		std::string bytes_hex = body.value("bytes", "");

		if (!address || bytes_hex.empty())
		{
			res.set_content(error_response("Missing address or bytes").dump(), "application/json");
			return;
		}

		uint64_t cr3 = memory::get_cr3();
		if (!cr3)
		{
			res.set_content(error_response("No process attached").dump(), "application/json");
			return;
		}

		// parse hex string
		std::vector<uint8_t> buf;
		for (size_t i = 0; i + 1 < bytes_hex.size(); i += 2)
		{
			uint8_t b = (uint8_t)strtoul(bytes_hex.substr(i, 2).c_str(), nullptr, 16);
			buf.push_back(b);
		}

		if (buf.empty())
		{
			res.set_content(error_response("No valid bytes").dump(), "application/json");
			return;
		}

		uint64_t ok = hypercall::write_guest_virtual_memory(buf.data(), address, cr3, buf.size());

		json data = {
			{"address", std::format("0x{:X}", address)},
			{"bytes_written", (int)buf.size()},
			{"success", ok != 0}
		};
		res.set_content(ok_response(data).dump(), "application/json");
	}

	static void route_memory_read_value(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");
		std::string type = body.value("type", "uint64");

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}

		uint64_t cr3 = memory::get_cr3();
		if (!cr3)
		{
			res.set_content(error_response("No process attached").dump(), "application/json");
			return;
		}

		uint8_t buf[8] = {};
		int read_size = 8;

		if (type == "int8" || type == "uint8" || type == "byte") read_size = 1;
		else if (type == "int16" || type == "uint16" || type == "short") read_size = 2;
		else if (type == "int32" || type == "uint32" || type == "int" || type == "dword") read_size = 4;
		else if (type == "float") read_size = 4;
		else if (type == "double") read_size = 8;
		else read_size = 8; // default ptr64

		if (!hypercall::read_guest_virtual_memory(buf, address, cr3, read_size))
		{
			res.set_content(error_response("Read failed").dump(), "application/json");
			return;
		}

		json data = { {"address", std::format("0x{:X}", address)}, {"type", type} };

		if (type == "float")
		{
			float v; memcpy(&v, buf, 4);
			data["value"] = v;
		}
		else if (type == "double")
		{
			double v; memcpy(&v, buf, 8);
			data["value"] = v;
		}
		else if (type == "int8")   { int8_t v; memcpy(&v, buf, 1); data["value"] = v; }
		else if (type == "int16")  { int16_t v; memcpy(&v, buf, 2); data["value"] = v; }
		else if (type == "int32" || type == "int")  { int32_t v; memcpy(&v, buf, 4); data["value"] = v; }
		else if (type == "uint8" || type == "byte")  { data["value"] = buf[0]; }
		else if (type == "uint16" || type == "short") { uint16_t v; memcpy(&v, buf, 2); data["value"] = v; }
		else if (type == "uint32" || type == "dword") { uint32_t v; memcpy(&v, buf, 4); data["value"] = v; }
		else
		{
			uint64_t v; memcpy(&v, buf, 8);
			data["value"] = std::format("0x{:X}", v);
			data["value_decimal"] = v;
		}

		res.set_content(ok_response(data).dump(), "application/json");
	}

	static void route_memory_write_value(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");
		std::string type = body.value("type", "uint64");

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}

		uint64_t cr3 = memory::get_cr3();
		if (!cr3)
		{
			res.set_content(error_response("No process attached").dump(), "application/json");
			return;
		}

		uint8_t buf[8] = {};
		int write_size = 8;

		if (type == "float")
		{
			float v = body.value("value", 0.0f);
			memcpy(buf, &v, 4);
			write_size = 4;
		}
		else if (type == "double")
		{
			double v = body.value("value", 0.0);
			memcpy(buf, &v, 8);
			write_size = 8;
		}
		else if (type == "int8" || type == "uint8" || type == "byte")
		{
			buf[0] = (uint8_t)body.value("value", 0);
			write_size = 1;
		}
		else if (type == "int16" || type == "uint16" || type == "short")
		{
			uint16_t v = (uint16_t)body.value("value", 0);
			memcpy(buf, &v, 2);
			write_size = 2;
		}
		else if (type == "int32" || type == "uint32" || type == "int" || type == "dword")
		{
			uint32_t v = (uint32_t)body.value("value", 0);
			memcpy(buf, &v, 4);
			write_size = 4;
		}
		else // uint64 / ptr64
		{
			uint64_t v = json_uint64(body, "value");
			memcpy(buf, &v, 8);
			write_size = 8;
		}

		uint64_t ok = hypercall::write_guest_virtual_memory(buf, address, cr3, write_size);
		res.set_content(ok_response({{"success", ok != 0}}).dump(), "application/json");
	}

	static void route_disassemble(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");
		int count = body.value("count", 20);

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}
		if (count <= 0 || count > 200) count = 20;

		uint64_t cr3 = memory::get_cr3();
		if (!cr3)
		{
			res.set_content(error_response("No process attached").dump(), "application/json");
			return;
		}

		// read a block of code
		int read_size = count * 15; // worst case 15 bytes per instruction
		if (read_size > 4096) read_size = 4096;
		std::vector<uint8_t> code(read_size);

		if (!hypercall::read_guest_virtual_memory(code.data(), address, cr3, read_size))
		{
			res.set_content(error_response("Read failed").dump(), "application/json");
			return;
		}

		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

		json instructions = json::array();
		std::string listing;
		uint64_t offset = 0;

		for (int i = 0; i < count && offset < (uint64_t)read_size; i++)
		{
			ZydisDecodedInstruction instr;
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
				code.data() + offset, read_size - (size_t)offset,
				&instr, operands)))
			{
				// bad byte
				uint64_t rip = address + offset;
				std::string mod_addr = widgets::format_address_short(rip);
				std::string line = std::format("{:<30s}  db {:02X}h\n", mod_addr, code[offset]);
				listing += line;
				instructions.push_back({
					{"address", std::format("0x{:X}", rip)},
					{"module_address", mod_addr},
					{"bytes", std::format("{:02X}", code[offset])},
					{"mnemonic", "db"},
					{"text", std::format("db {:02X}h", code[offset])}
				});
				offset++;
				continue;
			}

			uint64_t rip = address + offset;
			char text_buf[128] = {};
			ZydisFormatterFormatInstruction(&formatter, &instr, operands,
				instr.operand_count, text_buf, sizeof(text_buf), rip, nullptr);

			// bytes hex
			std::string bytes_hex;
			for (int b = 0; b < instr.length; b++)
				bytes_hex += std::format("{:02X}", code[offset + b]);

			std::string mod_addr = widgets::format_address_short(rip);
			std::string line = std::format("{:<30s}  {:<24s}  {}\n", mod_addr, bytes_hex, text_buf);
			listing += line;

			instructions.push_back({
				{"address", std::format("0x{:X}", rip)},
				{"module_address", mod_addr},
				{"bytes", bytes_hex},
				{"mnemonic", text_buf},
				{"text", std::string(text_buf)},
				{"length", instr.length}
			});

			offset += instr.length;
		}

		json data = {
			{"address", std::format("0x{:X}", address)},
			{"count", (int)instructions.size()},
			{"listing", listing},
			{"instructions", instructions}
		};
		res.set_content(ok_response(data).dump(), "application/json");
	}

	static void route_resolve_address(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}

		auto f = s_queue.enqueue([address]() -> json {
			std::string mod_str = widgets::format_address_short(address);
			std::string export_name = widgets::resolve_export_name(address);

			json data = {
				{"address", std::format("0x{:X}", address)},
				{"module_address", mod_str}
			};
			if (!export_name.empty())
				data["export_name"] = export_name;

			std::string name;
			uint64_t offset;
			if (widgets::resolve_module(address, name, offset))
			{
				data["module"] = name;
				data["offset"] = std::format("0x{:X}", offset);
			}

			return ok_response(data);
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_modules(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			json arr = json::array();
			for (auto& mod : widgets::g_modules)
			{
				arr.push_back({
					{"name", mod.name},
					{"base", std::format("0x{:X}", mod.base)},
					{"size", std::format("0x{:X}", mod.size)}
				});
			}
			return ok_response(arr);
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_find_export(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		std::string query = body.value("name", "");
		std::string module_name = body.value("module", "");

		if (query.empty())
		{
			res.set_content(error_response("Missing name").dump(), "application/json");
			return;
		}

		auto f = s_queue.enqueue([query, module_name]() -> json {
			json results = json::array();
			std::string query_lower = query;
			std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), ::tolower);

			for (auto& mod : widgets::g_modules)
			{
				if (!module_name.empty())
				{
					std::string mname = mod.name;
					std::transform(mname.begin(), mname.end(), mname.begin(), ::tolower);
					if (mname.find(module_name) == std::string::npos)
						continue;
				}

				// walk PE export table
				uint16_t e_magic = 0;
				memory::read(&e_magic, mod.base, 2);
				if (e_magic != 0x5A4D) continue;

				uint32_t e_lfanew = 0;
				memory::read(&e_lfanew, mod.base + 0x3C, 4);
				if (e_lfanew == 0 || e_lfanew > 0x1000) continue;

				uint32_t export_rva = 0, export_size = 0;
				memory::read(&export_rva, mod.base + e_lfanew + 0x88, 4);
				memory::read(&export_size, mod.base + e_lfanew + 0x8C, 4);
				if (export_rva == 0) continue;

				uint64_t export_dir = mod.base + export_rva;
				uint32_t num_names = 0, addr_table_rva = 0, name_table_rva = 0, ordinal_table_rva = 0;
				memory::read(&num_names, export_dir + 0x18, 4);
				memory::read(&addr_table_rva, export_dir + 0x1C, 4);
				memory::read(&name_table_rva, export_dir + 0x20, 4);
				memory::read(&ordinal_table_rva, export_dir + 0x24, 4);
				uint32_t num_functions = 0;
				memory::read(&num_functions, export_dir + 0x14, 4);

				if (num_names == 0 || num_names > 20000) continue;

				int batch = (int)(num_names < 4096 ? num_names : 4096);
				std::vector<uint32_t> name_rvas(batch);
				std::vector<uint16_t> ordinals(batch);
				memory::read(name_rvas.data(), mod.base + name_table_rva, batch * 4);
				memory::read(ordinals.data(), mod.base + ordinal_table_rva, batch * 2);

				for (int i = 0; i < batch; i++)
				{
					char name_buf[128] = {};
					memory::read(name_buf, mod.base + name_rvas[i], sizeof(name_buf) - 1);
					name_buf[sizeof(name_buf) - 1] = '\0';

					std::string ename(name_buf);
					std::string ename_lower = ename;
					std::transform(ename_lower.begin(), ename_lower.end(), ename_lower.begin(), ::tolower);

					if (ename_lower.find(query_lower) != std::string::npos)
					{
						uint32_t func_rva = 0;
						if (ordinals[i] < num_functions)
							memory::read(&func_rva, mod.base + addr_table_rva + ordinals[i] * 4, 4);

						uint64_t func_va = mod.base + func_rva;
						results.push_back({
							{"module", mod.name},
							{"name", ename},
							{"address", std::format("0x{:X}", func_va)},
							{"rva", std::format("0x{:X}", func_rva)}
						});

						if (results.size() >= 100) break;
					}
				}
				if (results.size() >= 100) break;
			}
			return ok_response(results);
		});
		res.set_content(wait_result(f, 10000).dump(), "application/json");
	}

	// ---- Code filter routes ----

	static void route_code_filter_start(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}

		auto f = s_queue.enqueue([address]() -> json {
			IPanel* panel = app::get_panel(tab_id::code_filter);
			if (!panel) return error_response("CodeFilter panel not found");

			auto* cf = static_cast<CodeFilterPanel*>(panel);
			cf->api_start(address);

			return ok_response({{"monitoring", true}, {"address", std::format("0x{:X}", address)}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_code_filter_stop(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::code_filter);
			if (!panel) return error_response("CodeFilter panel not found");

			auto* cf = static_cast<CodeFilterPanel*>(panel);
			cf->api_stop();

			return ok_response({{"monitoring", false}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_code_filter_results(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::code_filter);
			if (!panel) return error_response("CodeFilter panel not found");

			auto* cf = static_cast<CodeFilterPanel*>(panel);
			bool monitoring = cf->api_is_monitoring();
			uint64_t target = cf->api_target();
			auto entries = cf->api_entries();

			json arr = json::array();
			for (auto& e : entries)
			{
				arr.push_back({
					{"rip", std::format("0x{:X}", e.rip)},
					{"instruction", e.instruction},
					{"module_rip", e.module_rip},
					{"access_type", e.access_type},
					{"hit_count", e.hit_count}
				});
			}

			json data = {
				{"monitoring", monitoring},
				{"target_address", std::format("0x{:X}", target)},
				{"count", (int)entries.size()},
				{"entries", arr}
			};
			return ok_response(data);
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	// ---- Breakpoint routes ----

	static void route_breakpoint_add(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");
		std::string label = body.value("label", "");

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}

		auto f = s_queue.enqueue([address, label]() -> json {
			IPanel* panel = app::get_panel(tab_id::breakpoints);
			if (!panel) return error_response("Breakpoints panel not found");

			auto* bp = static_cast<BreakpointsPanel*>(panel);
			bp->add_breakpoint_public(address, label.empty() ? nullptr : label.c_str());

			return ok_response({{"address", std::format("0x{:X}", address)}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_breakpoint_remove(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		uint64_t address = json_uint64(body, "address");

		if (!address)
		{
			res.set_content(error_response("Missing address").dump(), "application/json");
			return;
		}

		auto f = s_queue.enqueue([address]() -> json {
			IPanel* panel = app::get_panel(tab_id::breakpoints);
			if (!panel) return error_response("Breakpoints panel not found");

			auto* bp_panel = static_cast<BreakpointsPanel*>(panel);
			bp_panel->api_remove(address);

			return ok_response({{"address", std::format("0x{:X}", address)}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_breakpoints_list(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::breakpoints);
			if (!panel) return error_response("Breakpoints panel not found");

			auto* bp_panel = static_cast<BreakpointsPanel*>(panel);
			auto bps = bp_panel->api_list();

			json arr = json::array();
			for (auto& bp : bps)
			{
				arr.push_back({
					{"address", std::format("0x{:X}", bp.virtual_address)},
					{"page_gpa", std::format("0x{:X}", bp.physical_address)},
					{"label", bp.label},
					{"active", bp.active},
					{"hit_count", bp.hit_count}
				});
			}
			return ok_response(arr);
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_breakpoint_logs(const httplib::Request& req, httplib::Response& res)
	{
		int limit = 200;
		if (req.has_param("limit"))
			limit = std::stoi(req.get_param_value("limit"));

		auto f = s_queue.enqueue([limit]() -> json {
			IPanel* panel = app::get_panel(tab_id::breakpoints);
			if (!panel) return error_response("Breakpoints panel not found");

			auto* bp_panel = static_cast<BreakpointsPanel*>(panel);
			auto logs = bp_panel->api_logs(limit);

			json arr = json::array();
			for (auto& log : logs)
			{
				arr.push_back({
					{"rip", std::format("0x{:X}", log.rip)},
					{"cr3", std::format("0x{:X}", log.cr3)},
					{"rax", std::format("0x{:X}", log.rax)},
					{"rcx", std::format("0x{:X}", log.rcx)},
					{"rdx", std::format("0x{:X}", log.rdx)},
					{"r8",  std::format("0x{:X}", log.r8)},
					{"r9",  std::format("0x{:X}", log.r9)},
					{"rsp", std::format("0x{:X}", log.rsp)},
					{"rbp", std::format("0x{:X}", log.rbp)},
					{"rip_module", widgets::format_address_short(log.rip)},
					{"stack", {
						std::format("0x{:X}", log.stack_data[0]),
						std::format("0x{:X}", log.stack_data[1]),
						std::format("0x{:X}", log.stack_data[2]),
						std::format("0x{:X}", log.stack_data[3]),
						std::format("0x{:X}", log.stack_data[4])
					}}
				});
			}

			json data = {
				{"count", (int)logs.size()},
				{"logs", arr}
			};
			return ok_response(data);
		});
		res.set_content(wait_result(f, 10000).dump(), "application/json");
	}

	// ---- Function Filter routes ----

	static void route_func_filter_load(const httplib::Request& req, httplib::Response& res)
	{
		auto body = parse_body(req);
		std::string module_name = body.value("module", "");
		std::string source_str = body.value("source", "pdata");

		if (module_name.empty())
		{
			res.set_content(error_response("Missing module").dump(), "application/json");
			return;
		}

		fn_source_t source = fn_source_t::combined; // default to combined for max coverage
		if (source_str == "pdata") source = fn_source_t::pdata;
		else if (source_str == "call_scan") source = fn_source_t::call_scan;
		else if (source_str == "trace") source = fn_source_t::trace;
		else if (source_str == "combined") source = fn_source_t::combined;

		auto f = s_queue.enqueue([module_name, source, source_str]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			ff->api_load(module_name, source);

			return ok_response({{"module", module_name}, {"source", source_str}});
		});
		res.set_content(wait_result(f, 30000).dump(), "application/json");
	}

	static void route_func_filter_start(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			ff->api_start_monitoring();

			return ok_response({{"status", ff->api_status()}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_func_filter_stop(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			ff->api_stop_monitoring();

			return ok_response({{"status", ff->api_status()}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_func_filter_keep(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			ff->api_keep_executed();

			return ok_response({{"status", ff->api_status()}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_func_filter_remove(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			ff->api_remove_executed();

			return ok_response({{"status", ff->api_status()}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_func_filter_status(const httplib::Request&, httplib::Response& res)
	{
		auto f = s_queue.enqueue([]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			auto fns = ff->api_get_functions(0); // just for counts
			std::string status = ff->api_status();

			return ok_response({{"status", status}});
		});
		res.set_content(wait_result(f).dump(), "application/json");
	}

	static void route_func_filter_functions(const httplib::Request& req, httplib::Response& res)
	{
		int limit = 500;
		if (req.has_param("limit"))
			limit = std::stoi(req.get_param_value("limit"));

		auto f = s_queue.enqueue([limit]() -> json {
			IPanel* panel = app::get_panel(tab_id::function_filter);
			if (!panel) return error_response("FunctionFilter panel not found");

			auto* ff = static_cast<FunctionFilterPanel*>(panel);
			auto fns = ff->api_get_functions(limit);

			json arr = json::array();
			for (auto& fn : fns)
			{
				arr.push_back({
					{"address", std::format("0x{:X}", fn.va)},
					{"name", fn.name},
					{"executed", fn.executed}
				});
			}

			json data = {
				{"count", (int)fns.size()},
				{"status", ff->api_status()},
				{"functions", arr}
			};
			return ok_response(data);
		});
		res.set_content(wait_result(f, 10000).dump(), "application/json");
	}

	// ---- Server lifecycle ----

	void start(int port)
	{
		if (s_server) return;

		s_server = new httplib::Server();

		// CORS headers for any client
		s_server->set_default_headers({
			{"Access-Control-Allow-Origin", "*"},
			{"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
			{"Access-Control-Allow-Headers", "Content-Type"}
		});

		// OPTIONS preflight handler
		s_server->Options(".*", [](const httplib::Request&, httplib::Response& res) {
			res.status = 204;
		});

		// register routes
		s_server->Get("/api/status",             route_status);
		s_server->Get("/api/processes",           route_processes);
		s_server->Post("/api/attach",            route_attach);
		s_server->Post("/api/detach",            route_detach);
		s_server->Post("/api/memory/read",       route_memory_read);
		s_server->Post("/api/memory/write",      route_memory_write);
		s_server->Post("/api/memory/read_value", route_memory_read_value);
		s_server->Post("/api/memory/write_value",route_memory_write_value);
		s_server->Post("/api/disassemble",       route_disassemble);
		s_server->Post("/api/resolve_address",   route_resolve_address);
		s_server->Get("/api/modules",            route_modules);
		s_server->Post("/api/modules/find_export",route_find_export);
		s_server->Post("/api/code_filter/start", route_code_filter_start);
		s_server->Post("/api/code_filter/stop",  route_code_filter_stop);
		s_server->Get("/api/code_filter/results",route_code_filter_results);
		s_server->Post("/api/breakpoints/add",   route_breakpoint_add);
		s_server->Post("/api/breakpoints/remove",route_breakpoint_remove);
		s_server->Get("/api/breakpoints",        route_breakpoints_list);
		s_server->Get("/api/breakpoints/logs",   route_breakpoint_logs);
		s_server->Post("/api/func_filter/load",  route_func_filter_load);
		s_server->Post("/api/func_filter/start", route_func_filter_start);
		s_server->Post("/api/func_filter/stop",  route_func_filter_stop);
		s_server->Post("/api/func_filter/keep_executed",   route_func_filter_keep);
		s_server->Post("/api/func_filter/remove_executed",  route_func_filter_remove);
		s_server->Get("/api/func_filter/status", route_func_filter_status);
		s_server->Get("/api/func_filter/functions", route_func_filter_functions);

		s_thread = std::thread([port]() {
			std::println("[MCP] HTTP server starting on port {}", port);
			s_server->listen("127.0.0.1", port);
			std::println("[MCP] HTTP server stopped");
		});

		std::println("[MCP] Server thread launched");
	}

	void stop()
	{
		if (!s_server) return;

		s_server->stop();
		if (s_thread.joinable())
			s_thread.join();

		delete s_server;
		s_server = nullptr;
	}

	void tick()
	{
		s_queue.drain();
	}
}
