#include "project_file.h"
#include <nlohmann/json.hpp>
#include <fstream>

namespace project
{
	int field_size(field_type_t type)
	{
		switch (type)
		{
		case field_type_t::int8:
		case field_type_t::uint8:
		case field_type_t::bool8:   return 1;
		case field_type_t::int16:
		case field_type_t::uint16:  return 2;
		case field_type_t::int32:
		case field_type_t::uint32:
		case field_type_t::float32: return 4;
		case field_type_t::int64:
		case field_type_t::uint64:
		case field_type_t::float64:
		case field_type_t::ptr64:   return 8;
		case field_type_t::char16:  return 16;
		case field_type_t::char32:  return 32;
		case field_type_t::char64:  return 64;
		}
		return 4;
	}

	const char* field_type_name(field_type_t type)
	{
		switch (type)
		{
		case field_type_t::int8:    return "Int8";
		case field_type_t::uint8:   return "UInt8";
		case field_type_t::int16:   return "Int16";
		case field_type_t::uint16:  return "UInt16";
		case field_type_t::int32:   return "Int32";
		case field_type_t::uint32:  return "UInt32";
		case field_type_t::int64:   return "Int64";
		case field_type_t::uint64:  return "UInt64";
		case field_type_t::float32: return "Float";
		case field_type_t::float64: return "Double";
		case field_type_t::ptr64:   return "Ptr64";
		case field_type_t::char16:  return "Char[16]";
		case field_type_t::char32:  return "Char[32]";
		case field_type_t::char64:  return "Char[64]";
		case field_type_t::bool8:   return "Bool";
		}
		return "???";
	}

	static std::string type_to_string(field_type_t type)
	{
		return field_type_name(type);
	}

	static field_type_t string_to_type(const std::string& s)
	{
		if (s == "Int8") return field_type_t::int8;
		if (s == "UInt8") return field_type_t::uint8;
		if (s == "Int16") return field_type_t::int16;
		if (s == "UInt16") return field_type_t::uint16;
		if (s == "Int32") return field_type_t::int32;
		if (s == "UInt32") return field_type_t::uint32;
		if (s == "Int64") return field_type_t::int64;
		if (s == "UInt64") return field_type_t::uint64;
		if (s == "Float") return field_type_t::float32;
		if (s == "Double") return field_type_t::float64;
		if (s == "Ptr64") return field_type_t::ptr64;
		if (s == "Char[16]") return field_type_t::char16;
		if (s == "Char[32]") return field_type_t::char32;
		if (s == "Char[64]") return field_type_t::char64;
		if (s == "Bool") return field_type_t::bool8;
		return field_type_t::int32;
	}

	bool save_structs(const std::string& path, const std::vector<struct_def_t>& structs)
	{
		nlohmann::json root = nlohmann::json::array();

		for (auto& s : structs)
		{
			nlohmann::json js;
			js["name"] = s.name;
			js["fields"] = nlohmann::json::array();

			for (auto& f : s.fields)
			{
				nlohmann::json jf;
				jf["name"] = f.name;
				jf["type"] = type_to_string(f.type);
				jf["offset"] = f.offset;
				jf["array_count"] = f.array_count;
				js["fields"].push_back(jf);
			}

			root.push_back(js);
		}

		std::ofstream file(path);
		if (!file.is_open()) return false;

		file << root.dump(2);
		return true;
	}

	bool load_structs(const std::string& path, std::vector<struct_def_t>& structs)
	{
		std::ifstream file(path);
		if (!file.is_open()) return false;

		nlohmann::json root;
		try {
			file >> root;
		}
		catch (...) {
			return false;
		}

		structs.clear();

		for (auto& js : root)
		{
			struct_def_t s;
			s.name = js.value("name", "unnamed");

			for (auto& jf : js["fields"])
			{
				field_def_t f;
				f.name = jf.value("name", "field");
				f.type = string_to_type(jf.value("type", "Int32"));
				f.offset = jf.value("offset", 0u);
				f.array_count = jf.value("array_count", 1);
				s.fields.push_back(f);
			}

			structs.push_back(s);
		}

		return true;
	}
}
