#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace project
{
	enum class field_type_t
	{
		int8, uint8, int16, uint16,
		int32, uint32, int64, uint64,
		float32, float64,
		ptr64,
		char16, char32, char64,
		bool8
	};

	struct field_def_t
	{
		std::string name;
		field_type_t type = field_type_t::int32;
		uint32_t offset = 0;
		int array_count = 1;
	};

	struct struct_def_t
	{
		std::string name;
		std::vector<field_def_t> fields;
	};

	int field_size(field_type_t type);
	const char* field_type_name(field_type_t type);

	bool save_structs(const std::string& path, const std::vector<struct_def_t>& structs);
	bool load_structs(const std::string& path, std::vector<struct_def_t>& structs);
}
