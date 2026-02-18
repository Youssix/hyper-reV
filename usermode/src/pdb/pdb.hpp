#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <memory>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")

// PDB structures (thanks mambda - https://bitbucket.org/mambda/pdb-parser/src/master/)
struct pdb_info {
	DWORD signature;
	GUID guid;
	DWORD age;
	char pdb_file_name[1];
};

typedef struct _pdb_context {
	HANDLE h_pdb_file;    // IDiaDataSource*
	HANDLE h_process;     // IDiaSession*
	DWORD64 base_address; // IDiaSymbol* (global scope)
} pdb_context, *p_pdb_context;

// download PDB file from symbol server
std::string
pdb_download(const std::string& pe_path, const std::string& pdb_download_path = "",
             const std::string& symbol_server = "https://msdl.microsoft.com/download/symbols/");

// load PDB file
bool pdb_load(const std::string& pdb_path, p_pdb_context pdb);

// get function/global variable RVA
ULONG pdb_get_rva(p_pdb_context pdb, const std::string& sym_name);

// get struct property offset
ULONG pdb_get_struct_property_offset(p_pdb_context pdb, const std::string& struct_name,
                                     const std::wstring& property_name);

// get struct size
ULONG pdb_get_struct_size(p_pdb_context pdb, const std::string& struct_name);

// unload PDB and cleanup
void pdb_unload(const std::string& pdb_path, p_pdb_context pdb);
