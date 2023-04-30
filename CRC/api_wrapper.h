#ifndef API_WRAPPPER_ENABLE
#define API_WRAPPPER_ENABLE 1 
#include "hash_str.h"

namespace api_wrapper
{

	INLINE auto  get_module_address(uint64_t hash_module) -> PVOID
	{
		LDR_DATA_TABLE_ENTRY* modEntry = nullptr;

#ifdef _WIN64
		PEB* peb = (PEB*)__readgsqword(0x60);

#else
		PEB* peb = (PEB*)__readfsdword(0x30);
#endif

		LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

		LIST_ENTRY curr = head;

		for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
		{
			LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (mod->BaseDllName.Buffer)
			{
				if (!hash_module)
				{
					modEntry = mod;
					break;
				}

				if (hash_module == fnv::hash_runtime(mod->BaseDllName.Buffer))
				{
					modEntry = mod;
					break;
				}
			}
		}
		return (PVOID)modEntry->DllBase;
	}

	INLINE auto get_proc_address(PVOID base_module, uint64_t hash_str) -> PVOID
	{
		DWORD64 base = (DWORD64)base_module;
		if (!base)
			return NULL;
		auto image_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (image_dos->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;
		auto image_nt_head = reinterpret_cast<PIMAGE_NT_HEADERS>(base + image_dos->e_lfanew);
		if (image_nt_head->Signature != IMAGE_NT_SIGNATURE)
			return NULL;
		auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + image_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (!pExport)
			return NULL;
		//reinterpret_cast break this
		auto names = (PDWORD)(base + pExport->AddressOfNames);
		auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
		auto functions = (PDWORD)(base + pExport->AddressOfFunctions);

		if (!names || !ordinals || !functions)
			return NULL;

		for (uint32_t i = NULL; i < pExport->NumberOfFunctions; ++i)
		{
			auto name = reinterpret_cast<CHAR*>(base + names[i]);
			if (hash_str == fnv::hash_runtime(name))
				return  reinterpret_cast<PVOID>(base + functions[ordinals[i]]);
		}
		return NULL;
	}
}
#endif // !API_WRAPPPER_ENABLE
