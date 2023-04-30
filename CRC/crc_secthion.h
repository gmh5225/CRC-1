#ifndef CRC_SECTHION_RUNTIME
#define CRC_SECTHION_RUNTIME 1 
#include "Struct.h"
#include <vector>

namespace crc_runtime
{
	INLINE auto memset(PVOID dest, CHAR c, uint32_t len) -> PVOID
	{
		uint32_t i;
		uint32_t fill;
		uint32_t chunks = len / sizeof(fill);
		CHAR* char_dest = (CHAR*)dest;
		uint32_t* uint_dest = (uint32_t*)dest;
		fill = (c << 24) + (c << 16) + (c << 8) + c;

		for (i = len; i > chunks * sizeof(fill); i--)
			char_dest[i - 1] = c;

		for (i = chunks; i > NULL; i--)
			uint_dest[i - 1] = fill;

		return dest;
	}

 

	INLINE auto memcpy(PVOID dest, CONST PVOID src, unsigned __int64 count) -> PVOID
	{
		CHAR* char_dest = (CHAR*)dest;
		CHAR* char_src = (CHAR*)src;
		if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
		{
			while (count > NULL)
			{
				*char_dest = *char_src;
				char_dest++;
				char_src++;
				count--;
			}
		}
		else
		{
			char_dest = (CHAR*)dest + count - 1;
			char_src = (CHAR*)src + count - 1;
			while (count > NULL)
			{
				*char_dest = *char_src;
				char_dest--;
				char_src--;
				count--;
			}
		}
		return dest;
	}

	class crc_secthion
	{

	private:
		bool is_enable_unhook = FALSE;
		bool is_init = FALSE;
		PVOID address_module = NULL;
		std::vector<SECTION_CRC> crc_secthon_res;

		INLINE auto fletcher32(PVOID  data, size_t len) -> uint32_t
		{
			uint64_t data2 = reinterpret_cast<uint64_t>(data);
			uint32_t sum1 = 0xffff, sum2 = 0xffff;

			while (len)
			{
				unsigned tlen = len > 359 ? 359 : len;
				len -= tlen;
				do
				{
					sum1 += *(uint64_t*)data2++;
					sum2 += sum1;
				} while (--tlen);

				sum1 = (sum1 & 0xffff) + (sum1 >> 16);
				sum2 = (sum2 & 0xffff) + (sum2 >> 16);

			}
			sum1 = (sum1 & 0xffff) + (sum1 >> 16);
			sum2 = (sum2 & 0xffff) + (sum2 >> 16);
			return sum2 << 16 | sum1;
		}

		NO_INLINE auto get_crc_sec(PVOID address, ULONG size)
		{
			return fletcher32(address, size);
		}

		INLINE auto  init_crc_secthion(PVOID base) -> VOID
		{
			address_module = base;
			SECTION_CRC  crc_secthon;
			auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
			auto* sections = IMAGE_FIRST_SECTION(headers);

			for (uint32_t i = NULL; i <= headers->FileHeader.NumberOfSections; i++)
			{
				//Check sections rules
				if ((sections[i].Characteristics & IMAGE_SCN_MEM_READ) && !(sections[i].Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					crc_secthon.virtual_address = static_cast<CHAR*>(base) + sections[i].VirtualAddress;
					crc_secthon.fletcher_crc = get_crc_sec(crc_secthon.virtual_address, sections[i].Misc.VirtualSize);
					crc_secthon.size_secthion = sections[i].Misc.VirtualSize;

					if (is_enable_unhook)
					{
						crc_secthon.virtual_address_copy = VirtualAlloc(NULL, sections[i].Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
						if (crc_secthon.virtual_address_copy)
							memcpy(crc_secthon.virtual_address_copy, crc_secthon.virtual_address, crc_secthon.size_secthion);

					}
					crc_secthon_res.push_back(crc_secthon);
					is_init = TRUE;
				}
			}

		}


		 

	public:
		INLINE auto fast_start(bool unhook_address, PVOID base_address) -> VOID
		{
			address_module = base_address;
			is_enable_unhook = unhook_address;
			init_crc_secthion(base_address);
		}
		 
		 

		INLINE auto is_crc_bad() -> bool
		{
			DWORD old_protecthion = NULL;
			bool is_any_bad_secthin = FALSE;
			if (!is_init)
				init_crc_secthion(address_module);
			for (uint32_t i = NULL; i < crc_secthon_res.size(); i++)
			{
				if (__rdtsc() % 10 > 3) //random execute
				{ 
					if (crc_secthon_res[i].virtual_address && crc_secthon_res[i].size_secthion)
					{
						if (get_crc_sec(crc_secthon_res[i].virtual_address, crc_secthon_res[i].size_secthion) != crc_secthon_res[i].fletcher_crc)
						{
							if (is_enable_unhook)
							{
								if (crc_secthon_res[i].virtual_address_copy && VirtualProtect(crc_secthon_res[i].virtual_address, crc_secthon_res[i].size_secthion, PAGE_EXECUTE_READWRITE, &old_protecthion))
								{
									memcpy(crc_secthon_res[i].virtual_address, crc_secthon_res[i].virtual_address_copy, crc_secthon_res[i].size_secthion);
									VirtualProtect(crc_secthon_res[i].virtual_address, crc_secthon_res[i].size_secthion, old_protecthion, NULL);
								}

							}
							//Don't check over secthion
							is_any_bad_secthin = TRUE;
						}
					}
				}
			}
			return is_any_bad_secthin;
		}

	};

}
#endif // !CRC_SECTHION_RUNTIME
