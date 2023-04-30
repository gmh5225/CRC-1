#ifndef CRC_FILE_ENABLE
#define CRC_FILE_ENABLE 1 
#include "Struct.h" 
#include "api_wrapper.h"
#include <iostream>

  

namespace crc_file_check
{
    namespace crt_wrapper
    {
        INLINE auto malloc(size_t size) -> PVOID
        {
            return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        }

        INLINE auto free(PVOID ptr) -> VOID
        {
            if (nullptr != ptr)
                VirtualFree(ptr, NULL, MEM_RELEASE);
        }

        INLINE auto tolower(INT c) -> INT
        {
            if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
            return c;
        }
        INLINE auto stricmp(CONST CHAR* cs, CONST CHAR* ct) -> INT
        {
            if (cs && ct)
            {
                while (tolower(*cs) == tolower(*ct))
                {
                    if (*cs == NULL && *ct == NULL) return NULL;
                    if (*cs == NULL || *ct == NULL) break;
                    cs++;
                    ct++;
                }
                return tolower(*cs) - tolower(*ct);
            }
            return -1;
        }
    }

    class crc_file
    {
    private:

        PVOID base_address = NULL;

        INLINE  auto get_current_name_file() -> CONST PWCHAR
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
                    return mod->FullDllName.Buffer;
                }
            }
            return FALSE;
        }
        INLINE auto fletcher32(PVOID  data, size_t len) -> uint32_t
        {
            uint64_t data2 = reinterpret_cast<uint64_t>(data);
            uint32_t sum1 = 0xffff, sum2 = 0xffff;

            while (len)
            {
                unsigned tlen = len > 359 ? 359 : len;
                len -= tlen;

                do {
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

        //This check use TimeDateStamp and recommend change
        INLINE auto start_sheck(PVOID allocate_file, uint32_t size_file) -> bool
        { 
            CHAR* address_start = reinterpret_cast<CHAR*>(allocate_file);
            uint32_t size_check = NULL;
            uint32_t crc_res = NULL;

            if (!allocate_file)
                return FALSE;
            
            if (static_cast<PIMAGE_DOS_HEADER>(allocate_file)->e_lfanew != IMAGE_DOS_SIGNATURE)
                FALSE;

            auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(allocate_file) + static_cast<PIMAGE_DOS_HEADER>(allocate_file)->e_lfanew);
            auto* sections = IMAGE_FIRST_SECTION(headers);

            //Like packed by protector
            if (!sections->PointerToRawData || !sections->Misc.VirtualSize)
                return FALSE;

            address_start = address_start + sections->PointerToRawData;
            size_check = size_file - sections->Misc.VirtualSize;

            crc_res = fletcher32(address_start, size_check); 
            return headers->FileHeader.TimeDateStamp != crc_res;
        }

    public:

        /*
           Sample with ReadFile
           Load file from disk and start check byte(use TimeDateStamp)
        */
        auto is_crc_bad(WCHAR* name_file = NULL) -> bool
        {

            bool is_corrupted = FALSE;
            uint8_t* base_map_file = NULL;
            uint32_t size_file = NULL;
            DWORD num_read = NULL;
            PVOID allocate_file = NULL;
            HANDLE file = NULL;

            if (!name_file)
                name_file = get_current_name_file();
            file = CreateFileW(name_file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            if (file != INVALID_HANDLE_VALUE)
            {
                size_file = GetFileSize(file, NULL);
                allocate_file = crt_wrapper::malloc(size_file);
                if (allocate_file)
                {
                    if (ReadFile(file, allocate_file, size_file, &num_read, NULL))
                        is_corrupted = start_sheck(allocate_file, size_file);
                    
                    crt_wrapper::free(allocate_file);
                    allocate_file = NULL;
                }

            }
            return is_corrupted;
        }

    };

}

#endif // !CRC_FILE_ENABLE
