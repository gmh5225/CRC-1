#include <iostream>
#include "Struct.h"


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


auto main(INT argc, CHAR* argv[]) -> INT
{
    CHAR* address_start = NULL;
    uint32_t size_file = NULL;
    uint32_t size_check = NULL;
    uint32_t crc_res = NULL;
    DWORD num_read = NULL;
    PVOID allocate_file = NULL;
    HANDLE file_handle = NULL;
    CONST CHAR* file_path = argv[1];

    if (file_path)
    {

        file_handle = CreateFileA(file_path, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_handle != INVALID_HANDLE_VALUE)
        {
            size_file = GetFileSize(file_handle, NULL);
            allocate_file = crt_wrapper::malloc(size_file);
 
            ReadFile(file_handle, allocate_file, size_file, &num_read, NULL);

            address_start = reinterpret_cast<CHAR*>(allocate_file);
 
            if (!allocate_file)
            {
                std::cout << "Bad allocate!\n";
                getchar();
                return NULL;
            }

            auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(allocate_file) + static_cast<PIMAGE_DOS_HEADER>(allocate_file)->e_lfanew);
            auto* sections = IMAGE_FIRST_SECTION(headers);

            //Like packed by protector
            if (!sections->PointerToRawData)
            {
                std::cout << "Bad PointerToRawData info!\n";
                crt_wrapper::free(allocate_file);
                getchar();
                return NULL;
            }

            address_start = address_start + sections->PointerToRawData;
            size_check = size_file - sections->Misc.VirtualSize;

            headers->FileHeader.TimeDateStamp = fletcher32(address_start, size_check);
            SetFilePointer(file_handle, NULL, NULL, FILE_BEGIN);

            WriteFile(file_handle, allocate_file, size_file, &num_read, NULL);
            CloseHandle(file_handle);
            std::cout << "Success write!\n";
        }
        else
            std::cout << "Bad open file!\n";
        

    }
    else
        std::cout << "Bad get path file!\n";

    getchar();
    return NULL;
     
}