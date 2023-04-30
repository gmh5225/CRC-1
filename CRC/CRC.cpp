
#include <iostream>
#include "crc_secthion.h"
#include "crc_file.h"
int main()
{
	//Runtime check and unhook
	crc_runtime::crc_secthion current_mod;
	crc_runtime::crc_secthion ntdll_mod;

	//CRC file
	crc_file_check::crc_file crc_file;

	current_mod.fast_start(TRUE,GetModuleHandleW(NULL));
	ntdll_mod.fast_start(TRUE, GetModuleHandleW(L"ntdll.dll"));
 
	//1 call in init
	printf("CRC file ->\t%x\n", crc_file.is_crc_bad()); 

	while (TRUE)
	{
		 
		if (GetAsyncKeyState(VK_SPACE))
		{
			printf("CRC mod ->\t%x\n", current_mod.is_crc_bad()); 
			printf("CRC ntdll ->\t%x\n", ntdll_mod.is_crc_bad());
 		}
		Sleep(1000);
		system("cls");
	}
}
