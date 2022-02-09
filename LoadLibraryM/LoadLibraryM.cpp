#include "LoadLibraryM.h"
#include <iostream>

#if defined(_WIN64) || defined(_WIN32)
BOOL LoadLibraryM(LPCSTR lpszLibName, ADDR_M* paddrBase)
{
	LPBYTE lpBuf = NULL;
	DWORD dwBufSize = 0;
	BOOL bResult = ReadLibraryM(lpszLibName, (LPVOID*)&lpBuf, &dwBufSize);
	if (!bResult || !lpBuf || !dwBufSize)
		return FALSE;
	PE_PACKET* ppkPacket = MakePacket(lpBuf, dwBufSize);
	std::cout << "[+] Find Entry Point: " << std::hex << Rva2Foa(ppkPacket, ppkPacket->nt_header->OptionalHeader.AddressOfEntryPoint) << std::endl;
	ADDR_M addrImageBase;
	bResult = ImageAlloc(ppkPacket, &addrImageBase);
	if (!bResult)
		return FALSE;
	std::cout << "[+] Allocate image successfully" << std::endl;
	bResult = ImageReloc(ppkPacket);
	if (!bResult)
		return FALSE;
	std::cout << "[+] Relocate image successfully" << std::endl;
	bResult = ResolveIAT(ppkPacket);
	if (!bResult)
		return FALSE;
	std::cout << "[+] resolve image IAT successfully" << std::endl;
	bResult = ImageProtect(ppkPacket);
	if (!bResult)
		return FALSE;
	std::cout << "[+] Protect image successfully" << std::endl;
	BOOL(*APIENTRY fnDllMain)(HANDLE, DWORD, LPVOID) = reinterpret_cast<BOOL(*)(HANDLE, DWORD, LPVOID)>(ppkPacket->lpImage + ppkPacket->nt_header->OptionalHeader.AddressOfEntryPoint);
	(fnDllMain)(NULL, 0, NULL);
	return TRUE;
}

BOOL ReadLibraryM(LPCSTR lpszLibName, LPVOID* plpvBuf, LPDWORD lpdwBufSize)
{
	if (!lpszLibName || !plpvBuf || !lpdwBufSize)
		return FALSE;
	HANDLE hFile = CreateFileA(lpszLibName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	LPVOID lpvBuf = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpvBuf)
		return FALSE;
	*plpvBuf = lpvBuf;
	DWORD dwNumToRead = dwFileSize, dwNumRead = 0;
	BOOL bResult = ReadFile(hFile, lpvBuf, dwNumToRead, &dwNumRead, NULL);
	if (!bResult || dwNumToRead != dwNumRead)
		return FALSE;
	*lpdwBufSize = dwFileSize;
	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;
	return TRUE;
}

PE_PACKET* MakePacket(LPVOID lpvBuf, DWORD dwBufSize)
{
	if (!lpvBuf || !dwBufSize)
		return NULL;
	PE_PACKET* ppkPacket = new PE_PACKET;
	// point to image, just NULL
	ppkPacket->lpImage = NULL;
	// point to file
	ppkPacket->lpBuf = reinterpret_cast<LPBYTE>(lpvBuf);
	ppkPacket->dwBufSize = dwBufSize;
	// parse headers
	ppkPacket->dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(ppkPacket->lpBuf);
	ppkPacket->nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(ppkPacket->lpBuf + ppkPacket->dos_header->e_lfanew);
	ppkPacket->section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(ppkPacket->lpBuf + ppkPacket->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	// generate Rva2FoaHelper
	ppkPacket->rva2foa.dwNumReg = ppkPacket->nt_header->FileHeader.NumberOfSections + 1;
	ppkPacket->rva2foa.hsRegions = new HeaderOrSection[ppkPacket->rva2foa.dwNumReg];
	// set hsRegions[0] point to PE Headers
	ppkPacket->rva2foa.hsRegions[0].szName = new char[10];
	strcpy_s(ppkPacket->rva2foa.hsRegions[0].szName, 10, "header");
	ppkPacket->rva2foa.hsRegions[0].rva = 0;
	ppkPacket->rva2foa.hsRegions[0].dwMemSize = CalcAlignedSize(ppkPacket->nt_header->OptionalHeader.SectionAlignment, ppkPacket->nt_header->OptionalHeader.SizeOfHeaders);
	ppkPacket->rva2foa.hsRegions[0].foa = 0;
	ppkPacket->rva2foa.hsRegions[0].dwFileSize = ppkPacket->nt_header->OptionalHeader.SizeOfHeaders;
	// set hsRegions[0 .. -1] point to sections
	DWORD dwNumNoUsedSection = 0;
	for (DWORD i = 0, j = 1; (i < ppkPacket->nt_header->FileHeader.NumberOfSections) && (j < ppkPacket->rva2foa.dwNumReg); i++)
	{
		if (ppkPacket->section_header[i].SizeOfRawData == 0 || ppkPacket->section_header[i].VirtualAddress == 0)
		{
			dwNumNoUsedSection++;
			continue;
		}
		ppkPacket->rva2foa.hsRegions[j].szName = new char[10];
		ZeroMemory(ppkPacket->rva2foa.hsRegions[j].szName, 10);
		CopyMemory(ppkPacket->rva2foa.hsRegions[j].szName, &ppkPacket->section_header[i].Name, 8);
		ppkPacket->rva2foa.hsRegions[j].rva = ppkPacket->section_header[i].VirtualAddress;
		ppkPacket->rva2foa.hsRegions[j].dwMemSize = CalcAlignedSize(ppkPacket->nt_header->OptionalHeader.SectionAlignment, ppkPacket->section_header[i].SizeOfRawData);
		ppkPacket->rva2foa.hsRegions[j].foa = ppkPacket->section_header[i].PointerToRawData;
		ppkPacket->rva2foa.hsRegions[j].dwFileSize = ppkPacket->section_header[i].SizeOfRawData;
		j++;
	}
	ppkPacket->rva2foa.dwNumReg -= dwNumNoUsedSection;
	return ppkPacket;
}

DWORD Rva2Foa(PE_PACKET* ppkPacket, DWORD dwRva)
{
	for (DWORD i = 0; i < ppkPacket->rva2foa.dwNumReg; i++)
	{
		if ((dwRva >= ppkPacket->rva2foa.hsRegions[i].rva) && (dwRva < (ppkPacket->rva2foa.hsRegions[i].rva + ppkPacket->rva2foa.hsRegions[i].dwMemSize)))
		{
			return ppkPacket->rva2foa.hsRegions[i].foa + (dwRva - ppkPacket->rva2foa.hsRegions[i].rva);
		}
	}
	return 0;
}

DWORD CalcAlignedSize(DWORD dwAlignment, DWORD dwSize)
{
	DWORD i = 0;
	while ((i * dwAlignment) < dwSize) i++;
	return i * dwAlignment;
}

BOOL ImageAlloc(PE_PACKET* ppkPacket, ADDR_M* paddrImageBase)
{
	if (!ppkPacket)
		return FALSE;
	LPVOID lpvImage = VirtualAlloc(NULL, ppkPacket->nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpvImage)
		return FALSE;
	ZeroMemory(lpvImage, ppkPacket->nt_header->OptionalHeader.SizeOfImage);
	ppkPacket->lpImage = reinterpret_cast<LPBYTE>(lpvImage);
	BOOL bResult;
	bResult = CopyRegions(ppkPacket);
	return bResult;
}

BOOL ImageReloc(PE_PACKET* ppkPacket)
{
	ADDR_M addrNewBase = reinterpret_cast<ADDR_M>(ppkPacket->lpImage);
	ADDR_M addrOldBase = ppkPacket->nt_header->OptionalHeader.ImageBase;
	DWORD dwBaseRelocRva = ppkPacket->nt_header->OptionalHeader.DataDirectory[5].VirtualAddress;
	DWORD dwBaseRelocSize = ppkPacket->nt_header->OptionalHeader.DataDirectory[5].Size;
	PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
	for (DWORD i = 0; i < dwBaseRelocSize; )
	{
		PIMAGE_BASE_RELOCATION pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ppkPacket->lpImage + dwBaseRelocRva + i);
		DWORD dwBaseRelocRva = pBaseReloc->VirtualAddress;
		LPWORD lpdwTypeOffset = reinterpret_cast<LPWORD>(pBaseReloc + 1);
		LPVOID lpvEnd = reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(pBaseReloc) + pBaseReloc->SizeOfBlock);
		while (lpdwTypeOffset < lpvEnd)
		{
			DWORD dwType = (*lpdwTypeOffset & 0xf000) >> 12;
			DWORD dwOffset = (*lpdwTypeOffset) & 0xfff;
			DWORD dwRelocRva = dwBaseRelocRva + dwOffset;
			ADDR_M* paddrReloc = reinterpret_cast<ADDR_M*>(ppkPacket->lpImage + dwRelocRva);
			if (dwType != IMAGE_REL_BASED_ABSOLUTE)
				*paddrReloc = *paddrReloc - addrOldBase + addrNewBase;
			lpdwTypeOffset++;
		}
		i += pBaseReloc->SizeOfBlock;
		pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(lpvEnd);
	}
	return TRUE;
}

BOOL CopyRegions(PE_PACKET* ppkPacket)
{
	// copy headers
	CopyMemory(ppkPacket->lpImage, ppkPacket->lpBuf, ppkPacket->nt_header->OptionalHeader.SizeOfHeaders);
	// copy sections
	DWORD dwNumSection = ppkPacket->nt_header->FileHeader.NumberOfSections;
	for (DWORD i = 0; i < dwNumSection; i++)
	{
		DWORD dwRealSize = 0;
		if (ppkPacket->section_header[i].SizeOfRawData > 0)
		{
			dwRealSize = CalcAlignedSize(ppkPacket->nt_header->OptionalHeader.FileAlignment, ppkPacket->section_header[i].SizeOfRawData);
			CopyMemory(
				ppkPacket->lpImage + ppkPacket->section_header[i].VirtualAddress,
				ppkPacket->lpBuf + ppkPacket->section_header[i].PointerToRawData,
				dwRealSize
			);
			dwRealSize = CalcAlignedSize(ppkPacket->nt_header->OptionalHeader.SectionAlignment, ppkPacket->section_header[i].SizeOfRawData);
		}
	}
	return TRUE;
}

BOOL ImageProtect(PE_PACKET* ppkPacket)
{
	DWORD dwNumSection = ppkPacket->nt_header->FileHeader.NumberOfSections;
	BOOL bResult;
	for (DWORD i = 0; i < dwNumSection; i++)
	{
		DWORD dwProtect = PAGE_READWRITE;
		DWORD dwOldProtect = 0;
		DWORD dwRealSize = 0;
		DWORD dwCharacteristics = ppkPacket->section_header[i].Characteristics;
		if (ppkPacket->section_header[i].SizeOfRawData > 0)
		{
			dwRealSize = CalcAlignedSize(ppkPacket->nt_header->OptionalHeader.SectionAlignment, ppkPacket->section_header[i].SizeOfRawData);
		}
		else
		{
			dwRealSize = ppkPacket->section_header[i + 1].VirtualAddress - ppkPacket->section_header[i].VirtualAddress;
		}
		// protect memory
		switch (dwCharacteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE))
		{
		case IMAGE_SCN_MEM_READ:
			dwProtect = PAGE_READONLY;
			//std::cout << "r--\n";
			break;
		case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
			dwProtect = PAGE_READWRITE;
			//std::cout << "rw-\n";
			break;
		case IMAGE_SCN_MEM_EXECUTE:
			dwProtect = PAGE_EXECUTE;
			//std::cout << "--x\n";
			break;
		case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ:
			dwProtect = PAGE_EXECUTE_READ;
			//std::cout << "r-x\n";
			break;
		case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
			dwProtect = PAGE_EXECUTE_READWRITE;
			//std::cout << "rwx\n";
			break;
		default:
			//std::cout << "---\n";
			break;
		}
		bResult = VirtualProtect(
			ppkPacket->lpImage + ppkPacket->section_header[i].VirtualAddress,
			dwRealSize,
			dwProtect,
			&dwOldProtect
		);
		if (!bResult)
		{
			return FALSE;
		}
	}
	return TRUE;
}

BOOL ResolveIAT(PE_PACKET* ppkPacket)
{
	DWORD dwImportRva = ppkPacket->nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD dwImportSize = ppkPacket->nt_header->OptionalHeader.DataDirectory[1].Size;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ppkPacket->lpImage + dwImportRva);

	for (DWORD i = 0; i < (dwImportSize / sizeof(IMAGE_IMPORT_DESCRIPTOR)); i++)
	{
		if (!pImportDescriptor[i].Characteristics) continue;
		DWORD dwNameRva = pImportDescriptor[i].Name;
		LPCSTR lpszName = reinterpret_cast<LPCSTR>(ppkPacket->lpImage + dwNameRva);
		HMODULE hMod = LoadLibraryA(lpszName);
		if (!hMod)
			return FALSE;
		DWORD dwINTRva = pImportDescriptor[i].OriginalFirstThunk;
		DWORD dwIATRva = pImportDescriptor[i].FirstThunk;
		ADDR_M* paddrIAT = reinterpret_cast<ADDR_M*>(ppkPacket->lpImage + pImportDescriptor[i].FirstThunk);
		PIMAGE_THUNK_DATA pThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(ppkPacket->lpImage + dwINTRva);
		while (pThunkData->u1.AddressOfData)
		{
			PIMAGE_IMPORT_BY_NAME pImpName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ppkPacket->lpImage + pThunkData->u1.AddressOfData);
			LPCSTR lpszProcName = pImpName->Name;
			ADDR_M addrProc = reinterpret_cast<ADDR_M>(GetProcAddress(hMod, lpszProcName));
			if (addrProc)
			{
				*paddrIAT = addrProc;
			}
			pThunkData++;
			paddrIAT++;
		}
	}
	return TRUE;
}
#endif