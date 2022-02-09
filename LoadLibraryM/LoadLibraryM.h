#pragma once
#include <Windows.h>

#if defined(_WIN64)
#define ADDR_M ULONGLONG
#elif defined(_WIN32)
#define ADDR_M DWORD
#endif // defined(_WIN64)

#if defined(_WIN64) || defined(_WIN32)
typedef struct HeaderOrSection
{
	char* szName;
	DWORD rva;
	DWORD dwMemSize;
	DWORD foa;
	DWORD dwFileSize;
} HeaderOrSection;

typedef struct Rva2FoaHelper 
{
	HeaderOrSection* hsRegions;
	DWORD dwNumReg;
} Rva2FoaHelper;

typedef struct PE_PACKET 
{
	LPBYTE lpBuf;
	DWORD dwBufSize;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_SECTION_HEADER section_header;
	Rva2FoaHelper rva2foa;
	LPBYTE lpImage;
} PE_PACKET;
//================
BOOL LoadLibraryM(LPCSTR lpszLibName, ADDR_M* paddrBase);
BOOL ReadLibraryM(LPCSTR lpszLibName, LPVOID* plpvBuf, LPDWORD lpdwBufSize);
PE_PACKET* MakePacket(LPVOID lpvBuf, DWORD dwBufSize);
DWORD Rva2Foa(PE_PACKET* ppkPacket, DWORD dwRva);
DWORD CalcAlignedSize(DWORD dwAlignment, DWORD dwSize);
BOOL ImageAlloc(PE_PACKET* ppkPacket, ADDR_M* paddrImageBase);
BOOL ImageReloc(PE_PACKET* ppkPacket);
BOOL ImageProtect(PE_PACKET* ppkPacket);
BOOL CopyRegions(PE_PACKET* ppkPacket);
BOOL ResolveIAT(PE_PACKET* ppkPacket);
#endif // defined(_WIN64) || defined(_WIN32)
