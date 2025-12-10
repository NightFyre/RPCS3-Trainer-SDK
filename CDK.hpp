// -------------------------------------------------------------- \\
//						RPCS3 CHEAT DEVICE						  \\
// -------------------------------------------------------------- \\
// Name: PlayStation3 - RPCS3, Version: 1.0.0
#define VERSION_CDK		"v1.0.0"		//	
#define VERSION_RPCS3	"v0.0.0"		//	

#pragma once
#include <windows.h>
#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

namespace Playstation3
{
	bool InitCDK();
	void ShutdownCDK();

	class CGlobals
	{
	public:
		static class Memory* g_memory;		//	
	};

	class Memory
	{
	public:
		//	section headers index
		enum class ESECTIONHEADERS : int
		{
			SECTION_TEXT = 0,		//	.text
			SECTION_DATA,			//	.data
			SECTION_RDATA,			//	.rdata
			SECTION_IMPORT,			//	IMPORTS TABLE
			SECTION_EXPORT,			//	EXPORTS TABLE
			SECTION_NULL
		};

	public:
		template <typename T>
		static inline T	ReadMemoryEx(__int64 addr) { return *(T*)addr; }

		template<typename T>
		static inline void	WriteMemoryEx(__int64 addr, T patch) { *(T*)addr = patch; }

	public:
		static Memory*	GetDefaultInstance();
		static __int64	GetModuleBase(); //  returns the module base of RPCS3 Process => RPCS3.exe
		static __int64	GetAddr(const unsigned __int32& offset); //  returns address offset from RPCS3 module base
		static __int64	FindPattern(const std::string& signature, const DWORD& padding, const DWORD& szInstruction, const DWORD& szOp, OUT __int64* lpResult);
		static bool		GetSectionHeaderAddress(const ESECTIONHEADERS& section, __int64* lpResult, size_t* szImage);
		static bool		DumpSectionToFile(const char* filename, const __int64& start_offset, const size_t& size); // Dumps a section of memory to a file

	public:
		Memory();
		~Memory();

	public:
		friend class PS3Memory;	// allow access to private members from PS3Memory class

	private:
		static DWORD p_pid;
		static HMODULE p_hModule;
		static bool p_isInitialized;
		static unsigned __int64 p_baseAddress;
		static Memory* p_instance;
	};

	class PS3Memory
	{
	public:

		template<typename T>
		static inline T					_flip(__int64 val)
		{
			size_t szVal = sizeof(T);
			switch (szVal)
			{
			case(2): return _byteswap_ushort(val); 
			case(4): return _byteswap_ulong(val);
			case(8): return _byteswap_uint64(val);
			default: break;
			}
		}

		static short ReadShort(__int64 addr) { return _flip<short>(*(short*)addr); }
		static long ReadLong(__int64 addr) { return _flip<long>(*(long*)addr); }
		static unsigned __int64 ReadULong(__int64 addr) { return _flip<unsigned long long>(*(unsigned long long*)addr); }

	public:
		static __int64                  GetBaseVM(); // vm::g_base_addr
		static __int64 					GetBaseSUDO(); // vm::g_sudo_addr
		static __int64 					GetBaseEXEC(); // vm::g_exec_addr
		static __int64                  GetAddrVM(const __int32& offset); // returns vm::g_base_addr + offset
		static __int64                  GetAddrSUDO(const __int32& offset); // returns vm::g_sudo_addr + offset
		static __int64                  GetAddrEXEC(const __int32& offset); // returns vm::g_exec_addr + offset
	};


    // --------------------------------------------------------------
    
	Memory* CGlobals::g_memory = nullptr;

	bool InitCDK()
	{
		if (!CGlobals::g_memory)
		{
			CGlobals::g_memory = Memory::GetDefaultInstance();

			return true;
		}
		
		return false; // already init
	}

	void ShutdownCDK()
	{
		CGlobals::g_memory = 0; 
	}

	//----------------------------------------------------------------------------------------------------
	//									Memory
	//-----------------------------------------------------------------------------------

	DWORD Memory::p_pid{ 0 };
	HMODULE Memory::p_hModule{ 0 };
	bool Memory::p_isInitialized{ false };
	unsigned __int64 Memory::p_baseAddress{ 0 };
	Memory* Memory::p_instance = new Memory(); // initalize at runtime
	
	Memory::Memory()
	{
		if (p_isInitialized)
			return;

		p_pid = GetCurrentProcessId();
		p_hModule = GetModuleHandle(0);
		p_baseAddress = reinterpret_cast<unsigned __int64>(p_hModule);
		p_isInitialized = p_pid != 0 && p_baseAddress != 0;
	}

	Memory::~Memory() {}

	Memory* Memory::GetDefaultInstance() { return p_instance; }

	__int64 Memory::GetModuleBase() { return reinterpret_cast<unsigned __int64>(GetModuleHandle(0)); }

	__int64 Memory::GetAddr(const unsigned __int32& offset) { return GetModuleBase() + offset; }

	__int64 Memory::FindPattern(const std::string& signature, const DWORD& padding, const DWORD& szInstruction, const DWORD& szOp, OUT __int64* lpResult)
	{
		static auto pattern_to_byte = [](const char* pattern)
		{
			const auto start = const_cast<char*>(pattern);
			const auto end = const_cast<char*>(pattern) + strlen(pattern);

			auto bytes = std::vector<int>{};
			for (auto current = start; current < end; ++current)
			{
				if (*current == '?')
				{
					++current;
					bytes.push_back(-1);
				}
				else
				{
					bytes.push_back(strtoul(current, &current, 16));
				}
			}
			return bytes;
		};

		__int64 result = 0;

		//	Get .text segment
		__int64 section_base = 0;
		size_t section_size = 0;
		if (!GetSectionHeaderAddress(ESECTIONHEADERS::SECTION_TEXT, &section_base, &section_size))
			return false;

		//	get pattern
		const auto pattern_bytes = pattern_to_byte(signature.c_str());
		const auto cbSize = pattern_bytes.size();
		const auto cbData = pattern_bytes.data();

		//	read section
		SIZE_T szRead{ 0 };
		std::vector<unsigned __int8> scan_bytes(section_size);
		if (!ReadProcessMemory(GetCurrentProcess(), (LPVOID)section_base, scan_bytes.data(), scan_bytes.size(), &szRead))
			return false;

		//	iterate through buffer & compare with pattern
		for (auto i = 0ul; i < section_size - cbSize; ++i)
		{
			bool found = true;
			for (auto j = 0ul; j < cbSize; ++j)
			{
				if (scan_bytes[i + j] != cbData[j] && cbData[j] != -1)
				{
					found = false;
					break;
				}
			}

			if (!found)
				continue;

			//	set result address
			auto address = section_base + i;

			//	apply optional padding
			address += padding;

			//	get value
			if (szInstruction > 0 && szOp > 0)
			{
				const auto offset = ReadMemoryEx<int>(address + szOp);
				result = (address + offset) + szInstruction;
			}
			else
				result = address;

			break;
		}

		*lpResult = result;

		return result;
	}

	bool Memory::GetSectionHeaderAddress(const ESECTIONHEADERS& section, __int64* lpResult, size_t* szImage)
	{
		//	get segment title
		std::string segment;
		switch (section)
		{
		case ESECTIONHEADERS::SECTION_TEXT: { segment = ".text"; break; }
		case ESECTIONHEADERS::SECTION_DATA: { segment = ".data"; break; }
		case ESECTIONHEADERS::SECTION_RDATA: { segment = ".rdata"; break; }
		case ESECTIONHEADERS::SECTION_IMPORT: { segment = ".idata"; break; }
		case ESECTIONHEADERS::SECTION_EXPORT: { segment = ".edata"; break; }
		default: return false;
		}
		if (segment.empty())	//	segment title not captured ?? 
			return false;

		//	get dos header
		const auto& image_dos_header = ReadMemoryEx<IMAGE_DOS_HEADER>(p_baseAddress);
		if (image_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		//	get nt headers
		const auto& e_lfanew = p_baseAddress + image_dos_header.e_lfanew;
		const auto& image_nt_headers = ReadMemoryEx<IMAGE_NT_HEADERS>(e_lfanew);
		if (image_nt_headers.Signature != IMAGE_NT_SIGNATURE)
			return false;

		//	Get section
		size_t section_size = 0;
		__int64 section_base = 0;
		const auto& image_section_header = e_lfanew + sizeof(IMAGE_NT_HEADERS);
		IMAGE_SECTION_HEADER section_headers_base = ReadMemoryEx<IMAGE_SECTION_HEADER>(image_section_header);
		for (int i = 0; i < image_nt_headers.FileHeader.NumberOfSections; ++i)
		{
			if (strncmp(reinterpret_cast<const char*>(section_headers_base.Name), segment.c_str(), segment.size()) != 0)
			{
				section_headers_base = ReadMemoryEx<IMAGE_SECTION_HEADER>(image_section_header + (sizeof(IMAGE_SECTION_HEADER) * i));
				continue;
			}

			section_base = p_baseAddress + section_headers_base.VirtualAddress;
			section_size = section_headers_base.SizeOfRawData;
			break;
		}
		if (!section_base)
			return false;

		//	pass result
		*lpResult = section_base;
		*szImage = section_size;

		return true;
	}

	bool Memory::DumpSectionToFile(const char* filename, const __int64& start_offset, const size_t& size)
	{
		if (!p_isInitialized || !filename || size == 0)
			return false;

		std::ofstream file(filename, std::ios::binary);
		if (!file.is_open())
			return false;

		constexpr size_t PAGE_SIZE = 4096; // 4 KB at a time
		std::unique_ptr<char[]> buffer(new (std::nothrow) char[size]);
		if (!buffer)
			return false;

		size_t bytesRemaining = size;
		__int64 currentOffset = start_offset;
		while (bytesRemaining > 0)
		{
			size_t chunkSize = (bytesRemaining < PAGE_SIZE) ? bytesRemaining : PAGE_SIZE;

			if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)currentOffset, buffer.get(), chunkSize, nullptr))
				return false;

			file.write(buffer.get(), chunkSize);
			if (!file.good())
				return false;

			currentOffset += chunkSize;
			bytesRemaining -= chunkSize;
		}

		return true;
	}

	//----------------------------------------------------------------------------------------------------
	//									PS3Memory
	//-----------------------------------------------------------------------------------

	__int64 PS3Memory::GetBaseVM()
	{
		/*
			.text:00000000006543E0 48 2B 15 91 96 74 03                                            sub     rdx, cs:vm__g_base_addr
		*/
		static __int64 g_base_addr = 0;
		if (!g_base_addr)
			g_base_addr = Memory::FindPattern("48 2B 15 ? ? ? ? 48 B8", 0, 7, 3, &g_base_addr);
		
		return g_base_addr > Memory::p_baseAddress ? *(__int64*)g_base_addr + 0x10000 : 0; // ".ELF"
	}

	__int64 PS3Memory::GetBaseSUDO()
	{
		/*
			.text:0000000000635938 48 8B 05 C9 84 76 03                                            mov     rax, cs:vm__g_sudo_addr
		*/
		static __int64 g_sudo_addr = 0;
		if (!g_sudo_addr)
			g_sudo_addr = Memory::FindPattern("48 8B 05 ? ? ? ? 39 0C 02 75 ? 49 8B 4E ? 48 8B D3", 0, 7, 3, &g_sudo_addr);

		return g_sudo_addr > 0 ? *(__int64*)g_sudo_addr + 0x10000 : 0; // ".ELF"
	}

	__int64 PS3Memory::GetBaseEXEC()
	{
		/*
			.text:0000000000A8D6C9 48 2B 05 28 0A 31 03                                            sub     rax, cs:vm__g_exec_addr
		*/
		static __int64 g_exec_addr = 0;
		if (!g_exec_addr)
			g_exec_addr = Memory::FindPattern("48 2B 05 ? ? ? ? 48 99", 0, 7, 3, &g_exec_addr);

		return g_exec_addr > 0 ? *(__int64*)g_exec_addr : 0;
	}

	__int64 PS3Memory::GetAddrVM(const __int32& offset)
	{
		return GetBaseVM() + offset;
	}

	__int64 PS3Memory::GetAddrSUDO(const __int32& offset)
	{
		return GetBaseSUDO() + offset;
	}

	__int64 PS3Memory::GetAddrEXEC(const __int32& offset)
	{
		return GetBaseEXEC() + offset;
	}
}