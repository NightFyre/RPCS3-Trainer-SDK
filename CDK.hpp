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
#include <stdint.h>


namespace Playstation3
{

	/* REFERENCES
	* Linus Torvalds - Linux - https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/uapi/linux/elf.h#L220
	* dfanz0r - https://gist.github.com/dfanz0r/38e59cdd0e4d87a865ecb5f2a6e912db
	*/

#define IMAGE_ELF_SIGNATURE				0x457F      // .ELF

	enum ElfType : unsigned int
	{
		ET_NONE = 0,
		ET_REL,
		ET_EXEC,
		ET_DYN,
		ET_SCE_Exec = 0xFE00,           // SCE Executable - PRX2
		ET_SCE_RelExec = 0xFE04,        // SCE Relocatable Executable - PRX2
		ET_SCE_StubLib = 0xFE0C,        // SCE SDK Stubs
		ET_SCE_DynExec = 0xFE10,        // SCE EXEC_ASLR (PS4 Executable with ASLR)
		ET_SCE_Dynamic = 0xFE18,        // SCE Dynamic
		ET_SCE_IopRelExec = 0xFF80,     // SCE IOP Relocatable Executable
		ET_SCE_IopRelExec2 = 0xFF81,    // SCE IOP Relocatable Executable Version 2
		ET_SCE_EeRelExec = 0xFF90,      // SCE EE Relocatable Executable
		ET_SCE_EeRelExec2 = 0xFF91,     // SCE EE Relocatable Executable Version 2
		ET_SCE_PspRelExec = 0xFFA0,     // SCE PSP Relocatable Executable
		ET_SCE_PpuRelExec = 0xFFA4,     // SCE PPU Relocatable Executable
		ET_SCE_ArmRelExec = 0xFFA5,     // SCE ARM Relocatable Executable (PS Vita)
		ET_SCE_PspOverlay = 0xFFA8      // SCE PSP Overlay
	};

	enum class ElfMachine : USHORT
	{
		None = 0,
		M32 = 1,
		Sparc = 2,
		I386 = 3,
		M68k = 4,
		M88k = 5,
		I860 = 7,
		Mips = 8,
		PowerPc = 0x14,    // 32-bit PowerPC
		PowerPc64 = 0x15,  // 64-bit PowerPC (PS3 PPU)
		Arm = 0x28,
		SparcV9 = 0x2B,
		Ia64 = 0x32,
		X86_64 = 0x3E
	};

	enum class ElfOsAbi : char
	{
		None = 0,
		HpUx = 1,
		NetBsd = 2,
		Linux = 3,
		Solaris = 6,
		Aix = 7,
		Irix = 8,
		FreeBsd = 9,
		OpenBsd = 12,
		CellLv2 = 102  // CELL LV2 (PS3)
	};

	enum ElfSectionType : unsigned int
	{
		EST_Null = 0,
		EST_ProgBits = 1,
		EST_SymTab = 2,
		EST_StrTab = 3,
		EST_Rela = 4,
		EST_Hash = 5,
		EST_Dynamic = 6,
		EST_Note = 7,
		EST_NoBits = 8,
		EST_Rel = 9,
		EST_ShLib = 10,
		EST_DynSym = 11,
		EST_InitArray = 14,
		EST_FiniArray = 15,
		EST_PreInitArray = 16,
		EST_Group = 17,
		EST_SymTabShndx = 18,

		// SCE-specific section types
		EST_SCE_Rela = 0x60000000,
		EST_SCE_Nid = 0x61000001,
		EST_SCE_IopMod = 0x70000080,
		EST_SCE_EeMod = 0x70000090,
		EST_SCE_PspRela = 0x700000A0,
		EST_SCE_PpuRela = 0x700000A4
	};

	enum ElfProgramType : unsigned int
	{
		EPT_Null = 0,
		EPT_Load = 1,
		EPT_Dynamic = 2,
		EPT_Interp = 3,
		EPT_Note = 4,
		EPT_ShLib = 5,
		EPT_Phdr = 6,
		EPT_Tls = 7,

		// SCE-specific segment types
		EPT_SceRela = 0x60000000,
		EPT_SceLicInfo1 = 0x60000001,
		EPT_SceLicInfo2 = 0x60000002,
		EPT_SceDynLibData = 0x61000000,
		EPT_SceProcessParam = 0x61000001,
		EPT_SceModuleParam = 0x61000002,
		EPT_SceRelRo = 0x61000010,  // for PS4
		EPT_SceComment = 0x6FFFFF00,
		EPT_SceLibVersion = 0x6FFFFF01,
		EPT_SceUnk70000001 = 0x70000001,
		EPT_SceIopMod = 0x70000080,
		EPT_SceEeMod = 0x70000090,
		EPT_ScePspRela = 0x700000A0,
		EPT_ScePspRela2 = 0x700000A1,
		EPT_ScePpuRela = 0x700000A4,
		EPT_SceSegSym = 0x700000A8
	};

	enum class ElfProgramFlags : unsigned int
	{
		Execute = 0x1,
		Write = 0x2,
		Read = 0x4,

		// SCE-specific segment flags
		SpuExecute = 0x00100000,     // SPU Execute
		SpuWrite = 0x00200000,       // SPU Write
		SpuRead = 0x00400000,        // SPU Read
		RsxExecute = 0x01000000,     // RSX Execute
		RsxWrite = 0x02000000,       // RSX Write
		RsxRead = 0x04000000         // RSX Read
	};

	typedef struct _IMAGE_ELF64_HEADER {
		uint8_t e_ident[16]; // magic
		uint16_t e_type; //0x0010 ; ElfType
		uint16_t e_machine; //0x0012 ; ElfMachine
		uint32_t e_version; //0x0014
		uint64_t e_entry; //0x0018
		uint64_t e_phoff; //0x0020
		uint64_t e_shoff; //0x0028
		uint32_t e_flags; //0x0030
		uint16_t e_ehsize; //0x0034
		uint16_t e_phentsize; //0x0036
		uint16_t e_phnum; //0x0038
		uint16_t e_shentsize; //0x003A
		uint16_t e_shnum; //0x003C
		uint16_t e_shstrndx; //0x003E
	} IMAGE_ELF64_HEADER, * PIMAGE_ELF64_HEADER; //Size: 0x0040

	typedef struct  _ELF64_PROG_HEADER
	{
	public:
		uint32_t p_type; //0x0000
		uint32_t p_flags; //0x0004
		uint64_t p_offset; //0x0008
		uint64_t p_vaddr; //0x0010
		uint64_t p_paddr; //0x0018
		uint64_t p_filesz; //0x0020
		uint64_t p_memsz; //0x0028
		uint64_t p_align; //0x0030
	} _ELF64_PROG_HEADER, * PELF64_PROG_HEADER; //Size: 0x0038

	typedef struct _ELF64_SECTION_HEADER
	{
	public:
		uint32_t sh_name; //0x0000
		uint32_t sh_type; //0x0004
		uint64_t sh_flags; //0x0008
		uint64_t sh_addr; //0x0010
		uint64_t sh_offset; //0x0018
		uint64_t sh_size; //0x0020
		uint32_t sh_link; //0x0028
		uint32_t sh_info; //0x002C
		uint64_t sh_addralign; //0x0030
		uint64_t sh_entsize; //0x0038
	} _ELF64_SECTION_HEADER, * PELF64_SECTION_HEADER; //Size: 0x0040


	// --------------------------------------------------------------

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

	public:
		static __int64                  GetBaseVM(); // vm::g_base_addr
		static __int64 					GetBaseSUDO(); // vm::g_sudo_addr
		static __int64 					GetBaseEXEC(); // vm::g_exec_addr
		static __int64                  GetAddrVM(const __int32& offset); // returns vm::g_base_addr + offset
		static __int64                  GetAddrSUDO(const __int32& offset); // returns vm::g_sudo_addr + offset
		static __int64                  GetAddrEXEC(const __int32& offset); // returns vm::g_exec_addr + offset
		static bool						DumpELF(const char* name); // parses and dumps each section
		static short					ReadShort(__int64 addr);
		static long						ReadWord(__int64 addr);
		static __int64					ReadLong(__int64 addr);
		static bool						WriteShort(__int64 addr, const short& value);
		static bool						WriteWord(__int64 addr, const long& v);
		static bool						WriteLong(__int64 addr, const unsigned __int64& v);
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

	inline bool PS3Memory::DumpELF(const char* name)
	{
		const auto& vm = GetBaseVM(); // _IMAGE_ELF64_HEADER
		if (!vm)
			return false;

		const auto& core = vm - 0x10000;
		const auto& ELF = Memory::ReadMemoryEx<_IMAGE_ELF64_HEADER>(vm);

		/* parse program headers */
		const auto& program_header_offset = _byteswap_uint64(ELF.e_phoff);
		const auto& program_header_size = _byteswap_ushort(ELF.e_phentsize);
		const auto& program_header_count = _byteswap_ushort(ELF.e_phnum);

		//	std::vector<_ELF64_PROG_HEADER> program_headers;
		for (int i = 0; i < program_header_count; i++)
		{
			auto offset = vm + program_header_offset + (i * program_header_size);

			auto ph = Memory::ReadMemoryEx<_ELF64_PROG_HEADER>(offset);
			ph.p_type = _byteswap_ulong(ph.p_type);		
			ph.p_flags = _byteswap_ulong(ph.p_flags);	
			ph.p_offset = _byteswap_uint64(ph.p_offset);
			ph.p_vaddr = _byteswap_uint64(ph.p_vaddr);	
			ph.p_paddr = _byteswap_uint64(ph.p_paddr);	
			ph.p_filesz = _byteswap_uint64(ph.p_filesz);
			ph.p_memsz = _byteswap_uint64(ph.p_memsz);	
			ph.p_align = _byteswap_uint64(ph.p_align);	
			//	program_headers.push_back(ph);


			char buff[256];
			sprintf_s(buff, "%s_%d.ELF", name, i);

			const auto& va = core + ph.p_vaddr;
			printf("[-] Dumping section to file @ 0x%llX with size 0x%08X\n", va, ph.p_memsz);
			Memory::DumpSectionToFile(buff, va, ph.p_memsz);
		}

		return true;

		/* parse section headers */
		//	const auto& section_header_offset = _byteswap_uint64(ELF.e_shoff);
		//	const auto& section_header_size = _byteswap_ushort(ELF.e_shentsize);
		//	const auto& section_header_count = _byteswap_ushort(ELF.e_shnum);
		//	
		//	std::vector<_ELF64_SECTION_HEADER> section_headers;
		//	for (int i = 0; i < section_header_count; i++)
		//	{
		//		auto offset = vm + section_header_offset + (i * section_header_size);
		//	
		//		auto sh = Memory::ReadMemoryEx<_ELF64_SECTION_HEADER>(offset);
		//		// sh.sh_name; //0x0000
		//		sh.sh_type = _byteswap_ulong(sh.sh_type); //0x0004
		//		sh.sh_flags = _byteswap_uint64(sh.sh_flags); //0x0008
		//		sh.sh_addr = _byteswap_uint64(sh.sh_addr); //0x0010
		//		sh.sh_offset = _byteswap_uint64(sh.sh_offset); //0x0018
		//		sh.sh_size = _byteswap_uint64(sh.sh_size); //0x0020
		//		sh.sh_link = _byteswap_ulong(sh.sh_link); //0x0028
		//		sh.sh_info = _byteswap_ulong(sh.sh_info); //0x002C
		//		sh.sh_addralign = _byteswap_uint64(sh.sh_addralign); //0x0030
		//		sh.sh_entsize = _byteswap_uint64(sh.sh_entsize); //0x0038
		//	
		//		section_headers.push_back(sh);
		//	}
	}

	inline short PS3Memory::ReadShort(__int64 addr)
	{
		return _byteswap_ushort(Memory::ReadMemoryEx<short>(addr));
	}
	
	inline long PS3Memory::ReadWord(__int64 addr)
	{
		return _byteswap_ulong(Memory::ReadMemoryEx<short>(addr));
	}
	
	inline __int64 PS3Memory::ReadLong(__int64 addr)
	{
		return _byteswap_uint64(Memory::ReadMemoryEx<unsigned __int64>(addr));
	}
	
	inline bool PS3Memory::WriteShort(__int64 addr, const short& v)
	{
		Memory::WriteMemoryEx<short>(addr, _byteswap_ushort(v));
		
		return ReadShort(addr) == v;
	}
	
	inline bool PS3Memory::WriteWord(__int64 addr, const long& v)
	{
		Memory::WriteMemoryEx<long>(addr, _byteswap_ulong(v));

		return ReadWord(addr) == v;
	}
	
	inline bool PS3Memory::WriteLong(__int64 addr, const unsigned __int64& v)
	{
		Memory::WriteMemoryEx<unsigned __int64>(addr, _byteswap_uint64(v));

		return ReadLong(addr) == v;
	}
}