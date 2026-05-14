#pragma once

#include "typedef.h"
#include "logger.h"
#include "strconv.h"

namespace peparser
{
	using namespace logging;
	using namespace strconv;

	// DATA_DIRECTORY 타입 정의
	enum PE_DIRECTORY_TYPE
	{
		PE_DIRECTORY_ALL	= 0xff,
		PE_DIRECTORY_EAT	= 0x1,
		PE_DIRECTORY_IAT	= 0x2,
		PE_DIRECTORY_TLS	= 0x4,
		PE_DIRECTORY_DEBUG	= 0x8
	};

	// Section 정보 저장을 위한 구조체 정의
	typedef struct _SECTION_INFO
	{
		tstring Name;
		size_t VirtualAddress;
		size_t PointerToRawData;
		size_t SizeOfRawData;
		size_t Characteristics;
		size_t RealAddress;
	}
	SECTION_INFO, *PSECTION_INFO;
	typedef vector<SECTION_INFO> SectionList;

	// Function 정보 저장을 위한 구조체 정의
	typedef struct _FUNCTION_INFO
	{
		tstring Name;
		size_t Ordinal;
		size_t Address;
	}
	FUNCTION_INFO, *PFUNCTION_INFO;
	typedef vector<FUNCTION_INFO> FunctionInfoList;

	// Module name, FUNCTION_INFO 정보 저장을 위한 벡터(튜플) 정의
	typedef vector<tuple<tstring, FunctionInfoList>> ModuleFunctionist;

	// PDB 정보를 담을 구조체 정의
	#define IMAGE_PDB_SIGNATURE 0x53445352 // "RSDS"
	typedef struct _IMAGE_PDB_INFO
	{
		DWORD Signature;
		BYTE Guid[16];
		DWORD Age;
		BYTE PdbFileName[1];
	}
	IMAGE_PDB_INFO, *PIMAGE_PDB_INFO;

	// PDB 파일 정보를 담을 구조체 정의
	typedef struct _PDB_FILE_INFO
	{
		tstring FilePath;
		u8string u8FilePath;
	}
	PDB_FILE_INFO, *PPDB_FILE_INFO;

	// TLS Callback 주소 정보를 담을 구조체 정의
	typedef struct _TLS_CALLBACK
	{
		size_t TlsCallbackAddress;
	}
	TLS_CALLBACK, *PTLS_CALLBACK;

	// TLS Callback 주소 정보 저장을 위한벡터 정의
	typedef vector<TLS_CALLBACK> TlsCallbackList;

	// PE 정보를 담기 위한 구조체 정의
	typedef struct _PE_STRUCT
	{
		bool is32Bit;
		size_t baseAddress;
		size_t imageBase;
		size_t sizeOfHeaders;
		size_t numberofSections;
		PIMAGE_DOS_HEADER dosHeader;
		PIMAGE_FILE_HEADER fileHader;
		union
		{
			PIMAGE_NT_HEADERS32 ntHeader32;
			PIMAGE_NT_HEADERS64 ntHeader64;
		};
		PIMAGE_SECTION_HEADER sectionHeader;
		PIMAGE_DATA_DIRECTORY dataDirectory;
		SectionList sectionList;
		ModuleFunctionist exportFunctionList;
		ModuleFunctionist importFunctionList;
		PDB_FILE_INFO pdbFileInfo;
		TlsCallbackList tlsCallbackList;
		tstring filePath;
	}
	PE_STRUCT;

	// PE file 또는 PE process 공통으로 필요한 함수들을 정의한 인터페이스 클래스
    class IPEBase
    {
    public:
        virtual ~IPEBase() = default;
        virtual bool isPE(void) const abstract;
        virtual bool is32bit(void) const abstract;
		virtual const tstring getFilePath(void) const abstract;
        virtual size_t getBaseAddress(void) const abstract;
        virtual bool getRealAddress(const size_t& rva, size_t& raw) const abstract;
		virtual bool getData(const size_t& address, const size_t& size, BinaryData& data) const abstract;
		virtual void setHeaderSize(const size_t& sizeOfHeaders) abstract;
		virtual void setSectionList(const SectionList& sectionLists) abstract;
	};
};
