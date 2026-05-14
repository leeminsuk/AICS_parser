#pragma once

#include "ipebase.h"
#include "logger.h"
#include "strconv.h"
#include "winternl.h"

namespace peparser
{
	using namespace logging;
	using namespace strconv;

	// NtQueryInformationProcess 함수 호출을 위한 정의
	typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)
	(
		IN HANDLE ProcessHandle, 
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation, 
		IN ULONG ProcessInformationLength, 
		OUT PULONG ReturnLength OPTIONAL
	);

	class PEProcess : public IPEBase
	{
	private:
		Logger logger_;
		StrConv strConv_;
		bool isPE_;
		bool is32bit_;
		size_t pid_;
		HANDLE fileMapping_;
		HANDLE processHandle_;
		HANDLE threadHandle_;
		size_t processBaseAddress_;
		size_t baseAddress_;
		size_t sizeOfHeaders_;
		size_t sizeOfImage_;
		size_t numberOfSections_;
		tstring filePath_;
		PEB peb_;
		PNtQueryInformationProcess ntQueryInformationProcess_;
		SectionList* sectionList_;

	private:
		bool parseImageBaseAddress(void);
		bool parseBasicInfo(void);
		bool createFileMapping(const size_t& pid);

	public:
		PEProcess();
		~PEProcess() override;
		bool open(const size_t& pid);
		void close(void);
		bool isPE(void) const override;
		bool is32bit(void) const override;
		const tstring getFilePath(void) const override;
		size_t getBaseAddress(void) const override;
		bool getRealAddress(const size_t& rva, size_t& raw) const override;
		bool getData(const size_t& address, const size_t& size, BinaryData& data) const override;
		void setHeaderSize(const size_t& sizeOfHeaders) override;
		void setSectionList(const SectionList& sectionList) override;
	};
};
