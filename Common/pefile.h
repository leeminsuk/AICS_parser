#pragma once

#include "ipebase.h"
#include "logger.h"

namespace peparser
{
	using namespace logging;

	class PEFile : public IPEBase
	{
	private : 
		Logger logger_;
		bool isPE_;
		bool is32bit_;
		size_t baseAddress_;
		HANDLE fileHandle_;
		HANDLE fileMapping_;
		size_t sizeOfHeaders_;
		size_t sizeOfImage_;
		size_t numberOfSections_;
		SectionList* sectionList_;
		tstring filePath_;

	public:
		PEFile();
		~PEFile() override;
		bool open(const tstring_view& filePath, const bool& forceOpen = false);
		void close(void);
		bool isPE(void) const override;
		bool is32bit(void) const override;
		const tstring getFilePath(void) const override;
		size_t getBaseAddress(void) const override;
		bool getRealAddress(const size_t& rva, size_t& raw) const override;
		bool getData(const size_t& address, const size_t& size, BinaryData& data) const override;
		void setHeaderSize(const size_t& sizeOfHeaders) override;
		void setSectionList(const SectionList& sectionLists) override;
	};
};


