#pragma once

#include "ipebase.h"
#include "pefile.h"
#include "peprocess.h"
#include "strconv.h"

namespace peparser
{
	class PEParser
	{
	private:
		Logger logger_;
		StrConv strConv_;
		IPEBase* peBase_;
		PE_STRUCT peStruct_;

	private:
		tstring getPEString(const char8_t* peStr);
		tstring getPEString(const char8_t* peStr, const size_t& maxLength);
		void parseSectionHeaders(void);
		void parseHeaders(void);
		void parseEAT(void);
		void parseIAT(void);
		void parseDebug(void);
		void parseTLS(void);

	public:
		PEParser();
		~PEParser();
		void close(void);
		bool open(const size_t& pid);
		bool open(const tstring_view& filePath);
		bool parsePE(const PE_DIRECTORY_TYPE& parseType = PE_DIRECTORY_ALL);
		const PE_STRUCT& getPEStructure(void) const;
	};
};

