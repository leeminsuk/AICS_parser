#pragma once

#include "typedef.h"
#include "ipebase.h"
#include "logger.h"

namespace peparser 
{
	using namespace logging;

	class PEPrint {

	private:
		Logger logger_;

	private:
		void printBaseAddress(const PE_STRUCT& peStructure);
		void printDosHeader(const PE_STRUCT& peStructure);
		void printNTHeader(const PE_STRUCT& peStructure);
		void printSectionHeader(const PE_STRUCT& peStructure);
		void printEAT(const PE_STRUCT& peStructure);
		void printIAT(const PE_STRUCT& peStructure);
		void printTLS(const PE_STRUCT& peStructure);

	public:
		PEPrint();
		~PEPrint() = default;
		void printPEStructure(const PE_STRUCT& peStructure);
	};
};

