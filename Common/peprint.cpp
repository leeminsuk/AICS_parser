#pragma once

#include "peprint.h"

namespace peparser 
{
    #define LINE_SPLIT _T("\n---------------------------------------------------------------------------------\n")

    PEPrint::PEPrint()
    {
        logger_.setLogType(LOG_LEVEL_ALL, LOG_DIRECTION_CONSOLE, FALSE);
    };

    void PEPrint::printBaseAddress(const PE_STRUCT& peStructure)
    {
        logger_.log(LINE_SPLIT);
        logger_.log(format(_T("PE file: {:s}"), peStructure.filePath));

        if (peStructure.is32Bit)
        {
            logger_.log(format(_T("    Image Base (PE header)  : {:#010x}"), peStructure.imageBase));
            logger_.log(format(_T("    Image Base (Memory map) : {:#010x}"), peStructure.baseAddress));
        }
        else
        {
            logger_.log(format(_T("    Image Base (PE header)  : {:#018x}"), peStructure.imageBase));
            logger_.log(format(_T("    Image Base (Memory map) : {:#018x}"), peStructure.baseAddress));
        }
        if (!peStructure.pdbFileInfo.FilePath.empty())
        {
            logger_.log(format(_T("    PDB file : {:s}"), peStructure.pdbFileInfo.FilePath));
        }
        logger_.log(LINE_SPLIT);
    };

    void PEPrint::printDosHeader(const PE_STRUCT& peStructure)
    {
        logger_.log(format(_T("DOS signature: {:#06x}"), static_cast<WORD>(peStructure.dosHeader->e_magic)));
        logger_.log(LINE_SPLIT);
    };

    void PEPrint::printNTHeader(const PE_STRUCT& peStructure)
    {
        logger_.log(format(_T("Machine type:                 {:#06x}"), static_cast<WORD>(peStructure.fileHader->Machine)));
        logger_.log(format(_T("Number of sections:           {:#06x}"), static_cast<WORD>(peStructure.fileHader->NumberOfSections)));
        logger_.log(format(_T("Timestamp:                    {:#010x}"), static_cast<DWORD>(peStructure.fileHader->TimeDateStamp)));

        if (peStructure.is32Bit)
        {
            logger_.log(format(_T("Magic:                        {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.Magic)));
            logger_.log(format(_T("Entry point address:          {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.AddressOfEntryPoint)));
            logger_.log(format(_T("Image base address:           {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.ImageBase)));
            logger_.log(format(_T("Section alignment:            {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.SectionAlignment)));
            logger_.log(format(_T("File alignment:               {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.FileAlignment)));
            logger_.log(format(_T("Size of image:                {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.SizeOfImage)));
            logger_.log(format(_T("Size of headers:              {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.SizeOfHeaders)));
            logger_.log(format(_T("Subsystem:                    {:#06x}"), static_cast<WORD>(peStructure.ntHeader32->OptionalHeader.Subsystem)));
            logger_.log(format(_T("Number of RVA and sizes:      {:#010x}"), static_cast<DWORD>(peStructure.ntHeader32->OptionalHeader.NumberOfRvaAndSizes)));
        }
        else
        {
            logger_.log(format(_T("Magic:                        {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.Magic)));
            logger_.log(format(_T("Entry point address:          {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.AddressOfEntryPoint)));
            logger_.log(format(_T("Image base address:           {:#018x}"), static_cast<ULONGLONG>(peStructure.ntHeader64->OptionalHeader.ImageBase)));
            logger_.log(format(_T("Section alignment:            {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.SectionAlignment)));
            logger_.log(format(_T("File alignment:               {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.FileAlignment)));
            logger_.log(format(_T("Size of image:                {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.SizeOfImage)));
            logger_.log(format(_T("Size of headers:              {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.SizeOfHeaders)));
            logger_.log(format(_T("Subsystem:                    {:#06x}"), static_cast<WORD>(peStructure.ntHeader64->OptionalHeader.Subsystem)));
            logger_.log(format(_T("Number of RVA and sizes:      {:#010x}"), static_cast<DWORD>(peStructure.ntHeader64->OptionalHeader.NumberOfRvaAndSizes)));
        }
        logger_.log(LINE_SPLIT);
    };

    void PEPrint::printSectionHeader(const PE_STRUCT& peStructure)
    {
        for (auto const& element : peStructure.sectionList)
        {
            logger_.log(format(_T("Section Name: {:s}"), element.Name));
            logger_.log(format(_T("          > VirtualAddress:   {:#010x}"), element.VirtualAddress));
            logger_.log(format(_T("          > PointerToRawData: {:#010x}"), element.PointerToRawData));
            logger_.log(format(_T("          > SizeOfRawData:    {:#010x}"), element.SizeOfRawData));
            logger_.log(format(_T("          > Characteristics:  {:#010x}"), element.Characteristics));
        }
        logger_.log(LINE_SPLIT);
    };

    void PEPrint::printEAT(const PE_STRUCT& peStructure)
    {
        if (!peStructure.exportFunctionList.empty())
        {
            for (auto const& element : peStructure.exportFunctionList)
            {
                logger_.log(format(_T("EAT Module: {:s} ({:d})"), get<0>(element), get<1>(element).size()));

                for (auto const& funcElement : get<1>(element))
                {
                    if (peStructure.is32Bit)
                    {
                        logger_.log(format(_T("          > {:#010x}, {:#06x}, {:s}"), funcElement.Address, funcElement.Ordinal, funcElement.Name));
                    }
                    else
                    {
                        logger_.log(format(_T("          > {:#018x}, {:#06x}, {:s}"), funcElement.Address, funcElement.Ordinal, funcElement.Name));
                    }
                }

                logger_.log(_T("\n"));
            }
            logger_.log(LINE_SPLIT);
        }
    };

    void PEPrint::printIAT(const PE_STRUCT& peStructure)
    {
        if (!peStructure.importFunctionList.empty())
        {
            for (auto const& element : peStructure.importFunctionList)
            {
                logger_.log(format(_T("IAT Module: {:s} ({:d})"), get<0>(element), get<1>(element).size()));

                for (auto const& funcElement : get<1>(element))
                {
                    if (peStructure.is32Bit)
                    {
                        logger_.log(format(_T("          > {:#010x}, {:#06x}, {:s}"), funcElement.Address, funcElement.Ordinal, funcElement.Name));
                    }
                    else
                    {
                        logger_.log(format(_T("          > {:#018x}, {:#06x}, {:s}"), funcElement.Address, funcElement.Ordinal, funcElement.Name));
                    }
                }

                logger_.log(_T("\n"));
            }
            logger_.log(LINE_SPLIT);
        }
    };

    void PEPrint::printTLS(const PE_STRUCT& peStructure)
    {
        if (peStructure.tlsCallbackList.size() > 0)
        {
            logger_.log(format(_T("TLS AddressOfCallBacks: ({})"), peStructure.tlsCallbackList.size()));

            for (auto const& element : peStructure.tlsCallbackList)
            {
                if (peStructure.is32Bit)
                {
                    logger_.log(format(_T("          > {:#010x}"), element.TlsCallbackAddress));
                }
                else
                {
                    logger_.log(format(_T("          > {:#010x}"), element.TlsCallbackAddress));
                }
            }
            logger_.log(LINE_SPLIT);
        }
    };

    void PEPrint::printPEStructure(const PE_STRUCT& peStructure)
    {
        printBaseAddress(peStructure);
        printDosHeader(peStructure);
        printNTHeader(peStructure);
        printSectionHeader(peStructure);
        printEAT(peStructure);
        printIAT(peStructure);
        printTLS(peStructure);
    };

};

