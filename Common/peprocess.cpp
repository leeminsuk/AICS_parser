#include "peprocess.h"

namespace peparser
{
    PEProcess::PEProcess()
        : isPE_(false), is32bit_(true), processBaseAddress_(0), baseAddress_(0), pid_(0), sizeOfImage_(0), sizeOfHeaders_(0), numberOfSections_(0),
        peb_({ 0, }), ntQueryInformationProcess_(nullptr), fileMapping_(nullptr), processHandle_(nullptr), threadHandle_(nullptr), sectionList_(nullptr)
    {
        logger_.setLogType(LOG_LEVEL_ERROR, LOG_DIRECTION_CONSOLE, TRUE);

        HMODULE hModule = GetModuleHandle(_T("ntdll.dll"));
        if (hModule != NULL)
        {
            ntQueryInformationProcess_ = (PNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
            if (ntQueryInformationProcess_ == NULL)
            {
                logger_.log(_T("Get NtQueryInformationProcess address fail.}"), LogLevel::LOG_LEVEL_ERROR);
            }
        }
    };

    PEProcess::~PEProcess()
    {
        close();
    };

    bool PEProcess::parseImageBaseAddress(void)
    {
        bool result = false;
        size_t readData = 0;
        NTSTATUS status = 0;
        HANDLE procHeap = NULL;
        PROCESS_BASIC_INFORMATION processBasicInformation = { 0, };
        BYTE moduleNameBuffer[MAX_PATH * 4] = { 0, };
        PEB_LDR_DATA pebLdrData = { 0, };
        PLDR_DATA_TABLE_ENTRY pFirstListEntry = NULL;
        LDR_DATA_TABLE_ENTRY ldrDataTable = { 0, };

        if ((processHandle_ != NULL) && (ntQueryInformationProcess_ != NULL))
        {
            // 프로세스로부터 ROCESS_BASIC_INFORMATION 정보를 얻음
            status = ntQueryInformationProcess_(
                processHandle_, 
                ProcessBasicInformation, 
                &processBasicInformation, 
                sizeof(PROCESS_BASIC_INFORMATION), 
                reinterpret_cast<PULONG>(&readData));

            if (NT_SUCCESS(status))
            {
                if (processBasicInformation.PebBaseAddress != NULL)
                {
                    if (ReadProcessMemory(processHandle_, processBasicInformation.PebBaseAddress, &peb_, sizeof(PEB), &readData))
                    {
                        // 프로세스의 Image Base Address가 저장되어 있는 필드
                        // OS 내부적으로 사용한다고 되어 있어서 향후에는 사용하지 못할 수 있음
                        // (ToolHelp32 API를 통해서 구하는 방법도 있음)
                        processBaseAddress_ = reinterpret_cast<size_t>(peb_.Reserved3[1]);
                        if (processBaseAddress_ != NULL)
                        {
                            logger_.log(format(_T("Process image base address : 0x{:x}"), processBaseAddress_), LOG_LEVEL_DEBUG);

                            if (ReadProcessMemory(processHandle_, peb_.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA), &readData))
                            {
                                // CONTAINING_RECORD 매크로 
                                // - 구조체안의 특정 field의 주소를 통해서 그 field를 포함하고 있는 실제 구조체(객체)의 주소를 얻을 수 있는 방법
                                // - 첫번째 인자인 Address에는 현재알고 있는 구조체 필드의 포인터를 입력하고 
                                //   두번째 인자는 알고자 하는 구조체 타입을 
                                //   세번째 인자는 두번째 구조체 내의 필드 이름을 넣어줌
                                //   그러면 두 번째에 입력했던 구조체의 주소를 리턴함
                                pFirstListEntry = CONTAINING_RECORD(pebLdrData.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                                if (pFirstListEntry != NULL)
                                {
                                    if (ReadProcessMemory(processHandle_, pFirstListEntry, &ldrDataTable, sizeof(LDR_DATA_TABLE_ENTRY), &readData))
                                    {
                                        if (reinterpret_cast<ULONGLONG>(ldrDataTable.DllBase) != 0)
                                        {
                                            // 맨 처음 항목이 프로세스 자신
                                            if (ReadProcessMemory(processHandle_, ldrDataTable.FullDllName.Buffer, moduleNameBuffer, ldrDataTable.FullDllName.Length, &readData))
                                            {
                                                filePath_ = strConv_.to_tstring(reinterpret_cast<wchar_t*>(moduleNameBuffer));
                                                logger_.log(format(_T("Module : 0x{:x}, {:s}"), reinterpret_cast<size_t>(ldrDataTable.DllBase), filePath_), LOG_LEVEL_DEBUG);
                                            }
                                        }
                                    }
                                }
                            }
                            result = true;
                        }
                        else
                        {
                            logger_.log(_T("Get image base address fail"), GetLastError(), LOG_LEVEL_ERROR);
                        }
                    }
                    else
                    {
                        logger_.log(_T("ReadProcessMemory fail"), GetLastError(), LOG_LEVEL_ERROR);
                    }
                }
            }
        }
        return result;
    };

    bool PEProcess::parseBasicInfo(void)
    {
        size_t readSize = 0;
        vector<BYTE> readBuffer(4096);
        size_t currentAddress = NULL;
        PIMAGE_FILE_HEADER fileHeader = NULL;

        if (ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(processBaseAddress_), reinterpret_cast<LPVOID>(readBuffer.data()), readBuffer.size(), &readSize) && (readSize == readBuffer.size()))
        {
            currentAddress = reinterpret_cast<size_t>(readBuffer.data());
            fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(currentAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(currentAddress)->e_lfanew + sizeof(DWORD));
            is32bit_ = (fileHeader->Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE;

            currentAddress = reinterpret_cast<size_t>(fileHeader) + sizeof(IMAGE_FILE_HEADER);
            if (is32bit_)
            {
                sizeOfImage_ = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(currentAddress)->SizeOfImage;
            }
            else
            {
                sizeOfImage_ = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(currentAddress)->SizeOfImage;
            }
            isPE_ = true;
        }
        return isPE_;
    };

    bool PEProcess::createFileMapping(const size_t& pid)
    {
        bool result = false;
        SIZE_T readSize = 0;

        if (sizeOfImage_ != 0)
        {
            // Create file mapping.
            fileMapping_ = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, static_cast<DWORD>(sizeOfImage_), NULL);
            if (fileMapping_ != NULL)
            {
                // Get address from memory mapped file.
                baseAddress_ = reinterpret_cast<size_t>(MapViewOfFile(fileMapping_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
                if (baseAddress_ != NULL)
                {
                    result = ReadProcessMemory(processHandle_, (LPCVOID)processBaseAddress_, (LPVOID)baseAddress_, sizeOfImage_, &readSize) && (readSize == sizeOfImage_);
                }
            }
            if (!result)
            {
                logger_.log(format(_T("Error: Cannot create file mapping - {}"), pid), GetLastError(), LOG_LEVEL_ERROR);
            }
        }
        return result;
    }

    bool PEProcess::open(const size_t& pid)
    {
        bool result = false;

        if (pid > 0x4)
        {
            processHandle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
            if (processHandle_ != NULL)
            {
                if (parseImageBaseAddress() && parseBasicInfo() && createFileMapping(pid))
                {
                    pid_ = pid;
                    isPE_ = true;
                    result = true;
                }
                else
                {
                    // Image Base Address를 얻지 못한 경우 실패로 처리(변수 초기화)
                    close();
                    logger_.log(format(_T("Open process fail : get image base address fail - {}"), pid), LOG_LEVEL_ERROR);
                }
            }
            else
            {
                logger_.log(format(_T("Open process fail - {}"), pid), GetLastError(), LOG_LEVEL_ERROR);
            }
        }
        return result;
    };

    void PEProcess::close(void)
    {
        // 핸들 초기화
        if (threadHandle_ != NULL)
        {
            CloseHandle(threadHandle_);
            threadHandle_ = NULL;
        }
        if (processHandle_ != NULL)
        {
            CloseHandle(processHandle_);
            processHandle_ = NULL;
        }
        if (fileMapping_ != INVALID_HANDLE_VALUE)
        {
            if (baseAddress_ != NULL)
            {
                UnmapViewOfFile(reinterpret_cast<void*>(baseAddress_));
                baseAddress_ = NULL;
            }
            CloseHandle(fileMapping_);
            fileMapping_ = INVALID_HANDLE_VALUE;
        }

        // 변수 초기화
        pid_ = 0;
        isPE_ = false;
        is32bit_ = false;
        baseAddress_ = 0;
        processBaseAddress_ = 0;
        sizeOfHeaders_ = 0;
        numberOfSections_ = 0;
        sectionList_ = nullptr;
        memset(&peb_, 0, sizeof(PEB));
        filePath_.clear();
    };

    bool PEProcess::isPE(void) const
    {
        return isPE_;
    };

    bool PEProcess::is32bit(void) const
    {
        return is32bit_;
    };

    const tstring PEProcess::getFilePath(void) const
    {
        return filePath_;
    };

    size_t PEProcess::getBaseAddress(void) const
    {
        return baseAddress_;
    };

    bool PEProcess::getRealAddress(const size_t& rva, size_t& raw) const
    {
        // 프로세스 메모리에서는 RAW를 계산할 필요가 없음
        raw = (size_t)baseAddress_ + rva;
        return true;
    };

    bool PEProcess::getData(const size_t& address, const size_t& size, BinaryData& data) const
    {
        bool result = false;
        size_t readSize = 0;

        // 벡터 크기 조정
        data.resize(size);

        if (sizeOfImage_ < (address + size))
        {
            if (ReadProcessMemory(processHandle_, reinterpret_cast<LPCVOID>(address), 
                reinterpret_cast<LPVOID>(data.data()), size, &readSize) && (readSize == size))
            {
                result = true;
            }
        }
        else
        {
            if (memcpy_s(data.data(), size, reinterpret_cast<const void*>(address), size) == 0)
            {
                result = true;
            }
        }
        if (!result)
        {
            data.clear();
        }
        return result;
    };

    void PEProcess::setHeaderSize(const size_t& sizeOfHeaders)
    {
        sizeOfHeaders_ = sizeOfHeaders;
    };

    void PEProcess::setSectionList(const SectionList& sectionList)
    {
        sectionList_ = const_cast<SectionList*>(&sectionList);
    };
};
