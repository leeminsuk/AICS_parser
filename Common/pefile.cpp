#include "pefile.h"

namespace peparser
{
    PEFile::PEFile()
        : isPE_(false), is32bit_(false), baseAddress_(0), sizeOfImage_(0), sizeOfHeaders_(0), numberOfSections_(0), 
        fileHandle_(INVALID_HANDLE_VALUE), fileMapping_(INVALID_HANDLE_VALUE), sectionList_(nullptr)

    {
        logger_.setLogType(LOG_LEVEL_ERROR, LOG_DIRECTION_CONSOLE, TRUE);
    };

    PEFile::~PEFile()
    {
        close();
    };

    bool PEFile::open(const tstring_view& filePath, const bool& forceOpen)
    {
        bool result = FALSE;
        size_t fileSize = 0;
        DWORD readLength = 0;
        WORD signature = 0;

        logger_.log(format(_T("Create memory map for {:s}"), filePath), LOG_LEVEL_DEBUG);

        fileHandle_ = CreateFile(filePath.data(),
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY, NULL);
        if (fileHandle_ == INVALID_HANDLE_VALUE)
        {
            logger_.log(format(_T("Error: Cannot open file - {}"), filePath), GetLastError(), LOG_LEVEL_ERROR);
        }
        else
        {
            // Calculate file size
            sizeOfImage_ = GetFileSize(fileHandle_, reinterpret_cast<DWORD*>(&fileSize) + 1) | fileSize;

            // PE file check - first, check DOS_HEADER signature.
            if (ReadFile(fileHandle_, &signature, sizeof(WORD), &readLength, NULL))
            {
                // first PE file check pass or 'forceOpen' is true.
                if ((signature == IMAGE_DOS_SIGNATURE) || forceOpen)
                {
                    // Create file mapping.
                    fileMapping_ = CreateFileMapping(fileHandle_, NULL, PAGE_READONLY, 0, 0, NULL);
                    if (fileMapping_ == NULL)
                    {
                        logger_.log(format(_T("Error: Cannot create file mapping - {}"), filePath), 
                            GetLastError(), LOG_LEVEL_ERROR);
                    }
                    else
                    {
                        // Get address from memory mapped file.
                        baseAddress_ = reinterpret_cast<size_t>(MapViewOfFile(fileMapping_, FILE_MAP_READ, 0, 0, 0));
                        if (baseAddress_ != NULL)
                        {
                            // PE file check - second, check FILE_HEADER signature.
                            PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress_);
                            signature = static_cast<WORD>(*(reinterpret_cast<DWORD*>(baseAddress_ + dosHeader->e_lfanew)));

                            if (signature == IMAGE_NT_SIGNATURE)
                            {
                                // if the file is 32bit PE then set 'is32bit' to true.
                                PIMAGE_FILE_HEADER fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(baseAddress_ + dosHeader->e_lfanew + sizeof(DWORD));
                                is32bit_ = (fileHeader->Characteristics & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE;

                                isPE_ = true;
                                result = true;
                            }
                            else
                            {
                                // File is not PE file.
                                isPE_ = false;

                                // if 'forceOpen' is true then set the result to true.
                                if (forceOpen)
                                {
                                    result = true;
                                }
                                else
                                {
                                    logger_.log(format(_T("Info: not PE file - {}"), filePath), LOG_LEVEL_ERROR);
                                }
                            }
                        }
                        else
                        {
                            logger_.log(_T("Error: Cannot map view of file"), GetLastError(), LOG_LEVEL_ERROR);
                        }
                    }
                }
            }
            if (result)
            {
                filePath_ = filePath;
            }
            else
            {
                close();
            }
        }
        return result;
    };

    void PEFile::close(void)
    {
        // 핸들 초기화
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
        if (fileHandle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(fileHandle_);
            fileHandle_ = INVALID_HANDLE_VALUE;
        }

        // 변수 값 초기화
        isPE_ = false;
        is32bit_ = false;
        baseAddress_ = 0;
        sizeOfHeaders_ = 0;
        numberOfSections_ = 0;
        sectionList_ = nullptr;
    };

    bool PEFile::isPE(void) const
    {
        return isPE_;
    };

    bool PEFile::is32bit(void) const
    {
        return is32bit_;
    };

    const tstring PEFile::getFilePath(void) const
    {
        return filePath_;
    };

    size_t PEFile::getBaseAddress(void) const
    {
        return baseAddress_;
    };

	bool PEFile::getRealAddress(const size_t& rva, size_t& raw) const
	{
        bool result = false;

        if (rva < sizeOfHeaders_)
        {
            // 헤더 영역까지는 RVA to RAW 계산이 불필요
            raw = baseAddress_ + rva;
        }
        else
        {
            size_t endAddress = 0;
            for (const auto& section : (*sectionList_))
            {
                // 현재 설정된 섹션 범위에 있는지 확인
                endAddress = section.VirtualAddress + section.SizeOfRawData;
                if ((rva >= section.VirtualAddress) && (rva < endAddress))
                {
                    // RVA to RAW 계산 (RAW = RVA - VirtualAddress + PointerToRawData)
                    raw =  rva - section.VirtualAddress + section.PointerToRawData;

                    // 데이터를 참조하기 위해서는 메모리 맵 뷰의 시작 주소(baseAddress_)를 더해 주어야 함
                    raw += baseAddress_;

                    result = true;
                    break;
                }
            }
            if (!result)
            {
                // 파일인 경우 실제 실행 중이 아닌 경우 RVA to RAW 계산이 불가능한 경우가 있음
                // 초기화 되지 않은 배열 등과 같이 메모리에 로드될 때 공간 할당이 되는 경우 발생할 수 있음
                raw = 0;
                logger_.log(format(_T("RVA to RAW fail : 0x{:x}"), rva), LOG_LEVEL_DEBUG);
            }
        }
        return result;
	};

    bool PEFile::getData(const size_t& address, const size_t& size, BinaryData& data) const
    {
        bool result = false;

        if (sizeOfImage_ < (address + size))
        {
            data.resize(size);
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

    void PEFile::setHeaderSize(const size_t& sizeOfHeaders)
    {
        sizeOfHeaders_ = sizeOfHeaders;
    };

    void PEFile::setSectionList(const SectionList& sectionList)
    {
        sectionList_ = const_cast<SectionList*>(&sectionList);
    };
};
