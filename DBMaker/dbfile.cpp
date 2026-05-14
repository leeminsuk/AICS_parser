#include "dbfile.h"
#include <format>

namespace dbmaker
{
    // ──────────────────────────────────────────────
    // 내부 유틸리티
    // ──────────────────────────────────────────────

    void DBFile::setBit(BYTE* bloomFilter, const DWORD bitIndex)
    {
        // bitIndex / 8 → 바이트 인덱스, bitIndex % 8 → 바이트 내 비트 위치
        // 연속된 비트 배열처럼 처리하기 위해 비트 위치를 반전(BIT_FLAG[7 - pos])
        bloomFilter[bitIndex / 8] |= BIT_FLAG[7 - (bitIndex % 8)];
    }

    bool DBFile::getBit(const BYTE* bloomFilter, const DWORD bitIndex) const
    {
        return (bloomFilter[bitIndex / 8] & BIT_FLAG[7 - (bitIndex % 8)]) != 0;
    }

    BinaryData DBFile::getHashBytesFromHexString(const tstring& hashHexString)
    {
        BinaryData hashBytes;
        for (size_t index = 0; index + 1 < hashHexString.size(); index += 2)
        {
            hashBytes.push_back(
                static_cast<BYTE>(std::stoi(hashHexString.substr(index, 2), nullptr, 16)));
        }
        return hashBytes;
    }

    bool DBFile::saveDataToFile(const tstring& saveFilePath, const BinaryData& binaryData) const
    {
        bool result = false;
        std::ofstream fileOut;
        fileOut.open(saveFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (fileOut.is_open())
        {
            fileOut.write(reinterpret_cast<const char*>(binaryData.data()),
                          static_cast<std::streamsize>(binaryData.size()));
            fileOut.close();
            result = true;
        }
        return result;
    }

    // ──────────────────────────────────────────────
    // CSV 파일 로드
    // ──────────────────────────────────────────────

    bool DBFile::getDetectHashInfo(const tstring& csvFilePath, DetectHashInfoList& detectHashInfoList)
    {
        bool result   = false;
        size_t strPos = 0;
        tstring hashString;
        std::u8string nameString;
        u8ifstream csvFile;

        // tstring → 파일 경로 변환 (UNICODE 빌드 대응)
#if defined(UNICODE) || defined(_UNICODE)
        csvFile.open(std::filesystem::path(csvFilePath));
#else
        csvFile.open(csvFilePath);
#endif

        if (csvFile.is_open())
        {
            // for 초기화식 내에서 std::getline() 호출하여 변수 선언과 읽기를 동시에 처리
            for (std::u8string line; std::getline(csvFile, line);)
            {
                strPos = line.find(u8',');
                if (strPos != std::u8string::npos && strPos > 0)
                {
                    // hash 부분은 stoi()가 u8string을 처리 못하므로 char로 재해석
                    hashString = strConv_.to_tstring(
                        reinterpret_cast<const char*>(line.substr(0, strPos).c_str()));
                    nameString = line.substr(strPos + 1);

                    // ltrim / rtrim
                    hashString.erase(0, hashString.find_first_not_of(_T(" \t\n\r\f\v")));
                    hashString.erase(hashString.find_last_not_of(_T(" \t\n\r\f\v")) + 1);
                    nameString.erase(0, nameString.find_first_not_of(u8" \t\n\r\f\v"));
                    nameString.erase(nameString.find_last_not_of(u8" \t\n\r\f\v") + 1);

                    if (!hashString.empty() && !nameString.empty())
                    {
                        result = true;
                        detectHashInfoList.push_back(
                            DetectHashInfo{ nameString, getHashBytesFromHexString(hashString) });
                    }
                }
            }
            csvFile.close();
        }
        return result;
    }

    // ──────────────────────────────────────────────
    // 탐지명 파일(.nam) 생성
    // ──────────────────────────────────────────────

    bool DBFile::makeNameDB(const tstring& dirPath,
                            const DetectHashInfoList& detectHashInfoList,
                            DetectNameInfoMap& detectNameInfoMap)
    {
        bool result      = false;
        WORD dataLength  = 0;
        DWORD currentOffset = 0;
        std::ofstream fileOut;
        tstring filePath = std::filesystem::path(dirPath)
                               .append(malwareDBFileName_.c_str())
                               .c_str()
                           + malwareNameExt_;
        std::map<std::u8string, bool> uniqueCheck;

        fileOut.open(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (fileOut.is_open())
        {
            for (const auto& element : detectHashInfoList)
            {
                // 중복 탐지명 건너뜀
                if (uniqueCheck.find(element.DetectName) == uniqueCheck.end())
                {
                    // 현재 파일 위치를 offset으로 저장
                    currentOffset = static_cast<DWORD>(fileOut.tellp());
                    detectNameInfoMap.insert(std::pair(element.DetectName, currentOffset));
                    uniqueCheck.insert(std::pair(element.DetectName, true));

                    // NULL 문자('\0') 포함한 길이로 파일에 기록
                    dataLength = static_cast<WORD>(element.DetectName.size() + 1);
                    write_typed_data(fileOut, element.DetectName, dataLength);

                    result = true;
                }
            }
            fileOut.close();
        }
        return result;
    }

    // ──────────────────────────────────────────────
    // 블룸 필터 파일(.blf) 생성
    // 6개의 24bit 해시 함수 사용:
    //   #1 : CRC16(MD5 bytes) [2 bytes] + MD5[0]  [1 byte]
    //   #2 : MD5[1..3]
    //   #3 : MD5[4..6]
    //   #4 : MD5[7..9]
    //   #5 : MD5[10..12]
    //   #6 : MD5[13..15]
    // ──────────────────────────────────────────────

    bool DBFile::makeBloomFilterDB(const tstring& dirPath,
                                   const DetectHashInfoList& detectHashInfoList,
                                   DetectCrc16List& crc16List)
    {
        bool result = false;
        WORD crc16Value = 0;
        DWORD hashValueLength = sizeof(WORD);
        BYTE bitHashValue24[BYTE_COUNT_DWORD] = { 0, };   // 24bit를 DWORD로 처리하기 위한 4byte 배열
        BinaryData binaryData;
        tstring filePath = std::filesystem::path(dirPath)
                               .append(malwareDBFileName_.c_str())
                               .c_str()
                           + malwareFilterExt_;

        // 블룸 필터 비트셋 초기화 (24bit = 16,777,216 bit = 2,097,152 byte)
        binaryData.assign(BLOOM_FILTER_SIZE, 0);

        for (const auto& element : detectHashInfoList)
        {
            const BinaryData& hashData = element.DetectHash;
            if (hashData.size() < 16) continue;

            // CRC16 계산
            if (hash_.open(HASH_TYPE_CRC16))
            {
                hash_.calculateHash(hashData.data(), static_cast<DWORD>(hashData.size()), true);
                crc16Value = *reinterpret_cast<const WORD*>(hash_.getHashBytes().data());
                hash_.close();
            }

            // ── 해시 함수 #1: CRC16(2byte) + MD5[0](1byte) → 24bit ──
            memcpy(bitHashValue24, &crc16Value, sizeof(WORD));
            bitHashValue24[2] = hashData.data()[0];
            bitHashValue24[3] = 0x00;  // Little Endian: 최상위 바이트 = 0 (24bit 마스킹)
            setBit(binaryData.data(), *reinterpret_cast<DWORD*>(bitHashValue24));

            // ── 해시 함수 #2: MD5[1..3] → 24bit ──
            memcpy(bitHashValue24, hashData.data() + 1, BYTE_COUNT_24BIT);
            bitHashValue24[3] = 0x00;
            setBit(binaryData.data(), *reinterpret_cast<DWORD*>(bitHashValue24));

            // ── 해시 함수 #3: MD5[4..6] → 24bit ──
            memcpy(bitHashValue24, hashData.data() + 4, BYTE_COUNT_24BIT);
            bitHashValue24[3] = 0x00;
            setBit(binaryData.data(), *reinterpret_cast<DWORD*>(bitHashValue24));

            // ── 해시 함수 #4: MD5[7..9] → 24bit ──
            memcpy(bitHashValue24, hashData.data() + 7, BYTE_COUNT_24BIT);
            bitHashValue24[3] = 0x00;
            setBit(binaryData.data(), *reinterpret_cast<DWORD*>(bitHashValue24));

            // ── 해시 함수 #5: MD5[10..12] → 24bit ──
            memcpy(bitHashValue24, hashData.data() + 10, BYTE_COUNT_24BIT);
            bitHashValue24[3] = 0x00;
            setBit(binaryData.data(), *reinterpret_cast<DWORD*>(bitHashValue24));

            // ── 해시 함수 #6: MD5[13..15] → 24bit ──
            memcpy(bitHashValue24, hashData.data() + 13, BYTE_COUNT_24BIT);
            bitHashValue24[3] = 0x00;
            setBit(binaryData.data(), *reinterpret_cast<DWORD*>(bitHashValue24));

            // CRC16 값은 해시 테이블 버킷 탐색에도 사용
            crc16List.push_back(crc16Value);
        }

        if (!crc16List.empty())
        {
            result = saveDataToFile(filePath, binaryData);
        }
        return result;
    }

    // ──────────────────────────────────────────────
    // 해시 테이블 파일(.has) 생성
    // Bucket: 16bit = 65,536개 × 4byte(DWORD) = 256KB
    // Node  : MD5(16) + detectNameOffset(4) + nextIndex(4) = 24byte
    // ──────────────────────────────────────────────

    bool DBFile::makeHashDB(const tstring& dirPath,
                            const DetectHashInfoList& detectHashInfoList,
                            const DetectCrc16List& crc16List,
                            const DetectNameInfoMap& detectNameInfoMap)
    {
        bool result = false;
        DWORD nextIndex = 0;
        PDWORD bucketPtr = nullptr;
        DWORD linkedListItemIndex = 0;
        PLINKED_LIST_ITEM linkedListItemPtr = nullptr;
        tstring filePath = std::filesystem::path(dirPath)
                               .append(malwareDBFileName_.c_str())
                               .c_str()
                           + malwareHashExt_;
        BinaryData binaryData;

        /*
         * 해시 테이블 전체 크기:
         *   버킷 영역 : HASH_TABLE_BUCKET_SIZE (= 65,536 * 4 = 262,144 byte)
         *   노드 영역 : sizeof(LINKED_LIST_ITEM) * 패턴 수
         */
        binaryData.assign(HASH_TABLE_BUCKET_SIZE +
                          detectHashInfoList.size() * sizeof(LINKED_LIST_ITEM), 0);

        // 버킷 시작 주소 및 버킷 초기값 -1(0xFFFFFFFF)로 설정
        bucketPtr = reinterpret_cast<PDWORD>(binaryData.data());
        memset(binaryData.data(), -1, HASH_TABLE_BUCKET_SIZE);

        // 노드(LINKED_LIST_ITEM) 배열 시작 주소
        linkedListItemPtr = reinterpret_cast<PLINKED_LIST_ITEM>(
            binaryData.data() + HASH_TABLE_BUCKET_SIZE);
        linkedListItemIndex = 0;

        for (DWORD index = 0; index < static_cast<DWORD>(detectHashInfoList.size()); index++)
        {
            const auto& nameInfo = detectNameInfoMap.find(detectHashInfoList[index].DetectName);
            if (nameInfo == detectNameInfoMap.end()) continue;

            const BinaryData& detectHash = detectHashInfoList[index].DetectHash;
            if (detectHash.size() < 16) continue;

            // 새 LINKED_LIST_ITEM 등록
            LINKED_LIST_ITEM& hashItem = linkedListItemPtr[linkedListItemIndex];
            memcpy_s(hashItem.md5Hash, sizeof(hashItem.md5Hash),
                     detectHash.data(), detectHash.size());
            hashItem.detectNameOffset = nameInfo->second;
            hashItem.nextIndex = 0;  // 새 항목이므로 연결된 항목 없음

            // 버킷 인덱스: CRC16 값
            WORD bucketIndex = crc16List[index];
            nextIndex = bucketPtr[bucketIndex];

            if (nextIndex == 0xFFFFFFFF)
            {
                // 버킷에 첫 번째 항목 등록
                bucketPtr[bucketIndex] = linkedListItemIndex;
            }
            else
            {
                // linked list 마지막 항목에 연결
                do
                {
                    if (linkedListItemPtr[nextIndex].nextIndex == 0)
                    {
                        linkedListItemPtr[nextIndex].nextIndex = linkedListItemIndex;
                        break;
                    }
                    else
                    {
                        nextIndex = linkedListItemPtr[nextIndex].nextIndex;
                    }
                } while (nextIndex < static_cast<DWORD>(detectHashInfoList.size()));
            }

            linkedListItemIndex++;
        }

        if (!binaryData.empty())
        {
            result = saveDataToFile(filePath, binaryData);
        }
        return result;
    }

    // ──────────────────────────────────────────────
    // 전체 DB 파일 생성
    // ──────────────────────────────────────────────

    bool DBFile::makeDBFile(const tstring& csvFilePath, const tstring& dbDirPath)
    {
        bool result = false;
        DetectHashInfoList detectHashInfoList;
        DetectNameInfoMap  detectNameInfoMap;
        DetectCrc16List    crc16List;

        // 1. CSV에서 악성코드 해시 목록 로드
        if (getDetectHashInfo(csvFilePath, detectHashInfoList))
        {
            // 탐지 테스트용 추가 데이터(.test 파일)
            std::filesystem::path testFile(csvFilePath + _T(".test"));
            if (std::filesystem::exists(testFile))
            {
                getDetectHashInfo(testFile.c_str(), detectHashInfoList);
            }

            // 2. 탐지명 파일 생성
            if (makeNameDB(dbDirPath, detectHashInfoList, detectNameInfoMap))
            {
                // 3. 블룸 필터 파일 생성 (6개 24bit 해시 함수)
                if (makeBloomFilterDB(dbDirPath, detectHashInfoList, crc16List))
                {
                    // 4. 해시 테이블 파일 생성
                    result = makeHashDB(dbDirPath, detectHashInfoList, crc16List, detectNameInfoMap);
                }
            }
        }
        return result;
    }
}
