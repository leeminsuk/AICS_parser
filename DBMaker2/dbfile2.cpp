#include "dbfile2.h"
#include <iostream>
#include <numeric>

namespace dbmaker2
{
    // ──────────────────────────────────────────────────────────────────────
    // 비트 조작
    // ──────────────────────────────────────────────────────────────────────

    void DBFile2::setBit(BYTE* bloomFilter, DWORD bitIndex) const
    {
        bloomFilter[bitIndex / 8] |= BIT_FLAG[7 - (bitIndex % 8)];
    }

    bool DBFile2::getBit(const BYTE* bloomFilter, DWORD bitIndex) const
    {
        return (bloomFilter[bitIndex / 8] & BIT_FLAG[7 - (bitIndex % 8)]) != 0;
    }

    // ──────────────────────────────────────────────────────────────────────
    // 내부 유틸리티
    // ──────────────────────────────────────────────────────────────────────

    BinaryData DBFile2::hexToBinary(const std::u8string& hexStr) const
    {
        // u8string hex → BinaryData (16 bytes for MD5)
        // MD5 hex는 순수 ASCII이므로 char로 재해석해도 안전
        BinaryData bytes;
        const char* p = reinterpret_cast<const char*>(hexStr.c_str());
        size_t len = hexStr.size();
        bytes.reserve(len / 2);
        for (size_t i = 0; i + 1 < len; i += 2)
        {
            char buf[3] = { p[i], p[i + 1], '\0' };
            bytes.push_back(static_cast<BYTE>(std::strtoul(buf, nullptr, 16)));
        }
        return bytes;
    }

    // [Fix] 파일 경로 생성: std::filesystem::path::operator/ 사용 (dangling pointer 위험 제거)
    tstring DBFile2::buildPath(const tstring& dir, const tstring& ext) const
    {
        return (std::filesystem::path(dir) / DB_FILE_NAME).native() + ext;
    }

    bool DBFile2::saveWithHeader(const tstring& path,
                                  const BinaryData& body,
                                  uint32_t count) const
    {
        std::ofstream f(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;

        DBFileHeader hdr{};
        memcpy(hdr.magic, DB_MAGIC, 4);
        hdr.version  = DB_VERSION;
        hdr.count    = count;
        hdr.reserved = 0;

        f.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        f.write(reinterpret_cast<const char*>(body.data()),
                static_cast<std::streamsize>(body.size()));
        f.close();
        return true;
    }

    // ──────────────────────────────────────────────────────────────────────
    // 블룸 필터 조회 (6개 해시 함수 동일 적용)
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::bloomMayContain(const BYTE* bloomData,
                                   const BinaryData& md5Hash,
                                   WORD crc16) const
    {
        if (md5Hash.size() < 16) return false;

        BYTE b[4] = { 0 };

        // Hash #1: CRC16 [2byte] + MD5[0] [1byte]
        memcpy(b, &crc16, 2); b[2] = md5Hash[0]; b[3] = 0;
        if (!getBit(bloomData, *reinterpret_cast<const DWORD*>(b))) return false;

        // Hash #2: MD5[1..3]
        memcpy(b, md5Hash.data() + 1, 3); b[3] = 0;
        if (!getBit(bloomData, *reinterpret_cast<const DWORD*>(b))) return false;

        // Hash #3: MD5[4..6]
        memcpy(b, md5Hash.data() + 4, 3); b[3] = 0;
        if (!getBit(bloomData, *reinterpret_cast<const DWORD*>(b))) return false;

        // Hash #4: MD5[7..9]
        memcpy(b, md5Hash.data() + 7, 3); b[3] = 0;
        if (!getBit(bloomData, *reinterpret_cast<const DWORD*>(b))) return false;

        // Hash #5: MD5[10..12]
        memcpy(b, md5Hash.data() + 10, 3); b[3] = 0;
        if (!getBit(bloomData, *reinterpret_cast<const DWORD*>(b))) return false;

        // Hash #6: MD5[13..15]
        memcpy(b, md5Hash.data() + 13, 3); b[3] = 0;
        if (!getBit(bloomData, *reinterpret_cast<const DWORD*>(b))) return false;

        return true;
    }

    // ──────────────────────────────────────────────────────────────────────
    // 해시 테이블 조회
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::hashTableLookup(const BYTE* tableData,
                                   size_t tableSize,
                                   const BinaryData& md5Hash,
                                   WORD crc16) const
    {
        if (tableSize < sizeof(DBFileHeader) + HASH_TABLE_BUCKET_SIZE) return false;
        if (md5Hash.size() < 16) return false;

        // 헤더 이후 버킷 배열 시작
        const DWORD* bucket = reinterpret_cast<const DWORD*>(tableData + sizeof(DBFileHeader));
        // 버킷 이후 노드 배열 시작
        const LINKED_LIST_ITEM* nodes = reinterpret_cast<const LINKED_LIST_ITEM*>(
            tableData + sizeof(DBFileHeader) + HASH_TABLE_BUCKET_SIZE);

        DWORD idx = bucket[crc16];
        const size_t maxNodes = (tableSize - sizeof(DBFileHeader) - HASH_TABLE_BUCKET_SIZE)
                                / sizeof(LINKED_LIST_ITEM);

        while (idx != NODE_NULL && idx < static_cast<DWORD>(maxNodes))
        {
            if (memcmp(nodes[idx].md5Hash, md5Hash.data(), 16) == 0)
                return true;
            idx = nodes[idx].nextIndex;
        }
        return false;
    }

    // ──────────────────────────────────────────────────────────────────────
    // CSV 로드
    // [Fix] to_tstring(u8string_view) 직접 사용 (char* 캐스트 불필요)
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::getDetectHashInfo(const tstring& csvPath, DetectHashInfoList& list)
    {
        bool result = false;
        std::basic_ifstream<char8_t, std::char_traits<char8_t>> f;
        f.open(std::filesystem::path(csvPath));
        if (!f.is_open()) return false;

        for (std::u8string line; std::getline(f, line);)
        {
            size_t pos = line.find(u8',');
            if (pos == std::u8string::npos || pos == 0) continue;

            std::u8string hashPart = line.substr(0, pos);
            std::u8string namePart = line.substr(pos + 1);

            // ltrim / rtrim
            auto ltrim = [](std::u8string& s) {
                s.erase(0, s.find_first_not_of(u8" \t\r\n\f\v"));
            };
            auto rtrim = [](std::u8string& s) {
                auto p = s.find_last_not_of(u8" \t\r\n\f\v");
                if (p != std::u8string::npos) s.erase(p + 1);
                else s.clear();
            };
            ltrim(hashPart); rtrim(hashPart);
            ltrim(namePart); rtrim(namePart);

            if (hashPart.empty() || namePart.empty()) continue;

            BinaryData md5Bytes = hexToBinary(hashPart);
            if (md5Bytes.size() != 16) continue;

            list.push_back(DetectHashInfo{ namePart, std::move(md5Bytes) });
            result = true;
        }
        f.close();
        return result;
    }

    // ──────────────────────────────────────────────────────────────────────
    // 탐지명 파일 (.nam) 생성
    // [New] DB 파일 헤더 포함
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::makeNameDB(const tstring& dirPath,
                              const DetectHashInfoList& list,
                              DetectNameInfoMap& nameMap)
    {
        tstring filePath = buildPath(dirPath, DB_EXT_NAME);
        std::ofstream f(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;

        // 헤더는 나중에 count가 확정된 후 덮어쓰기 위해 일단 빈 헤더 기록
        DBFileHeader hdr{};
        memcpy(hdr.magic, DB_MAGIC, 4);
        hdr.version = DB_VERSION;
        f.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

        std::map<std::u8string, bool> seen;
        uint32_t nameCount = 0;

        for (const auto& elem : list)
        {
            if (seen.count(elem.DetectName)) continue;

            DWORD offset = static_cast<DWORD>(
                static_cast<size_t>(f.tellp()) - sizeof(DBFileHeader));
            nameMap.insert({ elem.DetectName, offset });
            seen.insert({ elem.DetectName, true });

            // NULL 문자(\0) 포함하여 기록
            WORD len = static_cast<WORD>(elem.DetectName.size() + 1);
            f.write(reinterpret_cast<const char*>(elem.DetectName.data()), len);
            nameCount++;
        }

        // count 필드 업데이트 (파일 앞 헤더로 돌아가서 덮어쓰기)
        f.seekp(offsetof(DBFileHeader, count));
        f.write(reinterpret_cast<const char*>(&nameCount), sizeof(nameCount));
        f.close();
        return nameCount > 0;
    }

    // ──────────────────────────────────────────────────────────────────────
    // 블룸 필터 파일 (.blf) 생성
    // [New] DB 파일 헤더 포함
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::makeBloomFilterDB(const tstring& dirPath,
                                     const DetectHashInfoList& list,
                                     DetectCrc16List& crc16List)
    {
        BinaryData bloom(BLOOM_FILTER_SIZE, 0);
        WORD crc16Val = 0;
        BYTE b[4] = { 0 };
        size_t progress = 0;
        const size_t total = list.size();

        std::tcout << _T("[BloomFilter] 생성 중 (") << total << _T(" 패턴)...\n");

        for (const auto& elem : list)
        {
            const BinaryData& h = elem.DetectHash;
            if (h.size() < 16) { crc16List.push_back(0); continue; }

            // CRC16 계산
            if (hash_.open(HASH_TYPE_CRC16))
            {
                hash_.calculateHash(h.data(), static_cast<DWORD>(h.size()), true);
                crc16Val = *reinterpret_cast<const WORD*>(hash_.getHashBytes().data());
                hash_.close();
            }

            // Hash #1: CRC16 + MD5[0]
            memcpy(b, &crc16Val, 2); b[2] = h[0]; b[3] = 0;
            setBit(bloom.data(), *reinterpret_cast<DWORD*>(b));

            // Hash #2: MD5[1..3]
            memcpy(b, h.data() + 1, 3); b[3] = 0;
            setBit(bloom.data(), *reinterpret_cast<DWORD*>(b));

            // Hash #3: MD5[4..6]
            memcpy(b, h.data() + 4, 3); b[3] = 0;
            setBit(bloom.data(), *reinterpret_cast<DWORD*>(b));

            // Hash #4: MD5[7..9]
            memcpy(b, h.data() + 7, 3); b[3] = 0;
            setBit(bloom.data(), *reinterpret_cast<DWORD*>(b));

            // Hash #5: MD5[10..12]
            memcpy(b, h.data() + 10, 3); b[3] = 0;
            setBit(bloom.data(), *reinterpret_cast<DWORD*>(b));

            // Hash #6: MD5[13..15]
            memcpy(b, h.data() + 13, 3); b[3] = 0;
            setBit(bloom.data(), *reinterpret_cast<DWORD*>(b));

            crc16List.push_back(crc16Val);

            // 진행률 (10% 단위)
            ++progress;
            if (total > 0 && progress % (total / 10 + 1) == 0)
            {
                std::tcout << _T("  ") << (progress * 100 / total) << _T("%\r");
                std::tcout.flush();
            }
        }
        std::tcout << _T("  100%\n");

        return saveWithHeader(buildPath(dirPath, DB_EXT_FILTER), bloom,
                              static_cast<uint32_t>(list.size()));
    }

    // ──────────────────────────────────────────────────────────────────────
    // 해시 테이블 파일 (.has) 생성
    // [Fix] nextIndex sentinel → NODE_NULL (0xFFFFFFFF)
    //       기존 0 사용 시: index 0 노드가 체인 중간에 오면 이후 노드가 소실됨
    // [New] DB 파일 헤더 포함
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::makeHashDB(const tstring& dirPath,
                              const DetectHashInfoList& list,
                              const DetectCrc16List& crc16List,
                              const DetectNameInfoMap& nameMap)
    {
        const DWORD patternCount = static_cast<DWORD>(list.size());
        BinaryData data(HASH_TABLE_BUCKET_SIZE + patternCount * sizeof(LINKED_LIST_ITEM), 0);

        // 버킷 초기화: 0xFFFFFFFF = 비어 있음
        DWORD* bucket = reinterpret_cast<DWORD*>(data.data());
        memset(data.data(), 0xFF, HASH_TABLE_BUCKET_SIZE);

        LINKED_LIST_ITEM* nodes = reinterpret_cast<LINKED_LIST_ITEM*>(
            data.data() + HASH_TABLE_BUCKET_SIZE);

        DWORD nodeIdx = 0;
        std::tcout << _T("[HashTable] 생성 중 (") << patternCount << _T(" 패턴)...\n");

        for (DWORD i = 0; i < patternCount; i++)
        {
            const auto& ni = nameMap.find(list[i].DetectName);
            if (ni == nameMap.end()) continue;
            const BinaryData& h = list[i].DetectHash;
            if (h.size() < 16) continue;

            // 노드 초기화
            LINKED_LIST_ITEM& node = nodes[nodeIdx];
            memcpy_s(node.md5Hash, sizeof(node.md5Hash), h.data(), 16);
            node.detectNameOffset = ni->second;
            node.nextIndex        = NODE_NULL;  // [Fix] 0 → 0xFFFFFFFF

            WORD bktIdx  = crc16List[i];
            DWORD headIdx = bucket[bktIdx];

            if (headIdx == NODE_NULL)
            {
                // 버킷이 비어 있음 → 새 노드를 head로 등록
                bucket[bktIdx] = nodeIdx;
            }
            else
            {
                // linked list 끝까지 순회하여 연결
                // [Fix] 종료 조건: nextIndex == NODE_NULL (0xFFFFFFFF)
                DWORD cur = headIdx;
                while (nodes[cur].nextIndex != NODE_NULL)
                    cur = nodes[cur].nextIndex;
                nodes[cur].nextIndex = nodeIdx;
            }

            nodeIdx++;

            if (patternCount > 0 && i % (patternCount / 10 + 1) == 0)
            {
                std::tcout << _T("  ") << (i * 100 / patternCount) << _T("%\r");
                std::tcout.flush();
            }
        }
        std::tcout << _T("  100%\n");

        return saveWithHeader(buildPath(dirPath, DB_EXT_HASH), data, patternCount);
    }

    // ──────────────────────────────────────────────────────────────────────
    // 생성된 DB 검증 + 통계 계산
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::verifyAndStats(const tstring& dirPath,
                                  const DetectHashInfoList& list,
                                  const DetectCrc16List& crc16List,
                                  DBStats& stats)
    {
        stats = {};
        stats.totalPatterns = list.size();

        // ── 블룸 필터 파일 로드 ─────────────────────────────────────────
        tstring blfPath = buildPath(dirPath, DB_EXT_FILTER);
        std::ifstream blfFile(blfPath, std::ios::in | std::ios::binary);
        if (!blfFile.is_open())
        {
            std::tcout << _T("[Verify] ERROR: .blf 파일을 열 수 없습니다.\n");
            return false;
        }
        blfFile.seekg(0, std::ios::end);
        size_t blfSize = static_cast<size_t>(blfFile.tellg());
        blfFile.seekg(0, std::ios::beg);
        BinaryData blfData(blfSize);
        blfFile.read(reinterpret_cast<char*>(blfData.data()),
                     static_cast<std::streamsize>(blfSize));
        blfFile.close();

        // 헤더 검증
        if (blfSize < sizeof(DBFileHeader))
        {
            std::tcout << _T("[Verify] ERROR: .blf 파일이 너무 작습니다.\n");
            return false;
        }
        const DBFileHeader* blfHdr = reinterpret_cast<const DBFileHeader*>(blfData.data());
        if (memcmp(blfHdr->magic, DB_MAGIC, 4) != 0 || blfHdr->version != DB_VERSION)
        {
            std::tcout << _T("[Verify] ERROR: .blf 파일 헤더가 유효하지 않습니다.\n");
            return false;
        }
        const BYTE* bloomBits = blfData.data() + sizeof(DBFileHeader);

        // ── 해시 테이블 파일 로드 ───────────────────────────────────────
        tstring hasPath = buildPath(dirPath, DB_EXT_HASH);
        std::ifstream hasFile(hasPath, std::ios::in | std::ios::binary);
        if (!hasFile.is_open())
        {
            std::tcout << _T("[Verify] ERROR: .has 파일을 열 수 없습니다.\n");
            return false;
        }
        hasFile.seekg(0, std::ios::end);
        size_t hasSize = static_cast<size_t>(hasFile.tellg());
        hasFile.seekg(0, std::ios::beg);
        BinaryData hasData(hasSize);
        hasFile.read(reinterpret_cast<char*>(hasData.data()),
                     static_cast<std::streamsize>(hasSize));
        hasFile.close();

        // ── 블룸 필터 포화도 계산 ─────────────────────────────────────
        size_t bitsSet = 0;
        for (DWORD i = 0; i < BLOOM_FILTER_SIZE; i++)
        {
            BYTE b = bloomBits[i];
            while (b) { bitsSet += (b & 1); b >>= 1; }
        }
        stats.bloomBitsSet       = bitsSet;
        stats.bloomSaturationPct = static_cast<double>(bitsSet) /
                                   static_cast<double>(BLOOM_FILTER_BITS) * 100.0;

        // ── 해시 테이블 충돌 통계 ─────────────────────────────────────
        if (hasSize >= sizeof(DBFileHeader) + HASH_TABLE_BUCKET_SIZE)
        {
            const DWORD* bucket = reinterpret_cast<const DWORD*>(
                hasData.data() + sizeof(DBFileHeader));
            const LINKED_LIST_ITEM* nodes = reinterpret_cast<const LINKED_LIST_ITEM*>(
                hasData.data() + sizeof(DBFileHeader) + HASH_TABLE_BUCKET_SIZE);
            size_t maxNodes = (hasSize - sizeof(DBFileHeader) - HASH_TABLE_BUCKET_SIZE)
                              / sizeof(LINKED_LIST_ITEM);

            size_t totalChain = 0;
            size_t bucketUsed = 0;

            for (DWORD b = 0; b < HASH_BUCKET_COUNT; b++)
            {
                if (bucket[b] == NODE_NULL) continue;
                bucketUsed++;
                size_t chainLen = 0;
                DWORD cur = bucket[b];
                while (cur != NODE_NULL && cur < static_cast<DWORD>(maxNodes))
                {
                    chainLen++;
                    cur = nodes[cur].nextIndex;
                }
                if (chainLen > 1) stats.hashCollisions += (chainLen - 1);
                if (chainLen > stats.maxChainLength) stats.maxChainLength = chainLen;
                totalChain += chainLen;
            }
            stats.avgChainLength = bucketUsed > 0
                ? static_cast<double>(totalChain) / static_cast<double>(bucketUsed) : 0.0;
        }

        // ── 전체 패턴 검증 ─────────────────────────────────────────────
        std::tcout << _T("[Verify] 검증 중 (") << list.size() << _T(" 패턴)...\n");
        for (size_t i = 0; i < list.size(); i++)
        {
            if (list[i].DetectHash.size() < 16) continue;

            if (bloomMayContain(bloomBits, list[i].DetectHash, crc16List[i]))
                stats.verifyBloomPass++;

            if (hashTableLookup(hasData.data(), hasSize, list[i].DetectHash, crc16List[i]))
                stats.verifyHashPass++;
        }

        return true;
    }

    // ──────────────────────────────────────────────────────────────────────
    // 전체 DB 생성 + 검증
    // ──────────────────────────────────────────────────────────────────────

    bool DBFile2::makeDBFile(const tstring& csvPath, const tstring& dbDirPath)
    {
        DetectHashInfoList list;
        DetectNameInfoMap  nameMap;
        DetectCrc16List    crc16List;

        // 1. CSV 로드
        std::tcout << _T("[DBMaker2] CSV 로드: ") << csvPath << _T("\n");
        if (!getDetectHashInfo(csvPath, list))
        {
            std::tcout << _T("[DBMaker2] ERROR: CSV 파일 로드 실패\n");
            return false;
        }

        // .test 파일 (DetectMe + EICAR 등 추가 테스트 해시)
        tstring testPath = csvPath + _T(".test");
        if (std::filesystem::exists(testPath))
        {
            std::tcout << _T("[DBMaker2] 테스트 해시 파일 로드: ") << testPath << _T("\n");
            getDetectHashInfo(testPath, list);
        }

        // EICAR 해시 내장 추가 (CSV나 .test에 없는 경우에도 항상 포함)
        const std::u8string eicarMd5 = u8"44d88612fea8a8f36de82e1278abb02f";
        const std::u8string eicarName = u8"EICAR-Test-File";
        bool hasEicar = false;
        for (const auto& e : list)
        {
            // 탐지명으로 중복 체크
            if (e.DetectName == eicarName) { hasEicar = true; break; }
        }
        if (!hasEicar)
        {
            BinaryData eicarBytes = hexToBinary(eicarMd5);
            if (eicarBytes.size() == 16)
            {
                list.push_back(DetectHashInfo{ eicarName, std::move(eicarBytes) });
                std::tcout << _T("[DBMaker2] EICAR 테스트 해시 자동 추가\n");
            }
        }

        std::tcout << _T("[DBMaker2] 총 패턴 수: ") << list.size() << _T("\n\n");

        // 2. 탐지명 파일 생성
        std::tcout << _T("[Step 1/3] 탐지명 파일 (.nam) 생성\n");
        if (!makeNameDB(dbDirPath, list, nameMap))
        {
            std::tcout << _T("[DBMaker2] ERROR: .nam 파일 생성 실패\n");
            return false;
        }

        // 3. 블룸 필터 파일 생성
        std::tcout << _T("[Step 2/3] 블룸 필터 파일 (.blf) 생성\n");
        if (!makeBloomFilterDB(dbDirPath, list, crc16List))
        {
            std::tcout << _T("[DBMaker2] ERROR: .blf 파일 생성 실패\n");
            return false;
        }

        // 4. 해시 테이블 파일 생성
        std::tcout << _T("[Step 3/3] 해시 테이블 파일 (.has) 생성\n");
        if (!makeHashDB(dbDirPath, list, crc16List, nameMap))
        {
            std::tcout << _T("[DBMaker2] ERROR: .has 파일 생성 실패\n");
            return false;
        }

        // 5. 검증 + 통계
        std::tcout << _T("\n[Verify] DB 파일 검증 시작\n");
        DBStats stats;
        if (verifyAndStats(dbDirPath, list, crc16List, stats))
        {
            std::tcout << _T("\n─────────────────────────────────────────\n");
            std::tcout << _T(" DB 생성 통계\n");
            std::tcout << _T("─────────────────────────────────────────\n");
            std::tcout << _T(" 총 패턴 수          : ") << stats.totalPatterns << _T("\n");
            std::tcout << std::format(_T(" 블룸 포화도         : {:.4f}%"), stats.bloomSaturationPct) << _T("\n");
            std::tcout << _T(" 블룸 설정 비트 수   : ") << stats.bloomBitsSet << _T(" / ") << BLOOM_FILTER_BITS << _T("\n");
            std::tcout << _T(" 해시 충돌 수        : ") << stats.hashCollisions << _T("\n");
            std::tcout << _T(" 최대 체인 길이      : ") << stats.maxChainLength << _T("\n");
            std::tcout << std::format(_T(" 평균 체인 길이      : {:.2f}"), stats.avgChainLength) << _T("\n");
            std::tcout << _T(" 블룸 검증 통과      : ") << stats.verifyBloomPass << _T(" / ") << stats.totalPatterns << _T("\n");
            std::tcout << _T(" 해시 검증 통과      : ") << stats.verifyHashPass << _T(" / ") << stats.totalPatterns << _T("\n");

            bool bloomOk = (stats.verifyBloomPass == stats.totalPatterns);
            bool hashOk  = (stats.verifyHashPass  == stats.totalPatterns);
            std::tcout << _T("─────────────────────────────────────────\n");
            std::tcout << _T(" 블룸 필터 검증: ") << (bloomOk ? _T("PASS") : _T("FAIL")) << _T("\n");
            std::tcout << _T(" 해시 테이블 검증: ") << (hashOk  ? _T("PASS") : _T("FAIL")) << _T("\n");
            std::tcout << _T("─────────────────────────────────────────\n");

            if (!bloomOk || !hashOk)
            {
                std::tcout << _T("[DBMaker2] WARNING: 검증 실패 항목 있음!\n");
            }
        }

        return true;
    }
}
