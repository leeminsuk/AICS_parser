#pragma once

#include "typedef.h"
#include "hash.h"
#include "strconv.h"
#include <fstream>
#include <map>
#include <filesystem>

namespace dbmaker2
{
    using namespace hash;
    using namespace strconv;

    // ── 상수 ──────────────────────────────────────────────────────────────
    // 블룸 필터: 24bit = 16,777,216 bit = 2,097,152 byte (2MB)
    static constexpr DWORD BLOOM_FILTER_SIZE    = 2097152;
    static constexpr DWORD BLOOM_FILTER_BITS    = BLOOM_FILTER_SIZE * 8; // 16,777,216

    // 해시 테이블 버킷: 16bit = 65,536개 × 4byte
    static constexpr DWORD HASH_BUCKET_COUNT    = 65536;
    static constexpr DWORD HASH_TABLE_BUCKET_SIZE = HASH_BUCKET_COUNT * sizeof(DWORD); // 262,144

    // 파일명 / 확장자
    static constexpr TCHAR DB_FILE_NAME[]      = _T("acis");
    static constexpr TCHAR DB_EXT_NAME[]       = _T(".nam");
    static constexpr TCHAR DB_EXT_HASH[]       = _T(".has");
    static constexpr TCHAR DB_EXT_FILTER[]     = _T(".blf");

    // DB 파일 헤더 magic
    static constexpr uint8_t DB_MAGIC[4]       = { 'A','I','C','S' };
    static constexpr uint32_t DB_VERSION        = 1;

    // EICAR 표준 테스트 파일 MD5 (항상 탐지 대상에 포함)
    static constexpr char EICAR_MD5[]          = "44d88612fea8a8f36de82e1278abb02f";
    static constexpr char EICAR_NAME[]         = "EICAR-Test-File";

    // 다음 노드 없음을 나타내는 센티넬 (0 대신 0xFFFFFFFF 사용 → index 0 노드 소실 버그 수정)
    static constexpr DWORD NODE_NULL           = 0xFFFFFFFF;

    // BIT_FLAG: 바이트 내 비트 위치 플래그
    static constexpr BYTE BIT_FLAG[8] = {
        1 << 0, 1 << 1, 1 << 2, 1 << 3,
        1 << 4, 1 << 5, 1 << 6, 1 << 7
    };

    // ── DB 파일 헤더 ──────────────────────────────────────────────────────
    // 각 DB 파일 앞에 붙어 버전 관리와 파일 무결성 확인에 사용
    #pragma pack(push, 1)
    struct DBFileHeader
    {
        uint8_t  magic[4];      // 'AICS'
        uint32_t version;       // DB_VERSION
        uint32_t count;         // 저장된 패턴 수 (blf/has용) 또는 탐지명 수 (nam용)
        uint32_t reserved;      // 예약 (항상 0)
    };
    #pragma pack(pop)
    static_assert(sizeof(DBFileHeader) == 16, "DBFileHeader must be 16 bytes");

    // ── 탐지 패턴 정보 ────────────────────────────────────────────────────
    typedef struct _DetectHashInfo
    {
        std::u8string DetectName;   // 탐지명 (UTF-8)
        BinaryData    DetectHash;   // MD5 바이트 (16 bytes)
    }
    DetectHashInfo;
    typedef std::vector<DetectHashInfo> DetectHashInfoList;

    // 탐지명 → 파일 내 offset 맵
    typedef std::map<std::u8string, DWORD> DetectNameInfoMap;

    // 블룸 필터 생성 시 함께 계산된 CRC16 값 목록 (해시 테이블 bucket index로 재사용)
    typedef std::vector<WORD> DetectCrc16List;

    // ── 해시 테이블 노드 ──────────────────────────────────────────────────
    // [Fix] nextIndex 센티넬을 0xFFFFFFFF로 변경
    //       기존 0 사용 시: index 0 노드가 체인 중간에 있으면 이후 노드가 소실되는 버그 발생
    #pragma pack(push, 1)
    typedef struct _LINKED_LIST_ITEM
    {
        BYTE  md5Hash[16];          // MD5 해시 (16 byte)
        DWORD detectNameOffset;     // 탐지명 파일(.nam) 내 offset
        DWORD nextIndex;            // 다음 노드 index (없으면 NODE_NULL = 0xFFFFFFFF)
    }
    LINKED_LIST_ITEM, *PLINKED_LIST_ITEM;
    #pragma pack(pop)
    static_assert(sizeof(LINKED_LIST_ITEM) == 24, "LINKED_LIST_ITEM must be 24 bytes");

    // ── 통계 정보 ─────────────────────────────────────────────────────────
    struct DBStats
    {
        size_t totalPatterns;           // 총 패턴 수
        size_t bloomBitsSet;            // 블룸 필터에서 1로 설정된 비트 수
        double bloomSaturationPct;      // 포화도 = bloomBitsSet / BLOOM_FILTER_BITS × 100
        size_t hashCollisions;          // 버킷 충돌 횟수
        size_t maxChainLength;          // 최대 체인 길이
        double avgChainLength;          // 평균 체인 길이
        size_t verifyBloomPass;         // 검증: 블룸 필터 통과 수
        size_t verifyHashPass;          // 검증: 해시 테이블 조회 성공 수
    };

    // ── DBFile2 클래스 ─────────────────────────────────────────────────────
    class DBFile2
    {
    private:
        Hash    hash_;
        StrConv strConv_;

        // ── 비트 조작 ───────────────────────────────────────────────────
        void setBit(BYTE* bloomFilter, DWORD bitIndex) const;
        bool getBit(const BYTE* bloomFilter, DWORD bitIndex) const;

        // ── 내부 유틸리티 ───────────────────────────────────────────────
        BinaryData hexToBinary(const std::u8string& hexStr) const;
        tstring    buildPath(const tstring& dir, const tstring& ext) const;
        bool       saveWithHeader(const tstring& path,
                                  const BinaryData& body,
                                  uint32_t count) const;

        // ── 블룸 필터 조회 (검증용) ─────────────────────────────────────
        // false negative 없음, false positive 가능
        bool bloomMayContain(const BYTE* bloomData,
                             const BinaryData& md5Hash,
                             WORD crc16) const;

        // ── 해시 테이블 조회 (검증용) ──────────────────────────────────
        bool hashTableLookup(const BYTE* tableData,
                             size_t tableSize,
                             const BinaryData& md5Hash,
                             WORD crc16) const;

    public:
        DBFile2() = default;
        ~DBFile2() = default;

        // CSV 파일에서 탐지 해시 정보 로드 (UTF-8, "hash,name" 형식)
        bool getDetectHashInfo(const tstring& csvPath, DetectHashInfoList& list);

        // 탐지명 파일 (.nam) 생성
        bool makeNameDB(const tstring& dirPath,
                        const DetectHashInfoList& list,
                        DetectNameInfoMap& nameMap);

        // 블룸 필터 파일 (.blf) 생성
        // 6개 24bit 해시 함수 사용 (CRC16+MD5[0], MD5[1..3], ..., MD5[13..15])
        bool makeBloomFilterDB(const tstring& dirPath,
                               const DetectHashInfoList& list,
                               DetectCrc16List& crc16List);

        // 해시 테이블 파일 (.has) 생성
        // [Fix] nextIndex sentinel = 0xFFFFFFFF (기존 0에서 수정)
        bool makeHashDB(const tstring& dirPath,
                        const DetectHashInfoList& list,
                        const DetectCrc16List& crc16List,
                        const DetectNameInfoMap& nameMap);

        // 생성된 DB 파일 검증 + 통계 계산
        bool verifyAndStats(const tstring& dirPath,
                            const DetectHashInfoList& list,
                            const DetectCrc16List& crc16List,
                            DBStats& stats);

        // 전체 DB 생성 및 검증 (메인 엔트리)
        bool makeDBFile(const tstring& csvPath, const tstring& dbDirPath);
    };
}
