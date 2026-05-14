#pragma once

#include "typedef.h"
#include "hash.h"
#include "strconv.h"
#include <fstream>
#include <map>
#include <filesystem>

namespace dbmaker
{
    using namespace hash;
    using namespace strconv;

    // UTF-8 파일 스트림
    using u8ifstream = std::basic_ifstream<char8_t, std::char_traits<char8_t>>;

    // 블룸 필터 크기: 24bit = 16,777,216 bit = 2,097,152 byte = 2MB
    #define BLOOM_FILTER_SIZE 2097152

    // 해시 테이블 버킷 크기: 16bit = 65,536개 * 4byte(DWORD) = 262,144 byte = 256KB
    #define HASH_TABLE_BUCKET_SIZE 262144

    // 해시 배열에서 24bit 값을 읽기 위한 바이트 수
    #define BYTE_COUNT_24BIT 3
    #define BYTE_COUNT_DWORD 4

    // BYTE 배열에서 Bit flag(0~7번째 bit) 설정 및 확인을 위한 상수 값
    static const BYTE BIT_FLAG[8] = { 1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7 };

    // DB 파일명 및 확장자
    #define DB_FILE_NAME     _T("acis")
    #define DB_FILE_EXT_NAME _T(".nam")
    #define DB_FILE_EXT_HASH _T(".has")
    #define DB_FILE_EXT_FILTER _T(".blf")

    // 탐지 패턴 정보 구조체 (탐지명 + MD5 해시 바이트)
    typedef struct _DetectHashInfo
    {
        std::u8string DetectName;
        BinaryData    DetectHash;
    }
    DetectHashInfo;
    typedef std::vector<DetectHashInfo> DetectHashInfoList;

    // 탐지명 → 파일 내 offset 맵
    typedef std::map<std::u8string, DWORD> DetectNameInfoMap;

    // 블룸 필터 생성 시 계산된 CRC16 값 목록
    typedef std::vector<WORD> DetectCrc16List;

    // 해시 테이블 linked list 노드
    typedef struct _LINKED_LIST_ITEM
    {
        BYTE  md5Hash[16];
        DWORD detectNameOffset;
        DWORD nextIndex;
    }
    LINKED_LIST_ITEM, *PLINKED_LIST_ITEM;

    class DBFile
    {
    private:
        Hash   hash_;
        StrConv strConv_;

        const tstring malwareDBFileName_ = DB_FILE_NAME;
        const tstring malwareNameExt_    = DB_FILE_EXT_NAME;
        const tstring malwareHashExt_    = DB_FILE_EXT_HASH;
        const tstring malwareFilterExt_  = DB_FILE_EXT_FILTER;

        // 파일에 바이너리 데이터를 쓰는 템플릿 헬퍼
        template<typename T1, typename T2>
        std::ostream& write_typed_data(std::ostream& stream, const T1& value, const T2& valueLength)
        {
            return stream.write(reinterpret_cast<const char*>(value.data()), valueLength);
        }

        // BYTE 배열의 특정 비트를 1로 설정
        void setBit(BYTE* bloomFilter, const DWORD bitIndex);

        // BYTE 배열의 특정 비트 값 확인 (1이면 true)
        bool getBit(const BYTE* bloomFilter, const DWORD bitIndex) const;

        // MD5 해시 hex 문자열을 바이너리로 변환
        BinaryData getHashBytesFromHexString(const tstring& hashHexString);

        // 파일로 바이너리 데이터 저장
        bool saveDataToFile(const tstring& saveFilePath, const BinaryData& binaryData) const;

    public:
        DBFile() = default;
        ~DBFile() = default;

        // CSV 파일에서 탐지 해시 정보 로드
        bool getDetectHashInfo(const tstring& csvFilePath, DetectHashInfoList& detectHashInfoList);

        // 탐지명 파일(.nam) 생성
        bool makeNameDB(const tstring& dirPath,
                        const DetectHashInfoList& detectHashInfoList,
                        DetectNameInfoMap& detectNameInfoMap);

        // 블룸 필터 파일(.blf) 생성 - 6개의 24bit 해시 함수 사용
        bool makeBloomFilterDB(const tstring& dirPath,
                               const DetectHashInfoList& detectHashInfoList,
                               DetectCrc16List& crc16List);

        // 해시 테이블 파일(.has) 생성
        bool makeHashDB(const tstring& dirPath,
                        const DetectHashInfoList& detectHashInfoList,
                        const DetectCrc16List& crc16List,
                        const DetectNameInfoMap& detectNameInfoMap);

        // 전체 DB 파일 생성 (CSV → .nam + .blf + .has)
        bool makeDBFile(const tstring& csvFilePath, const tstring& dbDirPath);
    };
}
