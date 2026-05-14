#include <iostream>
#include <Windows.h>
#include "dbfile.h"
#include "strconv.h"

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "");

    using namespace dbmaker;
    using namespace strconv;

    StrConv strConv;
    DBFile dbFile;

    // 기본값: 실행 파일과 같은 디렉터리의 malware_hash.csv 사용
    tstring csvFilePath = _T("malware_hash.csv");
    tstring dbDirPath   = _T(".");

    if (argc >= 2)
        csvFilePath = strConv.to_tstring(argv[1]);
    if (argc >= 3)
        dbDirPath = strConv.to_tstring(argv[2]);

    std::tcout << _T("[DBMaker] CSV: ") << csvFilePath << std::endl;
    std::tcout << _T("[DBMaker] Output dir: ") << dbDirPath << std::endl;

    if (dbFile.makeDBFile(csvFilePath, dbDirPath))
    {
        std::tcout << _T("[DBMaker] DB files created successfully.") << std::endl;
        std::tcout << _T("  acis.nam - detect name file") << std::endl;
        std::tcout << _T("  acis.blf - bloom filter file (6 x 24bit hash)") << std::endl;
        std::tcout << _T("  acis.has - hash table file") << std::endl;
    }
    else
    {
        std::tcout << _T("[DBMaker] Failed to create DB files.") << std::endl;
        return 1;
    }

    return 0;
}
