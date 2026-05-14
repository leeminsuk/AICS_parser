#include "dbfile2.h"
#include <iostream>

// wmain: Unicode-safe entry on Windows (_UNICODE build)
// argv[1] = CSV file path, argv[2] = output DB directory path
int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3)
    {
        std::wcerr << L"Usage: DBMaker2 <csv_path> <db_dir_path>\n"
                   << L"  csv_path    : malware hash CSV (UTF-8, \"md5hash,DetectName\" per line)\n"
                   << L"  db_dir_path : output directory for acis.blf / acis.has / acis.nam\n";
        return 1;
    }

    const dbmaker2::tstring csvPath(argv[1]);
    const dbmaker2::tstring dbDirPath(argv[2]);

    dbmaker2::DBFile2 dbFile;
    if (!dbFile.makeDBFile(csvPath, dbDirPath))
    {
        std::wcerr << L"[ERROR] DB creation failed.\n";
        return 2;
    }

    return 0;
}
