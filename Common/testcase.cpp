#include "testcase.h"
#include "hash.h"
#include "peparser.h"
#include "peprint.h"
#include "strconv.h"
#include "logger.h"
#include "cmdparser.h"

using namespace hashtool;
using namespace peparser;
using namespace strconv;
using namespace logging;
using namespace cmdparser;

void TestCase::hashTest(void)
{
    Hash hash;
    BYTE bytes_1[] = { 'f', 'i', 'r', 's', 't', 'B', 'y', 't', 'e', 's' };
    BYTE bytes_2[] = { 's', 'e', 'c', 'o', 'n', 'd', 'B', 'y', 't', 'e', 's' };

    if (hash.open(HASH_TYPE_MD5))
    {
        hash.calculateHash(bytes_1, sizeof(bytes_1));
        hash.calculateHash(bytes_2, sizeof(bytes_2), true);
        tcout << hash.getHashString() << endl;
        hash.close();
    }

    if (hash.open(HASH_TYPE_CRC16))
    {
        hash.calculateHash(bytes_1, sizeof(bytes_1));
        hash.calculateHash(bytes_2, sizeof(bytes_2), true);
        tcout << hash.getHashString() << endl;
        hash.close();
    }
};

void TestCase::peParserTest(void)
{
    PEParser peParser;
    PEPrint pePrint;

    // if (peParser.open(_T("c:\\Temp\\Test\\DetectMe32.exe")))
    // if (peParser.open(_T("c:\\windows\\system32\\kernel32.dll")))
    if (peParser.open(_T("c:\\windows\\system32\\advapi32.dll")))
    // if (peParser.open(_T("c:\\Temp\\Test\\pepper.exe")))
    // if (peParser.open(21184))
    // if (peParser.open(_T("c:\\Temp\\Test\\DetectMe.exe")))
    {
        if (peParser.parsePE())
        {
            pePrint.printPEStructure(peParser.getPEStructure());
        }
    }
};

void TestCase::strConvTest(void)
{
    cout << "\nstrConvTest start ----------------------------------------\n\n";

    StrConv strConv;

    cout << strConv.to_string(strConv.to_u8string("한글 테스트 : Ansi -> UTF8 -> Ansi")) << endl;
    wcout << strConv.to_wstring(u8"한글 테스트 : UTF8 -> Unicode") << endl;
    tcout << strConv.to_tstring("한글 테스트 : Unicode -> tstring") << endl;
    tcout << strConv.to_tstring(u8"한글 테스트 : UTF8 -> tstring") << endl;

    char str[] = { 't','e','s' ,'t' ,'!' };
    cout << "to_string(string) : " << strConv.to_string(str, sizeof(str)) << endl;
    wcout << L"to_wstring(string) : " << strConv.to_wstring(str, sizeof(str)) << endl;
    tcout << _T("to_tstring(string) : ") << strConv.to_tstring(str, sizeof(str)) << endl;

    char8_t u8str[] = { 't','e','s' ,'t' ,'!' };
    cout << "to_string(u8string) : " << strConv.to_string(u8str, sizeof(u8str)) << endl;
    wcout << L"to_wstring(u8string) : " << strConv.to_wstring(u8str, sizeof(u8str)) << endl;
    tcout << _T("to_tstring(u8string) : ") << strConv.to_tstring(u8str, sizeof(u8str)) << endl;

    cout << "\nstrConvTest end ----------------------------------------\n\n";
};

void TestCase::loggerTest(void)
{
    cout << "\nloggerTest start ----------------------------------------\n\n";

    Logger logger;

    logger.log(L"로깅 테스트 - 1");
    logger.log(L"로깅 테스트 - 2", 0x4000);

    logger.setLogType(LogLevel::LOG_LEVEL_ALL, LogDirection::LOG_DIRECTION_CONSOLE, false);

    logger.log(L"로깅 테스트 - 3");
    logger.log(L"로깅 테스트 - 4", 0x4000);

    logger.setLogType(LogLevel::LOG_LEVEL_ERROR, LogDirection::LOG_DIRECTION_CONSOLE, false);
    logger.log(L"로깅 테스트 - 5", LogLevel::LOG_LEVEL_ALL);

    logger.setLogType(LogLevel::LOG_LEVEL_ALL, LogDirection::LOG_DIRECTION_CONSOLE, false);
    logger.log(L"로깅 테스트 - 6", LogLevel::LOG_LEVEL_ALL);

    logger.setLogType(LogLevel::LOG_LEVEL_OFF, LogDirection::LOG_DIRECTION_CONSOLE, false);
    logger.log(L"로깅 테스트 - 7", LogLevel::LOG_LEVEL_ALL);

    cout << "\nloggerTest end ----------------------------------------\n\n";
};

void TestCase::cmdParserTest(void)
{
    CmdParser cmdParser;

    cmdParser.set_required<tstring>(_T("i"), _T("target_ip"), _T("The target ip."));
    cmdParser.set_optional<int>(_T("p"), _T("target_port"), 65535, _T("The target port."));
    cmdParser.set_optional<int>(_T("c"), _T("connection"), 100, _T("The number of connections."));

    // 커맨드라인 입력 생성
    int argc = 5;
    TCHAR* argv[] = {
        const_cast<TCHAR*>(_T("Program_Path")), 
        const_cast<TCHAR*>(_T("-i")),
        const_cast<TCHAR*>(_T("10.0.0.1")),
        const_cast<TCHAR*>(_T("-p")),
        const_cast<TCHAR*>(_T("4096"))};

    cmdParser.parseCmdLine(argc, argv);

    if (cmdParser.isPrintHelp())
    {
        tcout << cmdParser.getHelpMessage(_T("Command Parser"));
    }
    else
    {
        try
        {
            tstring hostIP = cmdParser.get<tstring>(_T("i"));
            int hostPort = cmdParser.get<int>(_T("p"));
            int connection = cmdParser.get<int>(_T("c"));

            tcout << format(_T("IP = {}, Port = {}, Connection = {}\n"), hostIP, hostPort, connection);
        }
        catch (std::runtime_error ex)
        {
            cout << format("Error : {}\n\n", ex.what());
            tcout << cmdParser.getHelpMessage(_T("Command Parser"));
        }
    }
};
