#pragma once

#include "logger.h"
#include <windows.h>

namespace logging
{
    void Logger::setLogType(const LogLevel& logLevel, const LogDirection& logDirection, const bool& addFuncInfo)
    {
        logLevel_ = logLevel;
        logDirection_ = logDirection;
        addFuncInfo_ = addFuncInfo;
    };

    void Logger::getLogType(LogLevel& logLevel, LogDirection& logDirection, bool& addFuncInfo) const
    {
        logLevel = logLevel_;
        logDirection = logDirection_;
        addFuncInfo = addFuncInfo_;
    };

    void Logger::output(const string_view& logMessage, const bool& useEndl) const
    {
        if (logLevel_ > LOG_LEVEL_OFF)
        {
            if (logDirection_ == LOG_DIRECTION_DEBUGVIEW)
            {
                OutputDebugStringA(logMessage.data());
                if (useEndl)
                {
                    OutputDebugStringA("\n");
                }
            }
            else if (logDirection_ == LOG_DIRECTION_CONSOLE)
            {
                cout << logMessage.data();
                if (useEndl)
                {
                    cout << endl;
                }
            }
        }
    };

    void Logger::output(const wstring_view& logMessage, const bool& useEndl) const
    {
        if (logLevel_ > LOG_LEVEL_OFF)
        {
            if (logDirection_ == LOG_DIRECTION_DEBUGVIEW)
            {
                OutputDebugStringW(logMessage.data());
                if (useEndl)
                {
                    OutputDebugStringW(L"\n");
                }
            }
            else if (logDirection_ == LOG_DIRECTION_CONSOLE)
            {
                wcout << logMessage;
                if (useEndl)
                {
                    wcout << endl;
                }
            }
        }
    };

    void Logger::log(const string_view& logMessage, const LogLevel& logLevel, const bool& useEndl, const char* funcName, int funcLine) const
    {
        if (logLevel >= logLevel_)
        {
            if (addFuncInfo_)
            {
                output(format("Function = {:s}({:d}), Msg = ", funcName, funcLine), false);
            }
            output(format("{:s}", logMessage), useEndl);
        }
    };

    void Logger::log(const wstring_view& logMessage, const LogLevel& logLevel, const bool& useEndl, const char* funcName, int funcLine) const
    {
        if (logLevel >= logLevel_)
        {
            if (addFuncInfo_)
            {
                output(format("Function = {:s}({:d}), Msg = ", funcName, funcLine), false);
            }
            output(format(L"{:s}", logMessage), useEndl);
        }
    };

    void Logger::log(const string_view& logMessage, const uint32_t& errorCode, const LogLevel& logLevel, const bool& useEndl, const char* funcName, int funcLine) const
    {
        if (logLevel >= logLevel_)
        {
            if (addFuncInfo_)
            {
                output(format("Function = {:s}({:d}), Error code = 0x{2:x}({2:d}), Msg = ", funcName, funcLine, errorCode), false);
            }
            output(format("{:s}", logMessage), useEndl);
        }
    };

    void Logger::log(const wstring_view& logMessage, const uint32_t& errorCode, const LogLevel& logLevel, const bool& useEndl, const char* funcName, int funcLine) const
    {
        if (logLevel >= logLevel_)
        {
            if (addFuncInfo_)
            {
                output(format("Function = {0:s}({1:d}), Error code = 0x{2:x}({2:d}), Msg = ", funcName, funcLine, errorCode), false);
            }
            output(format(L"{:s}", logMessage), useEndl);
        }
    };
};

