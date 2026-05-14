#pragma once

#include "typedef.h"

namespace logging
{
	using namespace std;

	// 로그 출력시 사용할 레벨 정의
	enum LogLevel
	{
		LOG_LEVEL_OFF = 0,
		LOG_LEVEL_ALL,
		LOG_LEVEL_DEBUG,
		LOG_LEVEL_INFO,
		LOG_LEVEL_WARN,
		LOG_LEVEL_ERROR,
		LOG_LEVEL_FATAL
	};

	// 로그 출력 방향 정의
	enum LogDirection
	{
		LOG_DIRECTION_DEBUGVIEW = 0,
		LOG_DIRECTION_CONSOLE
	};

	class Logger 
	{
	private:
		bool addFuncInfo_;
		LogLevel logLevel_;
		LogDirection logDirection_;

	private:
		void output(const string_view& logMessage, const bool& useEndl = true) const;
		void output(const wstring_view& logMessage, const bool& useEndl = true) const;

	public:
		Logger(bool addFuncInfo = false, LogLevel logLevel = LOG_LEVEL_ALL, LogDirection logDirection = LOG_DIRECTION_CONSOLE) :
			addFuncInfo_(addFuncInfo), logLevel_(logLevel), logDirection_(logDirection) {};
		~Logger() {};
		void setLogType(const LogLevel& logLevel, const LogDirection& logDirection, const bool& addFuncInfo = true);
		void getLogType(LogLevel& logLevel, LogDirection& logDirection, bool& addFuncInfo) const;
		void log(const string_view& logMessage, const LogLevel& logLevel = LOG_LEVEL_ALL, const bool& useEndl = true, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE()) const;
		void log(const wstring_view& logMessage, const LogLevel& logLevel = LOG_LEVEL_ALL, const bool& useEndl = true, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE()) const;
		void log(const string_view& logMessage, const uint32_t& errorCode, const LogLevel& logLevel = LOG_LEVEL_ALL, const bool& useEndl = true, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE()) const;
		void log(const wstring_view& logMessage, const uint32_t& errorCode, const LogLevel& logLevel = LOG_LEVEL_ALL, const bool& useEndl = true, const char* funcName = __builtin_FUNCTION(), int funcLine = __builtin_LINE()) const;
	};
};

