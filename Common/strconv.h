#pragma once

#include "typedef.h"

namespace strconv
{
	using namespace std;

	class StrConv
	{
	private:
		const wstring ansi2unicode(const string_view& str);
		const string unicode2ansi(const wstring_view& str);
		const u8string ansi2u8(const string_view& str);
		const u8string unicode2u8(const wstring_view& str);
		const string u82ansi(const u8string_view& str);
		const wstring u82unicode(const u8string_view& str);

	public:
		StrConv() {};
		~StrConv() {};
		const string to_string(const wstring_view& str);
		const string to_string(const u8string_view& str);
		const string to_string(const char* str, const size_t& size);
		const string to_string(const char8_t* str, const size_t& size);
		const wstring to_wstring(const string_view& str);
		const wstring to_wstring(const u8string_view& str);
		const wstring to_wstring(const char* str, const size_t& size);
		const wstring to_wstring(const char8_t* str, const size_t& size);
		const u8string to_u8string(const string_view& str);
		const u8string to_u8string(const wstring_view& str);
		const u8string to_u8string(const char* str, const size_t& size);
		const u8string to_u8string(const char8_t* str, const size_t& size);
		const tstring to_tstring(const string_view& str);
		const tstring to_tstring(const wstring_view& str);
		const tstring to_tstring(const u8string_view& str);
		const tstring to_tstring(const char* str, const size_t& size);
		const tstring to_tstring(const char8_t* str, const size_t& size);
	};
};

