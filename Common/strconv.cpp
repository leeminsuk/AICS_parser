#include "windows.h"
#include "strconv.h"

namespace strconv
{
	const wstring StrConv::ansi2unicode(const string_view& str)
	{
		wstring unicode;

		// getting required cch.        
		int required_cch = MultiByteToWideChar(CP_ACP, 
												0, 
												str.data(), 
												static_cast<int>(str.size()), 
												nullptr, 
												0);
		if (required_cch != 0)
		{
			unicode.resize(required_cch);

			// convert.        
			if (MultiByteToWideChar(CP_ACP, 
									0, 
									str.data(), 
									static_cast<int>(str.size()), 
									unicode.data(), 
									static_cast<int>(unicode.size())) == 0)
			{
				unicode.clear();
			}
		}
		return unicode;
	};

	const string StrConv::unicode2ansi(const wstring_view& str)
	{
		string ansi;

		// getting required cch.        
		int required_cch = WideCharToMultiByte(CP_ACP, 
												0, 
												str.data(), 
												static_cast<int>(str.size()), 
												nullptr, 
												0, 
												nullptr, 
												nullptr);
		if (required_cch != 0)
		{
			ansi.resize(required_cch);

			// convert.        
			if (WideCharToMultiByte(CP_ACP, 
									0, 
									str.data(), 
									static_cast<int>(str.size()), 
									ansi.data(), 
									static_cast<int>(ansi.size()), 
									nullptr, 
									nullptr) == 0)
			{
				ansi.clear();
			}
		}
		return ansi;
	};

	const u8string StrConv::ansi2u8(const string_view& str)
	{
		return unicode2u8(ansi2unicode(str));
	};

	const u8string StrConv::unicode2u8(const wstring_view& str)
	{
		u8string utf8;

		// getting required cch.        
		int required_cch = WideCharToMultiByte(CP_UTF8, 
												0, 
												str.data(), 
												static_cast<int>(str.size()), 
												nullptr, 
												0, 
												nullptr, 
												nullptr);
		if (required_cch != 0)
		{
			utf8.resize(required_cch);

			// convert.        
			if (WideCharToMultiByte(CP_UTF8, 
									0, 
									str.data(), 
									static_cast<int>(str.size()), 
									reinterpret_cast<LPSTR>(utf8.data()), 
									static_cast<int>(utf8.size()), 
									nullptr, 
									nullptr) == 0)
			{
				utf8.clear();
			}
		}
		return utf8;
	};

	const string StrConv::u82ansi(const u8string_view& str)
	{
		return unicode2ansi(u82unicode(str));
	};

	const wstring StrConv::u82unicode(const u8string_view& str)
	{
		wstring unicode;

		// getting required cch.        
		int required_cch = MultiByteToWideChar(CP_UTF8, 
												0, 
												reinterpret_cast<LPCCH>(str.data()), 
												static_cast<int>(str.size()), 
												nullptr, 
												0);
		if (required_cch != 0)
		{
			unicode.resize(required_cch);

			// convert.        
			if (MultiByteToWideChar(CP_UTF8, 
									0, 
									reinterpret_cast<LPCCH>(str.data()), 
									static_cast<int>(str.size()), 
									unicode.data(), 
									static_cast<int>(unicode.size())) == 0)
			{
				unicode.clear();
			}
		}
		return unicode;
	};

	const string StrConv::to_string(const wstring_view& str)
	{
		return unicode2ansi(str);
	};

	const string StrConv::to_string(const u8string_view& str)
	{
		return u82ansi(str);
	};

	const string StrConv::to_string(const char* str, const size_t& size)
	{	
		return string(str, size);
	};

	const string StrConv::to_string(const char8_t* str, const size_t& size)
	{
		return u82ansi(u8string_view(str, size));
	}

	const wstring StrConv::to_wstring(const string_view& str)
	{
		return ansi2unicode(str);
	};

	const wstring StrConv::to_wstring(const u8string_view& str)
	{
		return u82unicode(str);
	};

	const wstring StrConv::to_wstring(const char* str, const size_t& size)
	{
		return ansi2unicode(string_view(str, size));
	};

	const wstring StrConv::to_wstring(const char8_t* str, const size_t& size)
	{
		return u82unicode(u8string_view(str, size));
	};

	const u8string StrConv::to_u8string(const string_view& str)
	{
		return ansi2u8(str);
	};

	const u8string StrConv::to_u8string(const wstring_view& str)
	{
		return unicode2u8(str);
	};

	const u8string StrConv::to_u8string(const char* str, const size_t& size)
	{
		return ansi2u8(string_view(str, size));
	};

	const u8string StrConv::to_u8string(const char8_t* str, const size_t& size)
	{
		return u8string(str, size);
	};

	const tstring StrConv::to_tstring(const string_view& str)
	{
#if defined(UNICODE) || defined(_UNICODE)
		return to_wstring(str);
#else
		return string(str);
#endif
	};

	const tstring StrConv::to_tstring(const wstring_view& str)
	{
#if defined(UNICODE) || defined(_UNICODE)
		return wstring(str);
#else
		return to_string(str);
#endif
	};

	const tstring StrConv::to_tstring(const u8string_view& str)
	{
#if defined(UNICODE) || defined(_UNICODE)
		return to_wstring(str);
#else
		return to_string(str);
#endif
	};

	const tstring StrConv::to_tstring(const char* str, const size_t& size)
	{
#if defined(UNICODE) || defined(_UNICODE)
		return to_wstring(str, size);
#else
		return to_string(str, size);
#endif
	};

	const tstring StrConv::to_tstring(const char8_t* str, const size_t& size)
	{
#if defined(UNICODE) || defined(_UNICODE)
		return to_wstring(str, size);
#else
		return to_string(str, size);
#endif
	};
};

