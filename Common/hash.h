#pragma once

#include "typedef.h"
#include "logger.h"

namespace hash
{
	using namespace logging;

	// Hash 타입 정의
	enum HashType
	{
		HASH_TYPE_MD5 = 0,
		HASH_TYPE_CRC16
	};

	class Hash
	{
	private:
		Logger logger_;
		HashType hashType_;
		HCRYPTPROV prov_ = NULL;
		HCRYPTHASH hash_ = NULL;
		BinaryData hashValue_;
		tstring hashString_;

	private:
		const void to_string(const BYTE* hashBytes, const size_t& length, tstring& hashString) const;

	public:
		Hash();
		~Hash();
		const bool open(const HashType& hashType = HASH_TYPE_MD5);
		void close(void);
		const bool calculateHash(const BYTE* srcBytes, const size_t& length, const bool& isLast = false);
		const BinaryData& getHashBytes(void) const;
		const tstring& getHashString(void) const;
	};
};


