#include "peparser.h"

namespace peparser
{
	PEParser::PEParser() : 
		peBase_(nullptr), peStruct_({ 0, })
	{
		logger_.setLogType(LOG_LEVEL_ERROR, LOG_DIRECTION_CONSOLE, TRUE);
	};

	PEParser::~PEParser()
	{
		close();
	};

	void PEParser::close(void)
	{
		// 생성된 객체(PEFile or PEProcess) 해제
		delete peBase_;
		peBase_ = nullptr;

		// peStruct_ 멤버 초기화
		peStruct_.baseAddress = 0;
		peStruct_.imageBase = 0;
		peStruct_.sizeOfHeaders = 0;
		peStruct_.numberofSections = 0;
		peStruct_.dosHeader = nullptr;
		peStruct_.fileHader = nullptr;
		peStruct_.ntHeader32 = nullptr;
		peStruct_.sectionHeader = nullptr;
		peStruct_.dataDirectory = nullptr;
		peStruct_.sectionList.clear();
		peStruct_.exportFunctionList.clear();
		peStruct_.importFunctionList.clear();
	};
	
	bool PEParser::open(const size_t& pid)
	{
		PEProcess* peProcess = new PEProcess();
		peBase_ = reinterpret_cast<IPEBase*>(peProcess);
		return peProcess->open(pid);
	};

	bool PEParser::open(const tstring_view& filePath)
	{
		PEFile* peFile = new PEFile();
		peBase_ = reinterpret_cast<IPEBase*>(peFile);
		return peFile->open(filePath);
	};

	bool PEParser::parsePE(const PE_DIRECTORY_TYPE& parseType)
	{
		if (peBase_->isPE())
		{
			// Set base address
			peStruct_.baseAddress = peBase_->getBaseAddress();

			// Set file path
			peStruct_.filePath = peBase_->getFilePath();

			// PE header parsing
			parseHeaders();

			// PE DataDirectory entry parsing
			if ((parseType & PE_DIRECTORY_EAT) == PE_DIRECTORY_EAT)
			{
				parseEAT();
			};
			if ((parseType & PE_DIRECTORY_IAT) == PE_DIRECTORY_IAT)
			{
				parseIAT();
			};
			if ((parseType & PE_DIRECTORY_TLS) == PE_DIRECTORY_TLS)
			{
				parseTLS();
			};
			if ((parseType & PE_DIRECTORY_DEBUG) == PE_DIRECTORY_DEBUG)
			{
				parseDebug();
			};
			return true;
		}
		else 
		{
			return false;
		}
	};

	// PE 정보를 담은 구조체 리턴
	const PE_STRUCT& PEParser::getPEStructure(void) const
	{
		return peStruct_;
	};

	// PE 파일의 문자열은 UTF8 문자열이기 때문에 변환 필요
	tstring PEParser::getPEString(const char8_t* peStr)
	{
		return strConv_.to_tstring(peStr);
	};

	// 섹션 이름 같은 경우 최대 8바이트를 이용해서 이름이 저장되어 있는데
	// NULL 문자('\0') 없이 전체 바이트 모두 문자로 차 있을 수 있기 때문에 
	// 이 부분을 감안해서 처리 필요
	tstring PEParser::getPEString(const char8_t* peStr, const size_t& maxLength)
	{
		// UTF8 문자열을 생성(여기에는 NULL 문자가 여러 개 포함된 상태일 수 있음)
		const std::u8string u8string(peStr, maxLength);

		// c_str()을 통해서 불필요한 NULL 문자를 제거한 상태로 문자열 변환
		// ( c_str()은 NULL 문자가 포함된 문자열을 리턴 )
		return strConv_.to_tstring(u8string.c_str());
	};

	void PEParser::parseSectionHeaders(void)
	{
		size_t realAddress = 0;
		PIMAGE_SECTION_HEADER sectionHeader = peStruct_.sectionHeader;

		for (WORD index = 0; index < peStruct_.numberofSections; index++)
		{
			// 섹션의 실제 주소를 구함
			if (typeid(*peBase_) == typeid(PEProcess))
			{
				// 프로세스의 경우 그냥 VirtualAddress를 사용 (RAV to RAW 계산 필요 없음) 
				realAddress = peBase_->getBaseAddress() + sectionHeader->VirtualAddress;
			}
			else if (typeid(*peBase_) == typeid(PEFile))
			{
				// 파일의 섹션의 경우 RVA가 VirtualAddress이기 때문에 PointerToRawData가 RAW
				// RAW = RVA - VirtualAddress + PointerToRawData
				realAddress = peBase_->getBaseAddress() + sectionHeader->PointerToRawData;
			}

			// 섹션의 주요 정보를 담은 SECTION_INFO 구조체를 sectionList_에 추가
			peStruct_.sectionList.push_back(
				SECTION_INFO{ 
					getPEString(reinterpret_cast<const char8_t*>(sectionHeader->Name), 
					sizeof(sectionHeader->Name)),
					static_cast<size_t>(sectionHeader->VirtualAddress), 
					static_cast<size_t>(sectionHeader->PointerToRawData), 
					static_cast<size_t>(sectionHeader->SizeOfRawData), 
					static_cast<size_t>(sectionHeader->Characteristics), 
					realAddress 
				}
			);

			// 다음 섹션 헤더로 포인터 이동
			sectionHeader++;
		}

		// RVA to RAW 계산 등을 위해서 필요한 섹션 정보를 설정
		peBase_->setSectionList(peStruct_.sectionList);
	};

	void PEParser::parseHeaders(void)
	{
		peStruct_.dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peStruct_.baseAddress);
		peStruct_.is32Bit = peBase_->is32bit();

		if (peStruct_.is32Bit)
		{			
			peStruct_.ntHeader32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peStruct_.baseAddress + peStruct_.dosHeader->e_lfanew);
			peStruct_.fileHader = reinterpret_cast<PIMAGE_FILE_HEADER>(&(peStruct_.ntHeader32->FileHeader));
			peStruct_.sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(peStruct_.baseAddress + peStruct_.dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
			peStruct_.imageBase = peStruct_.ntHeader32->OptionalHeader.ImageBase;
			peStruct_.dataDirectory = peStruct_.ntHeader32->OptionalHeader.DataDirectory;
			peStruct_.sizeOfHeaders = peStruct_.ntHeader32->OptionalHeader.SizeOfHeaders;
		}
		else
		{
			peStruct_.ntHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peStruct_.baseAddress + peStruct_.dosHeader->e_lfanew);
			peStruct_.fileHader = reinterpret_cast<PIMAGE_FILE_HEADER>(&(peStruct_.ntHeader64->FileHeader));
			peStruct_.sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(peStruct_.baseAddress + peStruct_.dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
			peStruct_.imageBase = peStruct_.ntHeader64->OptionalHeader.ImageBase;
			peStruct_.dataDirectory = peStruct_.ntHeader64->OptionalHeader.DataDirectory;
			peStruct_.sizeOfHeaders = peStruct_.ntHeader64->OptionalHeader.SizeOfHeaders;
		}
		peStruct_.numberofSections = peStruct_.fileHader->NumberOfSections;

		// RvaToRaw 계산 등을 위해서 헤더들의 전체 크기(PE Header + Section Header) 설정
		peBase_->setHeaderSize(peStruct_.sizeOfHeaders);

		// Parse section header
		parseSectionHeaders();
	};

	void PEParser::parseEAT(void)
	{
		tstring moduleName;
		size_t exportDescriptorAddress = 0;
		size_t exportDescriptorRva = 0;
		size_t odinalBase = 0;
		size_t functionsAddress = 0;
		size_t nameOrdinalsAddress = 0;
		size_t namesAddress = 0;
		size_t realNamesAddress = 0;
		PIMAGE_EXPORT_DIRECTORY exportDirectory = nullptr;

		// Export Directory는 DataDirectory의 첫 번째
		exportDescriptorRva = peStruct_.dataDirectory[0].VirtualAddress;
		if (exportDescriptorRva != 0x0)
		{
			// PE 파일에서 IED(IMAGE_EXPORT_DIRECTORY)는 하나만 존재
			if (peBase_->getRealAddress(exportDescriptorRva, exportDescriptorAddress))
			{
				exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(exportDescriptorAddress);
				FunctionInfoList functionInfoList(exportDirectory->NumberOfFunctions);

				// Export Module Name : 함수를 제공하는 exe나 dll의 이름
				if (peBase_->getRealAddress(exportDirectory->Name, realNamesAddress))
				{
					moduleName = getPEString(reinterpret_cast<const char8_t*>(realNamesAddress));
				}
				else
				{
					logger_.log(format(_T("Can't get module name address : RVA = 0x{:x}"), static_cast<size_t>(exportDirectory->Name)), LOG_LEVEL_ERROR);
				}

				// Ordinal 은 function address index + Base(odinalBase) 값
				odinalBase = exportDirectory->Base;

				// AddressOfFunctions : Export하는 함수의 주소들을 담고 있는 배열의 시작 주소
				// AddressOfNames : Export하는 함수 이름의 주소들을 담고 있는 배열의 시작 주소
				// AddressOfNameOrdinals : 함수 이름으로 Export하는 함수들의 함수 주소를 얻기 위해 필요한 
				//                         함수 주소 배열에서의 위치(index)들을 담고 있는 배열의 시작 주소
				if ((peBase_->getRealAddress(exportDirectory->AddressOfFunctions, functionsAddress)) &&
					(peBase_->getRealAddress(exportDirectory->AddressOfNames, namesAddress)) &&
					(peBase_->getRealAddress(exportDirectory->AddressOfNameOrdinals, nameOrdinalsAddress)))
				{
					// 이름이 존재하는 함수들의 이름을 functionInfoList에 저장
					for (DWORD index = 0; index < exportDirectory->NumberOfNames; index++)
					{
						if (peBase_->getRealAddress(reinterpret_cast<DWORD*>(namesAddress)[index], realNamesAddress))
						{
							functionInfoList[reinterpret_cast<WORD*>(nameOrdinalsAddress)[index]].Name = getPEString(reinterpret_cast<char8_t*>(realNamesAddress));
						}
					}

					// 전체 함수들의 정보를 목록에 저장
					for (DWORD index = 0; index < exportDirectory->NumberOfFunctions; index++)
					{
						if (reinterpret_cast<DWORD*>(functionsAddress)[index] != 0)
						{
							functionInfoList[index].Ordinal = static_cast<size_t>(odinalBase + index);
							functionInfoList[index].Address = static_cast<size_t>(reinterpret_cast<DWORD*>(functionsAddress)[index]);
						}
						else
						{
							logger_.log(format(_T("Export address is invalid > 0x{:x}, 0x{:x}"), reinterpret_cast<DWORD*>(functionsAddress)[index], (WORD)odinalBase + index), LOG_LEVEL_ERROR);
						}
					}
				}
				peStruct_.exportFunctionList.push_back(make_tuple(moduleName, functionInfoList));
			}
		}
	};

	void PEParser::parseIAT(void)
	{
		tstring moduleName;
		size_t importDescriptorAddress = 0;
		size_t importDescriptorRva = 0;
		size_t firstThunkAddress = 0;
		size_t originalThunkAddress = 0;
		size_t ordinal = 0;
		size_t ordinalAddress = 0;
		size_t iatAddress = 0;
		size_t nameAddress = 0;
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = nullptr;

		// Import Directory는 DataDirectory의 두 번째
		importDescriptorRva = peStruct_.dataDirectory[1].VirtualAddress;
		if (importDescriptorRva != 0)
		{
			if (peBase_->getRealAddress(importDescriptorRva, importDescriptorAddress))
			{
				while ((importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importDescriptorAddress))->OriginalFirstThunk != 0)
				{
					// Import하는 Module의 function list
					FunctionInfoList functionInfoList;

					// Import하는 Module 이름 얻기(NULL 문자를 만날 때까지 읽음)
					if (peBase_->getRealAddress(importDescriptor->Name, nameAddress))
					{
						moduleName = getPEString(reinterpret_cast<const char8_t*>(nameAddress));
					}
					else
					{
						logger_.log(format(_T("Can't get module name address : RVA = 0x{:x}"), static_cast<size_t>(importDescriptor->Name)), LOG_LEVEL_ERROR);
					}

					if (peBase_->is32bit())
					{
						// 32bit
						PIMAGE_THUNK_DATA32 firstThunkData = nullptr;
						PIMAGE_THUNK_DATA32 originalThunkData = nullptr;

						if (peBase_->getRealAddress(importDescriptor->FirstThunk, firstThunkAddress) &&
							peBase_->getRealAddress(importDescriptor->OriginalFirstThunk, originalThunkAddress))
						{
							while ((firstThunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(firstThunkAddress))->u1.AddressOfData != 0)
							{
								// FirstThunk의 경우 IAT(Import Address Table)의 주소를 담고 있기 때문에 
								// IMAGE_THUNK_DATA32의 AddressOfData 값이 함수의 주소
								// 단, 프로세스로 메모리에 로드된 이후에 실제 호출되는 주소값이 설정됨
								iatAddress = firstThunkData->u1.AddressOfData;

								// OriginalThunk의 경우 INT(Import Name Table)의 주소를 담고 있음
								originalThunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(originalThunkAddress);

								// 최상위 비트를 없앰(최상위 비트를 제거한 값이 Ordinal 값)
								// 최상위 비트는 왼쪽 쉬프트 연산 다음 오른 쪽 쉬프트 연산 수행
								ordinal = static_cast<DWORD>((originalThunkData->u1.Ordinal << 1) >> 1);

								// 원래 값과 비교해서 다르면 최상위 비트가 1로 설정 됐다는 의미
								if (ordinal != static_cast<size_t>(originalThunkData->u1.Ordinal))
								{
									// 최상위 비트가 1로 설정된 경우에는 Ordinal만 있는 함수
									functionInfoList.push_back(FUNCTION_INFO{ tstring(_T("")), ordinal,  iatAddress });
								}
								else
								{
									// Hint(Ordinal)와 함수 이름 읽기
									// IMAGE_IMPORT_BY_NAME 구조체를 통하지 않는 이유는 실제 프로세스 메모리에서 데이터를 읽어야 하는데 
									// IMAGE_IMPORT_BY_NAME 구조체가 Hint(WORD), Name(Char[1])으로만 정의되어 있어서 3Byte만 읽을 뿐이고 
									// 전체 함수 이름을 다 읽어 올 수 없는 문제가 있음(함수 이름의 크기를 알수 없기 때문)
									// 그래서 thunkData.u1.AddressOfData 주소를 통해서 Hint를 읽고 WORD 크기 만큼 주소를 증가 시켜 
									// getPEString() 함수로 이름을 읽도록 함
									if (peBase_->getRealAddress(originalThunkData->u1.AddressOfData, ordinalAddress))
									{
										ordinal = static_cast<size_t>(*(reinterpret_cast<WORD*>(ordinalAddress)));
										functionInfoList.push_back(
											FUNCTION_INFO{ 
												getPEString(reinterpret_cast<char8_t*>(ordinalAddress + sizeof(WORD))), 
												ordinal,  
												iatAddress 
											});
									}
								}
								firstThunkAddress += sizeof(IMAGE_THUNK_DATA32);
								originalThunkAddress += sizeof(IMAGE_THUNK_DATA32);
							}
						}
					}
					else
					{
						// 64bit
						PIMAGE_THUNK_DATA64 firstThunkData = nullptr;
						PIMAGE_THUNK_DATA64 originalThunkData = nullptr;

						if (peBase_->getRealAddress(importDescriptor->FirstThunk, firstThunkAddress) &&
							peBase_->getRealAddress(importDescriptor->OriginalFirstThunk, originalThunkAddress))
						{
							while ((firstThunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>(firstThunkAddress))->u1.AddressOfData != 0)
							{
								// FirstThunk의 경우 IAT(Import Address Table)의 주소를 담고 있기 때문에 
								// IMAGE_THUNK_DATA64의 AddressOfData 값이 함수의 주소
								// 단, 프로세스로 메모리에 로드된 이후에 실제 호출되는 주소값이 설정됨
								iatAddress = firstThunkData->u1.AddressOfData;

								// OriginalThunk의 경우 INT(Import Name Table)의 주소를 담고 있음
								originalThunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>(originalThunkAddress);

								// 최상위 비트를 없앰(최상위 비트를 제거한 값이 Ordinal 값)
								// 최상위 비트는 왼쪽 쉬프트 연산 다음 오른 쪽 쉬프트 연산 수행
								ordinal = (originalThunkData->u1.Ordinal << 1) >> 1;

								// 원래 값과 비교해서 다르면 최상위 비트가 1로 설정 됐다는 의미
								if (ordinal != static_cast<size_t>(originalThunkData->u1.Ordinal))
								{
									// 최상위 비트가 1로 설정된 경우에는 Ordinal만 있는 함수
									functionInfoList.push_back(FUNCTION_INFO{ tstring(_T("")), ordinal,  iatAddress });
								}
								else
								{
									// Hint(Ordinal)와 함수 이름 읽기
									// IMAGE_IMPORT_BY_NAME 구조체를 통하지 않는 이유는 실제 프로세스 메모리에서 데이터를 읽어야 하는데 
									// IMAGE_IMPORT_BY_NAME 구조체가 Hint(WORD), Name(Char[1])으로만 정의되어 있어서 3Byte만 읽을 뿐이고 
									// 전체 함수 이름을 다 읽어 올 수 없는 문제가 있음(함수 이름의 크기를 알수 없기 때문)
									// 그래서 thunkData.u1.AddressOfData 주소를 통해서 Hint를 읽고 WORD 크기 만큼 주소를 증가 시켜 
									// getPEString() 함수로 이름을 읽도록 함
									if (peBase_->getRealAddress(originalThunkData->u1.AddressOfData, ordinalAddress))
									{
										ordinal = static_cast<size_t>(*(reinterpret_cast<WORD*>(ordinalAddress)));
										functionInfoList.push_back(
											FUNCTION_INFO{ 
												getPEString(reinterpret_cast<char8_t*>(ordinalAddress + sizeof(WORD))), 
												ordinal,  
												iatAddress 
											});
									}
								}
								firstThunkAddress += sizeof(PIMAGE_THUNK_DATA64);
								originalThunkAddress += sizeof(PIMAGE_THUNK_DATA64);
							}
						}
					}
					peStruct_.importFunctionList.push_back(make_tuple(moduleName, functionInfoList));
					importDescriptorAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR);
				}
			}
		}
	};

	void PEParser::parseDebug(void)
	{
		size_t debugDirectoryAddress = 0;
		size_t pdbStructAddress = 0;
		PIMAGE_PDB_INFO pdbInfo = nullptr;
		PIMAGE_DEBUG_DIRECTORY debugDirectory = nullptr;

		// Debug Directory는 DataDirectory의 일곱번째
		if (peStruct_.dataDirectory[6].VirtualAddress != 0)
		{
			if (peBase_->getRealAddress(peStruct_.dataDirectory[6].VirtualAddress, debugDirectoryAddress))
			{
				while ((debugDirectory = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(debugDirectoryAddress))->AddressOfRawData != 0)
				{
					// IMAGE_DEBUG_DIRECTORY 구조체의 Type이 IMAGE_DEBUG_TYPE_CODEVIEW 이고 
					// 실제 데이터가 저장된 주소인 AddressOfRawData에 저장된 IMAGE_PDB_INFO의
					// Signature가 IMAGE_PDB_SIGNATURE일 때 PDB 파일 경로가 저장되어 있음
					if (debugDirectory->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
					{
						if (peBase_->getRealAddress(debugDirectory->AddressOfRawData, pdbStructAddress))
						{
							if ((pdbInfo = reinterpret_cast<PIMAGE_PDB_INFO>(pdbStructAddress))->Signature == IMAGE_PDB_SIGNATURE)
							{
								// pdbInfo->PdbFileName이 가리키는 주소는 pdbStructAddress 주소를 구할 때 
								// 이미 RVA to RAW 계산이 된 실제 주소이기 때문에 그대로 사용
								// u8FilePath는 실제 저장된 UTF8 문자열 저장
								peStruct_.pdbFileInfo.u8FilePath = reinterpret_cast<const char8_t*>(pdbInfo->PdbFileName);
								peStruct_.pdbFileInfo.FilePath = getPEString(peStruct_.pdbFileInfo.u8FilePath.c_str());
							}
						}
					}
					debugDirectoryAddress += sizeof(IMAGE_DEBUG_DIRECTORY);
				}
			}
		}
	};

	void PEParser::parseTLS(void)
	{
		size_t tlsDirectoryRva = 0;
		size_t tlsDirectoryAddress = 0;
		size_t tlsAddressOfCallBacks = 0;
		size_t tlsCurrentAddressOfCallBacks = 0;
		size_t tlsCallBackAddress = 0;
		size_t sizeofAddress = 0;
		BinaryData tlsData;

		// Tls Directory는 DataDirectory의 열번째
		if (peStruct_.dataDirectory[9].VirtualAddress != 0)
		{
			tlsDirectoryRva = peStruct_.dataDirectory[9].VirtualAddress;

			if (peBase_->is32bit())
			{
				// 32bit
				PIMAGE_TLS_DIRECTORY32 tlsDirectory = nullptr;
				sizeofAddress = sizeof(DWORD);

				// 먼저 IMAGE_TLS_DIRECTORY 구조체 주소를 얻음
				if (peBase_->getRealAddress(tlsDirectoryRva, tlsDirectoryAddress))
				{
					// PIMAGE_TLS_DIRECTORY64 주소를 얻음
					tlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(tlsDirectoryAddress);

					// IMAGE_TLS_DIRECTORY 구조체로부터 콜백 함수 배열이 저장된 주소인 AddressOfCallBacks를 얻음
					// 프로세스인 경우 AddressOfCallBacks 주소는 RVA가 아닌 실제 주소
					// 파일인 경우 ImageBase + RVA
					tlsAddressOfCallBacks = tlsDirectory->AddressOfCallBacks;
				}
			}
			else
			{
				// 64bit
				PIMAGE_TLS_DIRECTORY64 tlsDirectory = nullptr;
				sizeofAddress = sizeof(size_t);

				// 먼저 IMAGE_TLS_DIRECTORY 구조체 주소를 얻음
				if (peBase_->getRealAddress(tlsDirectoryRva, tlsDirectoryAddress))
				{
					// PIMAGE_TLS_DIRECTORY64 주소를 얻음
					tlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(tlsDirectoryAddress);

					// IMAGE_TLS_DIRECTORY 구조체로부터 콜백 함수 배열이 저장된 주소인 AddressOfCallBacks를 얻음
					// 프로세스인 경우 AddressOfCallBacks 주소는 RVA가 아닌 실제 주소
					// 파일인 경우 ImageBase + RVA
					tlsAddressOfCallBacks = tlsDirectory->AddressOfCallBacks;
				}
			}

			// TLS 콜백 함수 배열에서 주소를 얻음
			if (tlsAddressOfCallBacks != 0)
			{
				if (typeid(*peBase_) == typeid(PEProcess))
				{
					// 프로세스 인 경우 AddressOfCallBacks 주소가 RVA가 아닌 실제 주소이고
					// 프로세스 PE 이미지 내의 주소가 아니기 때문에 ReadProcessMemory로 
					// 해당 주소의 데이터를 프로세스 메모리에서 읽어야 함
					tlsCurrentAddressOfCallBacks = tlsAddressOfCallBacks;
					while(true)
					{
						if (peBase_->getData(tlsCurrentAddressOfCallBacks, sizeofAddress, tlsData))
						{
							if (sizeofAddress == sizeof(DWORD))
							{
								// 32bit
								tlsCallBackAddress = *(reinterpret_cast<DWORD*>(tlsData.data()));
							}
							else
							{
								// 64bit
								tlsCallBackAddress = *(reinterpret_cast<size_t*>(tlsData.data()));
							}

							if (tlsCallBackAddress != 0)
							{
								peStruct_.tlsCallbackList.push_back(TLS_CALLBACK{ tlsCallBackAddress });
							}
							else
							{
								// AddressOfCallBack 마지막
								break;
							}
						}
						else
						{
							logger_.log(format(_T("Can't read process memory : Address = 0x{:x}"), tlsCurrentAddressOfCallBacks), LOG_LEVEL_ERROR);
							break;
						}
						tlsCurrentAddressOfCallBacks += sizeofAddress;
					} 
				}
				else
				{
					// 파일에서는 AddressOfCallBacks의 주소가 ImageBase + RVA이기 때문에 
					// tlsCallbackAddress에서 ImageBase를 빼줘야 RVA를 얻을 수 있음
					if (peBase_->getRealAddress(tlsAddressOfCallBacks - peStruct_.imageBase, tlsCurrentAddressOfCallBacks))
					{
						while (true)
						{
							if (sizeofAddress == sizeof(DWORD))
							{
								// 32bit
								tlsCallBackAddress = *(reinterpret_cast<DWORD*>(tlsCurrentAddressOfCallBacks));
							}
							else
							{
								// 64bit
								tlsCallBackAddress = *(reinterpret_cast<size_t*>(tlsCurrentAddressOfCallBacks));
							}

							if (tlsCallBackAddress != 0)
							{
								peStruct_.tlsCallbackList.push_back(TLS_CALLBACK{ tlsCallBackAddress });
								tlsCurrentAddressOfCallBacks += sizeofAddress;
							}
							else
							{
								// AddressOfCallBack 마지막
								break;
							}
						} 
					}
				}
			}
		}
	};
};
