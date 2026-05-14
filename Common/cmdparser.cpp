#pragma once

#include "cmdparser.h"

namespace cmdparser
{
    using namespace std;

    // 옵션 이름 비교 (이름 또는 별칭이 일치하는 지 여부 확인)
    bool CmdBase::compare(const tstring& name) const
    { 
        return ((name_.compare(name) == 0) || (alternative_.compare(name) == 0)); 
    };

    // 필수 옵션인지 여부 확인
    bool CmdBase::isRequired(void) const
    { 
        return required_; 
    };

    // 옵션 값이 설정되었는 지 여부 확인
    bool CmdBase::isSet(void) const
    { 
        return isSet_; 
    };
    
    // OPTION_INFO_TYPE에 정의된 옵션의 정보를 얻음
    tstring CmdBase::getOptionInfo(const OPTION_INFO_TYPE& type) const
    {
        switch (type)
        {
        case NAME:
            return name_;
        case ALTERNATIVE:
            return alternative_;
        case DESCRIPTION:
            return description_;
        default:
            return _T("");
        }
    };

    // 옵션이 하나라도 등록 되었는지 여부 확인
    bool CmdParser::hasOptions(void) const
    { 
        return !command_.empty(); 
    };

    // 등록되어 있는 필수 옵션들이 다 설정되었는지 체크
    bool CmdParser::isRequiredOptionSet(void) const
    {
        bool isSet = true;

        for (const auto& iter : command_)
        {
            if (!iter->isSet())
            {
                isSet = false;
                break;
            };
        }
        return isSet;
    }

    // 이름으로 옵션이 저장된 위치의 iterator 찾기
    vector<CmdBase*>::iterator CmdParser::find(const tstring& name)
    {
        for (vector<CmdBase*>::iterator iter = command_.begin(); iter != command_.end(); iter++)
        {
            if ((*iter)->compare(name))
            {
                return iter;
            }
        }
        return command_.end();
    };

    // 저장된 옵션 모두 제거
    void CmdParser::clear(void)
    {
        for (const auto& iter : command_)
        {
            delete iter;
        }
        command_.clear();
        help_ = false;
    };

    // 도움말 출력 여부 확인
    // (도움말 출력 옵션이 지정되었거나 등록된 옵션이 없거나 
    // 필수 옵션의 값이 설정되지 않은 경우 도움말 출력이 필요)
    bool CmdParser::isPrintHelp(void) const
    {
        return (help_ || (!hasOptions()) || (!isRequiredOptionSet()));
    };

    // command line parsing
    void CmdParser::parseCmdLine(int argc, TCHAR* argv[])
    {
        tstring name;
        tstring command_str;
        int char_index = 0;

        if (argc < 1)
        {
            tcout << _T("No arguments provided.\n");
        }
        else
        {               
            // 첫 번째 항목은 실행 파일 자신의 이름이기 때문에 제거
            for (int index = 1; index < argc; index++)
            {
                // 도움말 출력 옵션이 지정 됐는지 확인 
                name = argv[index];
                if ((name.compare(_T("-h")) == 0) || (name.compare(_T("--help")) == 0))
                {
                    help_ = true;
                    break;
                }
                else if (name.at(0) == '-')
                {   
                    // 옵션 문자열에서 모든 '-' 문자 제거 (erase와 remove 같이 사용해야 함)
                    name.erase(remove(name.begin(), name.end(), '-'), name.end());

                    // 등록된 옵션인지 여부를 확인하여, 등록된 옵션이면 입력된 값을 읽어서 저장
                    // iter == vector<CmdBase*>::iterator
                    const auto& iter = find(name);

                    if ((iter != command_.end()) && (++index < argc)) // ++index로 옵션에 지정된 값 위치로 이동
                    {
                        const auto& type = typeid(*(*iter));

                        if (type == typeid(CmdOption<int>))
                        {
                            (dynamic_cast<CmdOption<int>*>(*iter))->set(stol(argv[index]));
                        }
                        else if (type == typeid(CmdOption<long>))
                        {
                            (dynamic_cast<CmdOption<long>*>(*iter))->set(stol(argv[index]));
                        }
                        else if (type == typeid(CmdOption<unsigned long>))
                        {
                            (dynamic_cast<CmdOption<unsigned long>*>(*iter))->set(stoul(argv[index]));
                        }
                        else if (type == typeid(CmdOption<long long>))
                        {
                            (dynamic_cast<CmdOption<long long>*>(*iter))->set(stoll(argv[index]));
                        }
                        else if (type == typeid(CmdOption<unsigned long long>))
                        {
                            (dynamic_cast<CmdOption<unsigned long long>*>(*iter))->set(stoull(argv[index]));
                        }
                        else if (type == typeid(CmdOption<float>))
                        {
                            (dynamic_cast<CmdOption<float>*>(*iter))->set(stof(argv[index]));
                        }
                        else if (type == typeid(CmdOption<double>))
                        {
                            (dynamic_cast<CmdOption<double>*>(*iter))->set(stod(argv[index]));
                        }
                        else if (type == typeid(CmdOption<tstring>))
                        {
                            (dynamic_cast<CmdOption<tstring>*>(*iter))->set(tstring(argv[index]));
                        }
                        // typeid 인식 가능한 타입에 대해서 추가 가능(단, 템플릿 클래스 정의에서도 타입 추가 필요)
                        else
                        {
                            // typeid name()은 const char*
                            cout << format("Unknown option type : {}\n", typeid(*(*iter)).name());
                        }
                    }
                }
            }
        }
    };

    // 도움말 문자열 얻기
    tstring CmdParser::getHelpMessage(const tstring& program) const
    {
        tstring help_msg;
        tstring required_option;
        tstring optional_option;

        for (auto& iter : command_)
        {
            if (iter->isRequired())
            {
                required_option.append(format(_T("-{}, --{} \t{}\n"), 
                    iter->getOptionInfo(NAME), 
                    iter->getOptionInfo(ALTERNATIVE), 
                    iter->getOptionInfo(DESCRIPTION)));
            }
            else
            {
                optional_option.append(format(_T("-{}, --{}\t{}\n"),
                    iter->getOptionInfo(NAME),
                    iter->getOptionInfo(ALTERNATIVE),
                    iter->getOptionInfo(DESCRIPTION)));
            }
        }
        help_msg = format(_T("Usage: {} [options]\n\n"), program);
        if (required_option.length() > 0)
        {
            help_msg.append(format(_T("Required Otions:\n{}\n"), required_option));
        }
        if (optional_option.length() > 0)
        {
            help_msg.append(format(_T("Optional Otions:\n{}\n"), optional_option));
        }
        return help_msg;
    };
};
