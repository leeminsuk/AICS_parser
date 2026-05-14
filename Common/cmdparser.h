#pragma once

#include "typedef.h"
#include <vector>
#include <format>
#include <typeinfo>
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace cmdparser
{
    using namespace std;

    enum OPTION_INFO_TYPE
    {
        NAME = 0,
        ALTERNATIVE,
        DESCRIPTION
    };

    class CmdBase
    {
    protected:
        bool required_;         // 필수 옵션 여부
        bool isSet_;            // 옵션 값이 설정되었는 지 여부
        tstring name_;          // 옵션 이름
        tstring alternative_;   // 옵션 별칭
        tstring description_;   // 옵션 설명

    public:
        CmdBase(const tstring& name, const tstring& alternative, const tstring& description, bool required):
            required_(required), isSet_(false), name_(name), alternative_(alternative), description_(description) {};
        virtual ~CmdBase() = default;
        virtual bool compare(const tstring& name) const;
        virtual bool isRequired(void) const;
        virtual bool isSet(void) const;
        virtual tstring getOptionInfo(const OPTION_INFO_TYPE& type) const;
    };

    // template<typename T>만 쓰면 타입을 제한할 수 없음
    // 타입을 제한하기 위해서는 enable_if_t<>와 is_same<>과 같은 기능을 이용
    // CmdOption<T> 템플릿 클래스의 타입을 int, float, tstring으로 제한

    template<typename T, 
        typename = typename enable_if_t<
        is_same<T, int>::value ||
        is_same<T, long>::value ||
        is_same<T, unsigned long>::value ||
        is_same<T, long long>::value ||
        is_same<T, unsigned long long>::value ||
        is_same<T, float>::value ||
        is_same<T, double>::value ||
        is_same<T, tstring>::value > >
    class CmdOption : public CmdBase
    {
    private:
        T value_;

    public:
        CmdOption(const tstring& name, const tstring& alternative, const tstring& description, bool required) :
            CmdBase(name, alternative, description, required) {};
        virtual ~CmdOption() override = default;

        // 템플릿 함수의 경우 헤더에 구현이 같이 포함되어야 함
        // hpp 파일을 이용해서 파일을 분리해서 작성할 수는 있지만 오히려 코드 가독성을 저하시킬 수 있음

        T get(void) { return value_; };
        void set(T value)
        {
            value_ = value;
            isSet_ = true;
        };
    };

    class CmdParser
    {
    private:
        bool help_;
        vector<CmdBase*> command_;

    private:
        bool hasOptions(void) const;
        bool isRequiredOptionSet(void) const;
        vector<CmdBase*>::iterator find(const tstring& name);

    public:
        CmdParser() : help_(false) {};
        ~CmdParser() { clear(); };
        void clear(void);
        bool isPrintHelp(void) const;
        void parseCmdLine(int argc, TCHAR* argv[]);
        tstring getHelpMessage(const tstring& program) const;

        // 템플릿 함수의 경우 헤더에 구현이 같이 포함되어야 함
        // hpp 파일을 이용해서 파일을 분리해서 작성할 수는 있지만 오히려 코드 가독성을 저하시킬 수 있음

        // 필수 옵션 등록
        template<typename T>
        void set_required(const tstring& name, const tstring& alternative, const tstring& description = _T(""))
        {
            command_.push_back(dynamic_cast <CmdBase*>(new CmdOption<T>(name, alternative, description, true)));
        };

        // 선택 옵션 등록
        template<typename T>
        void set_optional(const tstring& name, const tstring& alternative, T defaultValue, const tstring& description = _T(""))
        {
            CmdOption<T>* cmd_option = new CmdOption<T>(name, alternative, description, false);
            cmd_option->set(defaultValue);

            command_.push_back(dynamic_cast <CmdBase*>(cmd_option));
        };

        // 옵션에 설정된 값 얻기
        template<typename T>
        T get(const tstring& name)
        {
            vector<CmdBase*>::iterator iter = find(name);
            if (iter != command_.end())
            {
                return (dynamic_cast <CmdOption<T> *>(*iter))->get();
            }
            else
            {
                throw runtime_error("The option does not exist!");
            }
        };
    };
};

