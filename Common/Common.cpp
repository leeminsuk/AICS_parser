#include <iostream>
#include <Windows.h>
#include "testcase.h"
#include "strconv.h"
#include <string_view>
#include <algorithm>

int main()
{
    // 유니코드 출력시 로케일 설정이 필요
    // 시스템의 기본 로케일을 따르도록 설정
    setlocale(LC_ALL, "");

    TestCase testcase;

    // testcase.strConvTest();
    // testcase.loggerTest();
    // testcase.cmdParserTest();
    // testcase.peParserTest();
    testcase.hashTest();
}

