// RTP1-ARCH-03：RTP host 单测的入口。
//
// DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN 让 doctest 生成 main()（一个翻译单元里只能定义一次）。
// 本文件只放一条冒烟用例，用来证明「工程能配置、能编译、能跑测试」；真正的算法用例放在
// lib/ 下，由 CMakeLists.txt 的 RTP_HOST_TEST_SOURCES 显式列出。
//
// 用例命名建议以被测实体开头（如 RtpStreamKey ...），这样 run_host_tests.ps1 的
// -Test "RtpStreamKey*" 过滤器能直接命中。

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

TEST_CASE("host test harness smoke check") {
    // 示例断言：只验证工具链与 doctest 接线正常。
    CHECK(2 * 21 == 42);
    CHECK_EQ(2 * 21, 42);
}
