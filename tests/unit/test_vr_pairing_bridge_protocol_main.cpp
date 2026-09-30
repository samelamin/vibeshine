/**
 * @file tests/unit/test_vr_pairing_bridge_protocol_main.cpp
 * @brief Minimal standalone test runner for the portable VR pairing bridge
 *        protocol tests.
 *
 * The portable test suite runs without gtest; this file defines a tiny
 * TEST/TEST_F macro + main() that runs every registered test in source
 * order. The Windows-only IPC tests link against gtest because they need
 * thread/test fixtures; portable tests do not.
 */
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace vr_pairing_test {
  struct test_case_t {
    const char *suite;
    const char *name;
    std::function<void()> body;
  };

  std::vector<test_case_t> &registry() {
    static std::vector<test_case_t> r;
    return r;
  }

  struct registrar_t {
    registrar_t(const char *suite, const char *name, std::function<void()> body) {
      registry().push_back({suite, name, std::move(body)});
    }
  };
}  // namespace vr_pairing_test

#define TEST(suite, name) \
  static void vrpb_test_##suite##_##name(); \
  static vr_pairing_test::registrar_t vrpb_reg_##suite##_##name { \
    #suite, \
    #name, \
    vrpb_test_##suite##_##name \
  }; \
  static void vrpb_test_##suite##_##name()

#define EXPECT_TRUE(x) \
  do { \
    if (!(x)) { \
      std::fprintf(stderr, "  FAIL %s:%d: EXPECT_TRUE(%s)\n", __FILE__, __LINE__, #x); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define EXPECT_FALSE(x) \
  do { \
    if ((x)) { \
      std::fprintf(stderr, "  FAIL %s:%d: EXPECT_FALSE(%s)\n", __FILE__, __LINE__, #x); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define EXPECT_EQ(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av == _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: EXPECT_EQ(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define EXPECT_LE(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av <= _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: EXPECT_LE(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define EXPECT_GE(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av >= _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: EXPECT_GE(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_TRUE(x) \
  do { \
    if (!(x)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_TRUE(%s)\n", __FILE__, __LINE__, #x); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_FALSE(x) \
  do { \
    if ((x)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_FALSE(%s)\n", __FILE__, __LINE__, #x); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_EQ(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av == _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_EQ(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_LE(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av <= _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_LE(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_GE(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av >= _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_GE(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_NE(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av != _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_NE(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define ASSERT_LT(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av < _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: ASSERT_LT(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

#define EXPECT_NE(a, b) \
  do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av != _bv)) { \
      std::fprintf(stderr, "  FAIL %s:%d: EXPECT_NE(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
      vrpb_current_failed = true; \
      return; \
    } \
  } while (0)

static thread_local bool vrpb_current_failed = false;

#include "test_vr_pairing_bridge_protocol.cpp"

int main() {
  int total = 0;
  int failed = 0;
  std::string current_suite;
  for (const auto &tc : vr_pairing_test::registry()) {
    if (tc.suite != current_suite) {
      current_suite = tc.suite;
      std::printf("[%s]\n", current_suite.c_str());
    }
    vrpb_current_failed = false;
    std::printf("  %s ... ", tc.name);
    std::fflush(stdout);
    try {
      tc.body();
    } catch (const std::exception &e) {
      std::fprintf(stderr, "  FAIL %s.%s: exception: %s\n", tc.suite, tc.name, e.what());
      vrpb_current_failed = true;
    }
    if (vrpb_current_failed) {
      ++failed;
      std::printf("FAIL\n");
    } else {
      std::printf("ok\n");
    }
    ++total;
  }
  std::printf("\n%d tests, %d failed\n", total, failed);
  return failed == 0 ? 0 : 1;
}
