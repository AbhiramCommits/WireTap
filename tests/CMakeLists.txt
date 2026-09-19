add_executable(wiretap_tests
  test_itch.cpp
  test_decoder.cpp
  test_malformed.cpp
  test_roundtrip.cpp
  test_spsc_ring.cpp
  test_book_builder.cpp
  test_receiver.cpp
  test_time_base.cpp
  test_latency.cpp
  test_gap_tracker.cpp
  test_recovery.cpp
  test_archive_writer.cpp)
target_link_libraries(wiretap_tests PRIVATE wiretap GTest::gtest_main)
target_compile_definitions(wiretap_tests PRIVATE
  WIRETAP_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
add_test(NAME wiretap_tests COMMAND wiretap_tests)
