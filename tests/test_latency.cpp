#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>

#include "latency.hpp"

namespace wt = wiretap;

namespace {

std::string make_temp_dir() {
  char tmpl[] = "/tmp/wiretap-latency-XXXXXX";
  char* dir = ::mkdtemp(tmpl);
  EXPECT_NE(dir, nullptr);
  return dir;
}

}  // namespace

TEST(LatencyRecorder, RecordsAndReportsPercentiles) {
  wt::LatencyRecorder rec;
  // Values 100, 1000, 10000 ns: clearly separated at 3 significant digits.
  for (int i = 0; i < 100; ++i) rec.record(wt::LatencyStage::DecodeTime, 100);
  for (int i = 0; i < 100; ++i) rec.record(wt::LatencyStage::DecodeTime, 1000);
  for (int i = 0; i < 100; ++i) rec.record(wt::LatencyStage::DecodeTime, 10000);

  EXPECT_EQ(rec.count(wt::LatencyStage::DecodeTime), 300u);
  EXPECT_EQ(rec.count(wt::LatencyStage::WireToUserspace), 0u);
  EXPECT_EQ(rec.value_at(wt::LatencyStage::DecodeTime, 50.0), 1000u);
  // Bucket granularity at 3 significant digits: reported values are the
  // bucket's highest equivalent value (here 10007 for the 10000 bucket).
  EXPECT_GE(rec.value_at(wt::LatencyStage::DecodeTime, 90.0), 10000u);
  EXPECT_LE(rec.value_at(wt::LatencyStage::DecodeTime, 90.0), 10050u);
  EXPECT_GE(rec.value_at(wt::LatencyStage::DecodeTime, 99.99), 10000u);
  EXPECT_LE(rec.value_at(wt::LatencyStage::DecodeTime, 99.99), 10050u);
  EXPECT_LE(rec.max_value(wt::LatencyStage::DecodeTime), 10050u);
  EXPECT_NEAR(rec.mean(wt::LatencyStage::DecodeTime), 3700.0, 10.0);
}

TEST(LatencyRecorder, ZeroClampsToMinimum) {
  wt::LatencyRecorder rec;
  rec.record(wt::LatencyStage::QueueDelay, 0);
  rec.record(wt::LatencyStage::QueueDelay, 1);
  EXPECT_EQ(rec.count(wt::LatencyStage::QueueDelay), 2u);
}

TEST(LatencyRecorder, MergeAccumulates) {
  wt::LatencyRecorder a;
  wt::LatencyRecorder b;
  for (int i = 0; i < 1000; ++i) a.record(wt::LatencyStage::DecodeTime, 500);
  for (int i = 0; i < 500; ++i) b.record(wt::LatencyStage::DecodeTime, 900);
  a.merge(b);
  EXPECT_EQ(a.count(wt::LatencyStage::DecodeTime), 1500u);
}

TEST(LatencyRecorder, WritesHgrmAndJsonReports) {
  wt::LatencyRecorder rec;
  for (int i = 0; i < 1000; ++i) {
    rec.record(wt::LatencyStage::WireToUserspace, 250);
    rec.record(wt::LatencyStage::QueueDelay, 700);
    rec.record(wt::LatencyStage::DecodeTime, 4000);
    rec.record(wt::LatencyStage::WireToBook, 8000);
  }

  const std::string dir = make_temp_dir();
  FILE* sink = ::tmpfile();
  rec.write_report(dir, "test", sink);
  if (sink != nullptr) std::fclose(sink);

  auto read_file = [](const std::string& path) {
    std::ifstream f(path);
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
  };

  const std::string hgrm = read_file(dir + "/test-wire_to_book.hgrm");
  EXPECT_NE(hgrm.find("Value"), std::string::npos);
  EXPECT_NE(hgrm.find("Percentile"), std::string::npos);
  EXPECT_NE(hgrm.find("TotalCount"), std::string::npos);

  const std::string json = read_file(dir + "/test-latency.json");
  EXPECT_NE(json.find("\"wire_to_book\""), std::string::npos);
  EXPECT_NE(json.find("\"p50_ns\""), std::string::npos);
  EXPECT_NE(json.find("\"count\": 1000"), std::string::npos);

  ::unlink((dir + "/test-wire_to_userspace.hgrm").c_str());
  ::unlink((dir + "/test-queue_delay.hgrm").c_str());
  ::unlink((dir + "/test-decode_time.hgrm").c_str());
  ::unlink((dir + "/test-wire_to_book.hgrm").c_str());
  ::unlink((dir + "/test-latency.json").c_str());
  ::rmdir(dir.c_str());
}
