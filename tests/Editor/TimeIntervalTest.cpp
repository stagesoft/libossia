// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <catch.hpp>
#include <ossia/detail/config.hpp>
#include "TestUtils.hpp"


#include <iostream>

using namespace ossia;

void event_callback(time_event::status newStatus)
{
}

/*! test life cycle and accessors functions */
TEST_CASE ("test_basic", "test_basic")
{
  auto start_node = std::make_shared<time_sync>();
  auto start_event = *(start_node->emplace(start_node->get_time_events().begin(), &event_callback));

  auto end_node = std::make_shared<time_sync>();
  auto end_event = *(end_node->emplace(end_node->get_time_events().begin(), &event_callback));

  auto interval = time_interval::create(ossia::time_interval::exec_callback{[] (auto&&... args) {  }}, *start_event, *end_event, 1000._tv);
  ossia::clock c{*interval};
  REQUIRE(interval != nullptr);

  REQUIRE(c.get_granularity() == 1._tv);
  REQUIRE(interval->get_offset() == 0._tv);
  REQUIRE(interval->get_internal_speed() == 1.);
  REQUIRE(interval->get_nominal_duration() == 1000._tv);
  REQUIRE(interval->get_min_duration() == 0._tv);
  REQUIRE(interval->get_max_duration() == Infinite);

  using namespace std::literals;

  c.set_granularity(50ms);
  interval->set_speed(2.);
  interval->set_nominal_duration(2000._tv);
  interval->set_min_duration(1000._tv);
  interval->set_max_duration(3000._tv);
  interval->offset(500._tv);

  REQUIRE(c.get_granularity() == 50000._tv);
  REQUIRE(interval->get_internal_speed() == 2.);
  REQUIRE(interval->get_nominal_duration() == 2000._tv);
  REQUIRE(interval->get_min_duration() == 1000._tv);
  REQUIRE(interval->get_max_duration() == 3000._tv);
  REQUIRE(interval->get_offset() == 500._tv);

  REQUIRE(c.running() == false);
  REQUIRE(interval->get_date() == 500._tv);

  REQUIRE(&interval->get_start_event() == start_event.get());
  REQUIRE(&interval->get_end_event() == end_event.get());

  //! \todo test clone()
}

/*! test edition functions */
TEST_CASE ("test_edition", "test_edition")
{
  auto start_node = std::make_shared<time_sync>();
  auto start_event = *(start_node->emplace(start_node->get_time_events().begin(), &event_callback));

  auto end_node = std::make_shared<time_sync>();
  auto end_event = *(end_node->emplace(end_node->get_time_events().begin(), &event_callback));

  auto interval = time_interval::create(ossia::time_interval::exec_callback{[] (auto&&... args) { }}, *start_event, *end_event, 1000._tv);
  auto scenar = std::make_unique<scenario>();

  auto scenar_ptr = scenar.get();
  interval->add_time_process(std::move(scenar));
  REQUIRE(interval->get_time_processes().size() == 1);

  interval->remove_time_process(scenar_ptr);
  REQUIRE(interval->get_time_processes().size() == 0);
}

/*! test execution functions */
TEST_CASE ("test_execution", "test_execution")
{
  //      TestDevice t;
  //      auto start_node = std::make_shared<time_sync>();
  //      auto start_event = *(start_node->emplace(start_node->get_time_events().begin(), &event_callback));

  //      auto end_node = std::make_shared<time_sync>();
  //      auto end_event = *(end_node->emplace(end_node->get_time_events().begin(), &event_callback));

  //      auto interval = time_interval::create(&interval_callback, *start_event, *end_event, 1000._tv);

  //      auto s = new scenario;

  //      interval->add_time_process(std::unique_ptr<ossia::time_process>(s));
  //      auto a = new automation{*t.float_addr, std::make_shared<curve<double, float>>()};
  //      interval->add_time_process(std::unique_ptr<ossia::time_process>(a));
  //      auto m = new mapper{*t.float_addr, *t.float_addr, std::make_shared<curve<float, float>>()};
  //      interval->add_time_process(std::unique_ptr<ossia::time_process>(m));
  //      auto l = new loop{10._tv, {}, {}, {}};
  //      interval->add_time_process(std::unique_ptr<ossia::time_process>(l));

  //      interval->start_and_tick();
  //      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  //      interval->pause();
  //      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  //      interval->resume();
  //      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  //      interval->stop();
  //      std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
