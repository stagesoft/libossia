// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include <ossia/detail/config.hpp>
#include <ossia/editor/scenario/time_interval.hpp>
#include <ossia/editor/scenario/time_event.hpp>
#include <ossia/editor/scenario/time_sync.hpp>
#include <ossia/editor/scenario/scenario.hpp>
#include <ossia/editor/scenario/clock.hpp>

#include <functional>
#include <iostream>
#include "TestUtils.hpp"

using namespace ossia;
using namespace std::placeholders;

std::shared_ptr<time_interval> main_interval;
std::vector<ossia::time_value> events_date;

static void main_interval_callback(bool, ossia::time_value date)
{
  std::cout << "Main Interval : " << date << std::endl;
}

static void first_interval_callback(bool, ossia::time_value date)
{
  std::cout << "First Interval : " << date << std::endl;
}

static void second_interval_callback(bool, ossia::time_value date)
{
  std::cout << "Second Interval : " << date << std::endl;
}

void event_callback(time_event::status newStatus)
{
  ossia::time_value date = main_interval->get_date();

  switch (newStatus)
  {
    case time_event::status::NONE:
    {
      std::cout << "Event NONE" << std::endl;
      break;
    }
    case time_event::status::PENDING:
    {
      std::cout << "Event PENDING at " << date << " ms" << std::endl;
      break;
    }
    case time_event::status::HAPPENED:
    {
      std::cout << "Event HAPPENED at " << date << " ms" << std::endl;
      events_date.push_back(date);
      break;
    }
    case time_event::status::DISPOSED:
    {
      std::cout << "Event DISPOSED at " << date << " ms" << std::endl;
      break;
    }
  }
}


/*! test life cycle and accessors functions */
TEST_CASE ("test_basic", "test_basic")
{
  auto scenar = std::make_shared<scenario>();
  REQUIRE(scenar != nullptr);

  REQUIRE(scenar->get_start_time_sync() != nullptr);

  REQUIRE(scenar->get_time_syncs().size() == 1);
  REQUIRE(scenar->get_time_intervals().size() == 0);

  REQUIRE(scenar->get_start_time_sync()->get_date() == 0_tv);

  auto e_callback = std::bind(&event_callback, _1);
  auto start_event = *(scenar->get_start_time_sync()->emplace(
                         scenar->get_start_time_sync()->get_time_events().begin(),
                         e_callback));

  auto end_node = std::make_shared<time_sync>();
  auto end_event = *(end_node->emplace(end_node->get_time_events().begin(), e_callback));
  auto interval = time_interval::create(ossia::time_interval::exec_callback{[] (auto&&... args) { main_interval_callback(args...); }}, *start_event, *end_event, 1000._tv, 1000._tv, 1000._tv);

  REQUIRE(end_node->get_date() == 1000._tv);
}

/*! test edition functions */
TEST_CASE ("test_edition", "test_edition")
{
  auto e_callback = std::bind(event_callback, _1);

  auto scenar = std::make_shared<scenario>();

  auto start_node = scenar->get_start_time_sync();
  auto start_event = *(start_node->emplace(start_node->get_time_events().begin(), e_callback));

  auto end_node = std::make_shared<time_sync>();
  scenar->add_time_sync(end_node);
  auto end_event = *(end_node->emplace(end_node->get_time_events().begin(), e_callback));

  auto interval = time_interval::create(ossia::time_interval::exec_callback{[] (auto&&... args) { main_interval_callback(args...); }}, *start_event, *end_event, 1000._tv, 1000._tv, 1000._tv);

  scenar->add_time_interval(interval);
  REQUIRE(scenar->get_time_intervals().size() == 1);
  REQUIRE(scenar->get_time_syncs().size() == 2);

  scenar->remove_time_interval(interval);
  REQUIRE(scenar->get_time_intervals().size() == 0);
  REQUIRE(scenar->get_time_syncs().size() == 2);

  auto lonely_node = std::make_shared<time_sync>();

  scenar->add_time_sync(lonely_node);
  REQUIRE(scenar->get_time_syncs().size() == 3);

  scenar->remove_time_sync(lonely_node);
  REQUIRE(scenar->get_time_syncs().size() == 2);
}

/*! test execution functions */
//! \todo maybe a way to test many scenario would be to load them from a files
TEST_CASE ("test_execution", "test_execution")
{
  using namespace ossia;
  auto e_callback = std::bind(event_callback, _1);

  auto main_start_node = std::make_shared<time_sync>();
  auto main_end_node = std::make_shared<time_sync>();
  auto main_start_event = *(main_start_node->emplace(main_start_node->get_time_events().begin(), e_callback));
  auto main_end_event = *(main_end_node->emplace(main_end_node->get_time_events().begin(), e_callback));
  main_interval = time_interval::create(ossia::time_interval::exec_callback{[] (auto&&... args) { main_interval_callback(args...); }}, *main_start_event, *main_end_event, 5000._tv, 5000._tv, 5000._tv);
  ossia::clock c{*main_interval};
  using namespace std::literals;
  c.set_granularity(50ms);

  auto main_scenario = std::make_unique<scenario>();

  auto scenario_start_node = main_scenario->get_start_time_sync();

  auto first_end_node = std::make_shared<time_sync>();
  auto first_start_event = *(scenario_start_node->emplace(scenario_start_node->get_time_events().begin(), e_callback));
  auto first_end_event = *(first_end_node->emplace(first_end_node->get_time_events().begin(), e_callback));
  auto first_interval = time_interval::create(ossia::time_interval::exec_callback{[=] (auto&&... args) { first_interval_callback(args...); }}, *first_start_event, *first_end_event, 1500._tv, 1500._tv, 1500._tv);

  main_scenario->add_time_sync(first_end_node);
  main_scenario->add_time_interval(first_interval);

  auto second_end_node = std::make_shared<time_sync>();
  auto second_end_event = *(second_end_node->emplace(second_end_node->get_time_events().begin(), e_callback));
  auto second_interval = time_interval::create(ossia::time_interval::exec_callback{[=] (auto&&... args) { second_interval_callback(args...); }}, *first_end_event, *second_end_event, 2000._tv, 2000._tv, 2000._tv);

  main_scenario->add_time_sync(second_end_node);
  main_scenario->add_time_interval(second_interval);

  main_interval->add_time_process(std::move(main_scenario));

  main_interval->set_speed(1.);
  first_interval->set_speed(1.);
  second_interval->set_speed(1.);

  events_date.clear();
  c.start_and_tick();

  while (c.running())
    ;

  // check TimeEvents date
  REQUIRE((int)events_date.size() == 3);
  REQUIRE(events_date[0] == Zero);
  REQUIRE(events_date[1] >= first_end_node->get_date());
  // todo REQUIRE(events_date[1] < (first_end_node->get_date() + main_interval->getGranularity()));
  REQUIRE(events_date[2] >= first_end_node->get_date());
  // todo REQUIRE(events_date[2] < first_end_node->get_date() + main_interval->getGranularity());
}
