// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/*!
 * \file scenario.cpp
 *
 * \author Théo de la Hogue
 *
 * This code is licensed under the terms of the "CeCILL-C"
 * http://www.cecill.info
 */

#include "Editor/Loop.h"

#include "Editor/Clock.h"
#include "Editor/TimeConstraint.h"
#include "Editor/TimeEvent.h"
#include "Editor/TimeSync.h"

#include <iostream>
#include <memory>

using namespace ossia;
using namespace std;

void main_interval_callback(
    ossia::time_value position, ossia::time_value date,
    shared_ptr<StateElement> element);
void main_start_event_callback(TimeEvent::Status newStatus);
void main_end_event_callback(TimeEvent::Status newStatus);

void loop_pattern_interval_callback(
    ossia::time_value position, ossia::time_value date,
    shared_ptr<StateElement> element);
void loop_pattern_start_event_callback(TimeEvent::Status newStatus);
void loop_pattern_end_event_callback(TimeEvent::Status newStatus);

void print_event_status(TimeEvent::Status newStatus, std::string name);

int main()
{
  // create start and the end TimeSyncs
  auto start_node = TimeSync::create();
  auto end_node = TimeSync::create();

  /*
     Main Constraint setup
     */

  auto main_start_event = *(start_node->emplace(
      start_node->get_time_events().begin(), &main_start_event_callback));
  auto main_end_event = *(
      end_node->emplace(end_node->get_time_events().begin(), &main_end_event_callback));

  time_value main_duration(2000.);
  auto main_interval = TimeConstraint::create(
      main_interval_callback, main_start_event, main_end_event, main_duration);

  main_interval->set_granularity(10.);

  /*
     Loop Process setup
     */

  auto loop = Loop::create(
      90., loop_pattern_interval_callback, loop_pattern_start_event_callback,
      loop_pattern_end_event_callback);

  main_interval->add_time_process(loop);

  /*
     Display TimeSync's date
     */

  cout << "start node date = " << start_node->get_date() << endl;
  cout << "end node date = " << end_node->get_date() << endl;
  cout << "loop start node date = " << loop->getPatternStartTimeSync()->get_date()
       << endl;
  cout << "loop end node date = " << loop->getPatternEndTimeSync()->get_date() << endl;

  /*
     Execute
     */

  start_node->happen();

  // look at the console to see how things are repeated during the main interval duration
  while(main_interval->running())
    ;
}

void main_interval_callback(
    ossia::time_value position, ossia::time_value date, shared_ptr<StateElement> element)
{
  cout << "Main Constraint : " << double(position) << ", " << double(date) << endl;
}

void main_start_event_callback(TimeEvent::Status newStatus)
{
  print_event_status(newStatus, "Main Start");
}

void main_end_event_callback(TimeEvent::Status newStatus)
{
  print_event_status(newStatus, "Main End");
}

void loop_pattern_interval_callback(
    ossia::time_value position, ossia::time_value date, shared_ptr<StateElement> element)
{
  cout << "Loop Constraint : " << double(position) << ", " << double(date) << endl;
}

void loop_pattern_start_event_callback(TimeEvent::Status newStatus)
{
  print_event_status(newStatus, "Loop Pattern Start");
}

void loop_pattern_end_event_callback(TimeEvent::Status newStatus)
{
  print_event_status(newStatus, "Loop Pattern End");
}

void print_event_status(TimeEvent::Status newStatus, std::string name)
{
  switch(newStatus)
  {
    case TimeEvent::Status::NONE: {
      cout << name << " Event NONE" << endl;
      break;
    }
    case TimeEvent::Status::PENDING: {
      cout << name << " Event PENDING" << endl;
      break;
    }
    case TimeEvent::Status::HAPPENED: {
      cout << name << " Event HAPPENED" << endl;
      break;
    }
    case TimeEvent::Status::DISPOSED: {
      cout << name << " Event DISPOSED" << endl;
      break;
    }
  }
}
