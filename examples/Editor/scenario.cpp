//// This is an open source non-commercial project. Dear PVS-Studio, please check it.
//// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
///*!
// * \file scenario.cpp
// *
// * \author Théo de la Hogue
// *
// * This code is licensed under the terms of the "CeCILL-C"
// * http://www.cecill.info
// */

//#include <iostream>
//#include <memory>

//using namespace ossia;
//using namespace std;

//void local_play_callback(const value& v);
//void local_test_callback(const value& v);

//void main_interval_callback(double position, ossia::time_value date);
//void first_interval_callback(double position, ossia::time_value date);
//void second_interval_callback(double position, ossia::time_value date);
//void event_callback(time_event::status newStatus);

//ossia::clock* main_clock{};

int main()
{
  //    /*
  //     Network setup
  //     */

  //    // create a Local device "score"
  //    ossia::net::generic_device device{std::make_unique<ossia::net::multiplex_protocol>(), "score"};

  //    // add a /play address
  //    auto local_play_node = device.create_child("play");
  //    auto local_play_address = local_play_node->create_parameter(val_type::BOOL);

  //    // attach /play address to a callback
  //    local_play_address->add_callback(local_play_callback);

  //    // add a /test address
  //    auto local_test_node = device.create_child("test");
  //    auto local_test_address = local_test_node->create_parameter(val_type::LIST);

  //    // attach /test address to their callback
  //    local_test_address->add_callback(local_test_callback);

  //    // filter repetitions
  //    local_test_address->set_repetition_filter(repetition_filter::ON);

  //    /*
  //     Main scenario setup
  //     */

  //    // create the start and the end TimeSyncs
  //    auto main_start_node = std::make_shared<time_sync>();
  //    auto main_end_node = std::make_shared<time_sync>();

  //    // create time_events inside TimeSyncs and make them interactive to the /play address
  //    auto main_start_event = *(main_start_node->emplace(main_start_node->get_time_events().begin(), &event_callback));
  //    auto main_end_event = *(main_end_node->emplace(main_end_node->get_time_events().begin(), &event_callback));

  //    // create the main time_interval
  //    ossia::time_value main_duration(5000.);
  //    auto main_interval = std::make_shared<time_interval>(
  //                             main_interval_callback,
  //                             *main_start_event,
  //                             *main_end_event,
  //                             main_duration,
  //                             main_duration,
  //                             main_duration);

  //    // create the main scenario
  //    auto main_scenario_ptr = std::make_unique<scenario>();
  //    scenario* main_scenario = main_scenario_ptr.get();

  //    // add the scenario to the main time_interval
  //    main_interval->add_time_process(std::move(main_scenario_ptr));

  //    /*
  //     Main scenario edition : creation of a two time_intervals
  //     */

  //    // get the start node of the main scenario
  //    auto scenario_start_node = main_scenario->get_start_time_sync();

  //    // create a TimeSync
  //    auto first_end_node = std::make_shared<time_sync>();

  //    // create a time_event inside the scenario start node without Expression
  //    auto first_start_event = *(scenario_start_node->emplace(scenario_start_node->get_time_events().begin(), &event_callback));

  //    // create a time_event inside the end node without Expression
  //    auto first_end_event = *(first_end_node->emplace(first_end_node->get_time_events().begin(), &event_callback));

  //    // create a time_interval between the two time_events
  //    ossia::time_value first_duration(1500.);
  //    std::shared_ptr<time_interval> first_interval = std::make_shared<time_interval>(
  //                              first_interval_callback,
  //                              *first_start_event,
  //                              *first_end_event,
  //                              first_duration,
  //                              first_duration,
  //                              first_duration);

  //    // add the first time_interval to the main scenario
  //    main_scenario->add_time_interval(first_interval);

  //    // create a TimeSync
  //    auto second_end_node = std::make_shared<time_sync>();

  //    // create a time_event inside the end node without Expression
  //    auto second_end_event = *(second_end_node->emplace(second_end_node->get_time_events().begin(), &event_callback));

  //    // create a time_interval between the two time_events
  //    ossia::time_value second_duration(2000.);
  //    auto second_interval = std::make_shared<time_interval>(
  //                               second_interval_callback,
  //                               *first_end_event,
  //                               *second_end_event,
  //                               second_duration,
  //                               second_duration,
  //                               second_duration);

  //    // add the second time_interval to the main scenario
  //    main_scenario->add_time_interval(second_interval);

  //    /*
  //     Main scenario edition : make an event interactive
  //     */

  //    // create an expression : /score/test >= {0.7, 0.7, 0.7}
  //    auto make_expr = [&] () {
  //      return expressions::make_expression_atom(
  //        destination(*local_test_address),
  //        expressions::comparator::GREATER_EQUAL,
  //        std::vector<ossia::value>{0.7, 0.7, 0.7});
  //    };

  //    // set first end event expression to make it interactive
  //    first_end_event->set_expression(make_expr());

  //    /*
  //     Main scenario edition : creation of two Automations
  //     */

  //    // create a linear curve to drive all element of the Tuple value from 0. to 1.
  //    auto first_curve = std::make_shared<curve<double, float>>();
  //    curve_segment_linear<float> first_linearSegment;

  //    first_curve->set_x0(0.);
  //    first_curve->set_y0(0.);
  //    first_curve->add_point(first_linearSegment, 1., 1.);

  //    // create a power curve to drive all element of the Tuple value from 0. to 2.
  //    auto second_curve = std::make_shared<curve<double, float>>();
  //    auto second_powerSegment = curve_segment_power<float>{}(0.5);

  //    second_curve->set_y0(1.);
  //    second_curve->add_point(second_powerSegment, 1., 2.);

  //    // create a Tuple value of 3 behavior values based on the same curve
  //    std::vector<behavior> first_curves{(curve_ptr)first_curve, (curve_ptr)first_curve, (curve_ptr)first_curve};

  //    // create a Tuple value of 3 behavior values based on the same curve
  //    std::vector<behavior> second_curves{(curve_ptr)second_curve, (curve_ptr)second_curve, (curve_ptr)second_curve};

  //    // create a first Automation to drive /test address by the linear curve
  //    auto first_automation = std::make_unique<automation>(*local_test_address, first_curves);

  //    // create a second Automation to drive /test address by the power curve
  //    auto second_automation = std::make_unique<automation>(*local_test_address, second_curves);

  //    // add the first Automation to the first time_interval
  //    first_interval->add_time_process(std::move(first_automation));

  //    // add the second Automation to the second time_interval
  //    second_interval->add_time_process(std::move(second_automation));

  //    // add "/test 0. 0. 0." message to first time_interval's start State
  //    message first_start_message{*local_test_address, std::vector<ossia::value>{0., 0., 0.}};
  //    first_interval->get_start_event().add_state(first_start_message);

  //    // add "/test 1. 1. 1." message to first time_interval's end State
  //    message first_end_message{*local_test_address, std::vector<ossia::value>{1., 1., 1.}};
  //    first_interval->get_end_event().add_state(first_end_message);

  //    // add "/test 2. 2. 2." message to second time_interval's end State
  //    message second_end_message{*local_test_address, std::vector<ossia::value>{2., 2., 2.}};
  //    second_interval->get_start_event().add_state(second_end_message);

  //    /*
  //     Main scenario operation : miscellaneous
  //     */

  //    // display TimeSync's date
  //    cout << "first_start_node date = " << scenario_start_node->get_date() << endl;
  //    cout << "first_end_node date = " << first_end_node->get_date() << endl;
  //    cout << "second_end_node date = " << second_end_node->get_date() << endl;

  //    // change main time_interval speed, granularity and offset
  //    ossia::clock clk{*main_interval};
  //    main_clock = &clk;
  //    using namespace std::literals;

  //    clk.set_granularity(50ms);
  //    clk.set_duration(main_duration);
  //    main_interval->set_speed(1._tv);

  //    // set minimal duration of the first interval to 1000 ms
  //    first_interval->set_min_duration(1000._tv);

  //    // change first and second time_interval speed and granularity
  //    first_interval->set_speed(1._tv);
  //    second_interval->set_speed(1._tv);

  //    cout << "***** START *****" << endl;

  //    // play the main time_interval
  //    //local_play_address->pushvalue(&True);
  //    clk.start_and_tick();

  //    // wait the main time_interval end
  //    while (clk.running())
  //        ;

  //    cout << "***** END *****" << endl;

  //    // set minimal duration of the first interval to 500 ms
  //    first_interval->set_min_duration(750._tv);

  //    // set first end time sync expression to make it interactive
  //    // (instead of first end event)
  //    first_end_node->set_expression(make_expr());
  //    first_end_event->set_expression(expressions::make_expression_true());

  //    cout << "***** START *****" << endl;

  //    // play it again faster
  //    main_interval->set_speed(2._tv);

  //    // start at 500 ms (and launch the state at this time)
  //    ossia::launch(main_interval->offset(500._tv));

  //    local_play_address->push_value(true);

  //    // wait the main time_interval end
  //    while (clk.running())
  //        ;

  //    cout << "***** END *****" << endl;
  //}

  //void local_play_callback(const value& v)
  //{
  //    if (v.get_type() == val_type::BOOL)
  //    {
  //        auto b = v.get<bool>();
  //        if (b)
  //            main_clock->start_and_tick();
  //        else
  //            main_clock->stop();
  //    }
  //}

  //void local_test_callback(const value& v)
  //{
  //    cout << "/score/test = ";

  //    if (v.get_type() == val_type::LIST)
  //    {
  //      auto t = v.get<std::vector<ossia::value>>();

  //        for (auto e : t)
  //        {
  //            if (e.get_type() == val_type::FLOAT)
  //            {
  //                auto f = e.get<float>();
  //                cout << f << " ";
  //            }
  //        }
  //    }

  //    cout << endl;
  //}

  //void main_interval_callback(double position, ossia::time_value date)
  //{
  //    cout << "Main Constraint : " << double(position) << ", " << double(date) << endl;
  //}

  //void first_interval_callback(double position, ossia::time_value date)
  //{
  //    cout << "First Constraint : " << double(position) << ", " << double(date) << endl;

  //    // don't launch element here as the element produced by the first time_interval is handled by the main time_interval
  //}

  //void second_interval_callback(double position, ossia::time_value date)
  //{
  //    cout << "Second Constraint : " << double(position) << ", " << double(date) << endl;

  //    // don't launch element here as the element produced by the second time_interval is handled by the main time_interval
  //}

  //void event_callback(time_event::status newStatus)
  //{
  //    switch (newStatus)
  //    {
  //        case time_event::status::NONE:
  //        {
  //            cout << "Event NONE" << endl;
  //            break;
  //        }
  //        case time_event::status::PENDING:
  //        {
  //            cout << "Event PENDING" << endl;
  //            break;
  //        }
  //        case time_event::status::HAPPENED:
  //        {
  //            cout << "Event HAPPENED" << endl;
  //            break;
  //        }
  //        case time_event::status::DISPOSED:
  //        {
  //            cout << "Event DISPOSED" << endl;
  //            break;
  //        }
  //    }
}
