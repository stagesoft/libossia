// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#define CATCH_CONFIG_MAIN
#include <catch.hpp>
#include <ossia/detail/config.hpp>

#include <functional>
#include <iostream>
#include <ossia/audio/audio_parameter.hpp>
#include <ossia/dataflow/node_process.hpp>
#include <ossia/dataflow/graph/graph_static.hpp>
#include <ossia/dataflow/nodes/sound_ref.hpp>
#include <ossia/editor/loop/loop.hpp>
#include <ossia/editor/scenario/scenario.hpp>
#include <ossia/network/generic/generic_device.hpp>
#include <ossia/editor/scenario/clock.hpp>
#include <ossia/detail/pod_vector.hpp>
#include <ossia/editor/expression/expression.hpp>
#include <ossia/editor/expression/expression_generic.hpp>
#include "TestUtils.hpp"

struct expression_generic_test final
    : ossia::expressions::expression_generic_base
{
  expression_generic_test(bool& the_b): b{the_b} { }
  bool& b;

  void update() { }
  bool evaluate() const { return b; }
  void on_first_callback_added(ossia::expressions::expression_generic&) { }
  void on_removing_last_callback(ossia::expressions::expression_generic&) { }
};

auto make_expression_test(bool& b)
{
  return ossia::expressions::make_expression_generic<expression_generic_test>(b);
}

namespace ossia
{

struct test_loop
{
  ossia::net::generic_device d;
  ossia::tc_graph g;
  ossia::loop parent;

  ossia::audio_parameter* aparam{};
  ossia::nodes::sound_ref* snd1{};
  ossia::nodes::sound_ref* snd2{};
  ~test_loop()
  {
    g.clear();
  }

  test_loop()
    : parent{7_tv, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{}}
  {
    /// this creates :
    /// A root loop ("parent")
    /// With an interval (duration 7) which has a scenario:
    /// [ ---- i1 (4) ---- ] | [ ---- i2 (3) ---- ]
    /// [     loop (1)     ]   [    loop (2)      ]
    /// [ sound {1,2,3,4}  ]   [ sound {5,6,7,8}  ]
    auto& root = d.get_root_node();
    auto foo = root.create_child("foo");
    aparam = new audio_parameter{*foo};
    auto param = std::unique_ptr<ossia::net::parameter_base>{aparam};
    foo->set_parameter(std::move(param));

    parent.node->root_outputs()[0]->address = foo->get_parameter();
    auto scenar = std::make_shared<scenario>();
    parent.get_time_interval().add_time_process(scenar);

    auto ts0 = scenar->get_start_time_sync(); auto e0 = ts0->emplace(ts0->get_time_events().begin(), {});
    auto ts1 = std::make_shared<ossia::time_sync>(); scenar->add_time_sync(ts1); auto e1 = ts1->emplace(ts1->get_time_events().begin(), {});
    auto ts2 = std::make_shared<ossia::time_sync>(); scenar->add_time_sync(ts2); auto e2 = ts2->emplace(ts2->get_time_events().begin(), {});
    auto i1 = time_interval::create({}, **e0, **e1, 4_tv, 4_tv, 4_tv); scenar->add_time_interval(i1);
    auto i2 = time_interval::create({}, **e1, **e2, 3_tv, 3_tv, 3_tv); scenar->add_time_interval(i2);

    g.add_node(parent.node);
    g.add_node(scenar->node);
    g.add_node(i1->node);
    g.add_node(i2->node);

    {
      auto child = std::make_shared<loop>(1_tv, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{});

      auto snd = std::make_shared<ossia::nodes::sound_ref>(); snd1 = snd.get();
      snd->set_sound(std::vector<ossia::float_vector>{ {1., 2., 3., 4.} });
      child->get_time_interval().add_time_process(std::make_shared<ossia::node_process>(snd));
      i1->add_time_process(child);

      g.add_node(snd);
      g.connect(ossia::make_edge(ossia::immediate_glutton_connection{}, snd->root_outputs()[0], parent.node->root_inputs()[0], snd, parent.node));
    }

    {
      auto child = std::make_shared<loop>(2_tv, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{});

      auto snd = std::make_shared<ossia::nodes::sound_ref>(); snd2 = snd.get();
      snd->set_sound(std::vector<ossia::float_vector>{ {5.,6.,7.,8.} });
      child->get_time_interval().add_time_process(std::make_shared<ossia::node_process>(snd));
      i2->add_time_process(child);

      g.add_node(snd);
      g.connect(ossia::make_edge(ossia::immediate_glutton_connection{}, snd->root_outputs()[0], parent.node->root_inputs()[0], snd, parent.node));
    }

  }
};

}
using namespace ossia;

static void event_callback(time_event::status newStatus)
{
}

/*! test life cycle and accessors functions */
TEST_CASE ("test_basic", "test_basic")
{
  //using namespace std::placeholders;
  loop l(25._tv, ossia::time_interval::exec_callback{[] (auto&&... args) { }}, event_callback, event_callback);

  //! \todo test clone()
}

/*! test execution functions */
//! \todo test state()
TEST_CASE ("test_execution", "test_execution")
{
  auto start_node = std::make_shared<time_sync>();
  auto end_node = std::make_shared<time_sync>();

  auto start_event = *(start_node->emplace(start_node->get_time_events().begin(), event_callback));
  auto end_event = *(end_node->emplace(end_node->get_time_events().begin(), event_callback));

  auto interval = time_interval::create({}, *start_event, *end_event, 500._tv, 500._tv, 500._tv);

  ossia::clock c{*interval};
  c.set_granularity(std::chrono::milliseconds(20));
  interval->add_time_process(
        std::make_unique<loop>(25._tv, ossia::time_interval::exec_callback{}, event_callback, event_callback));

  c.start_and_tick();

  while (c.running())
    ;
}

TEST_CASE ("test_inf", "test_inf")
{
  REQUIRE_THROWS([] {
    loop l{0_tv, time_interval::exec_callback{}, time_event::exec_callback{},
           time_event::exec_callback{}};
    l.start();
    l.state(simple_token_request{0_tv, 1_tv});
  }());
}


TEST_CASE ("test_inf_trigger", "test_inf_trigger")
{
  using namespace ossia::expressions;

  loop l{ossia::Infinite, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{}};
  bool b = false;

  l.get_time_interval().set_min_duration(0_tv);
  l.get_time_interval().set_max_duration(ossia::Infinite);
  l.get_time_interval().set_nominal_duration(0_tv);
  l.get_end_timesync().set_expression(::make_expression_test(b));

  l.start();
  l.state(simple_token_request{0_tv, 10_tv});
  REQUIRE(l.get_time_interval().get_date() == 10_tv);
  l.state(simple_token_request{10_tv, 20_tv});
  REQUIRE(l.get_time_interval().get_date() == 20_tv);
  b = true;
  l.state(simple_token_request{20_tv, 25_tv});
  REQUIRE(l.get_time_interval().get_date() == 0_tv);
  b = false;
  l.state(simple_token_request{25_tv, 30_tv});
  REQUIRE(l.get_time_interval().get_date() == 5_tv);

}


TEST_CASE ("test_loop_sound", "test_loop_sound")
{
  {
    loop l{4_tv, time_interval::exec_callback{}, time_event::exec_callback{},
           time_event::exec_callback{}};
    auto snd = std::make_shared<ossia::nodes::sound_ref>();
    snd->set_sound(std::vector<ossia::float_vector>{ {0.1, 0.2, 0.3, 0.4} });
    l.get_time_interval().add_time_process(std::make_shared<ossia::node_process>(snd));

    l.start();
    l.state(simple_token_request{0_tv, 1_tv});
    REQUIRE((int)snd->requested_tokens.size() == (int)2);
    REQUIRE((snd->requested_tokens[0] == simple_token_request{0_tv, 0_tv}));
    REQUIRE((snd->requested_tokens[1] == simple_token_request{0_tv, 1_tv}));
    l.stop();
  }

  {
    loop l{4_tv, time_interval::exec_callback{}, time_event::exec_callback{},
           time_event::exec_callback{}};
    auto snd = std::make_shared<ossia::nodes::sound_ref>();
    snd->set_sound(std::vector<ossia::float_vector>{ {0.1, 0.2, 0.3, 0.4} });
    l.get_time_interval().add_time_process(std::make_shared<ossia::node_process>(snd));

    l.start();
    l.state(simple_token_request{0_tv, 5_tv});
    REQUIRE((int)snd->requested_tokens.size() == (int)4);
    REQUIRE(snd->requested_tokens[0] == simple_token_request{0_tv, 0_tv, 0_tv});
    REQUIRE(snd->requested_tokens[1] == simple_token_request{0_tv, 4_tv, 0_tv});
    REQUIRE(snd->requested_tokens[2] == simple_token_request{0_tv, 0_tv, 4_tv});
    REQUIRE(snd->requested_tokens[3] == simple_token_request{0_tv, 1_tv, 4_tv});
    l.stop();
  }

  {
    loop l{4_tv, time_interval::exec_callback{}, time_event::exec_callback{},
           time_event::exec_callback{}};
    auto snd = std::make_shared<ossia::nodes::sound_ref>();
    snd->set_sound(std::vector<ossia::float_vector>{ {0.1, 0.2, 0.3, 0.4} });
    l.get_time_interval().add_time_process(std::make_shared<ossia::node_process>(snd));

    l.start();
    l.state(simple_token_request{0_tv, 9_tv});
    ossia::execution_state e;
    e.bufferSize = 9;

    for(auto tk : snd->requested_tokens)
      ((ossia::graph_node*)snd.get())->run(tk, {e});
    auto op = snd->root_outputs()[0]->target<audio_port>()->samples;
    audio_vector expected{audio_channel{0.1f, 0.2f, 0.3f, 0.4f, 0.1f, 0.2f, 0.3f, 0.4f, 0.1f}};
    for(int i = 0; i < 9; i++)
    {
      REQUIRE(expected[0][i] - op[0][i] < 0.00001);
    }
    REQUIRE(op == expected);
  }
  {
    /*
        l.state(2_tv, 0, 0_tv);
        std::cerr << snd->requested_tokens[1];
        REQUIRE((snd->requested_tokens[1] == token_request{1_tv, 0, 1_tv}));
        l.state(3_tv, 0, 0_tv);
        REQUIRE((snd->requested_tokens[2] == token_request{1_tv, 0, 2_tv}));
        l.state(4_tv, 0, 0_tv);
        REQUIRE((snd->requested_tokens[3] == token_request{1_tv, 0, 3_tv}));
        l.state(5_tv, 0, 0_tv);
        REQUIRE((snd->requested_tokens[4] == token_request{1_tv, 0, 4_tv}));
        l.state(6_tv, 0, 0_tv);
        REQUIRE((snd->requested_tokens[5] == token_request{1_tv, 0, 5_tv}));
        */
  }

}

TEST_CASE ("test_subloop", "test_subloop")
{
  loop parent{7_tv, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{}};
  auto child = std::make_shared<loop>(3_tv, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{});
  parent.get_time_interval().add_time_process(child);

  auto snd = std::make_shared<ossia::nodes::sound_ref>();
  snd->set_sound(std::vector<ossia::float_vector>{ {0.1, 0.2, 0.3, 0.4} });
  child->get_time_interval().add_time_process(std::make_shared<ossia::node_process>(snd));

  parent.start();
  parent.state(simple_token_request{0_tv, 14_tv});

  ossia::execution_state e;
  e.bufferSize = 14;
  for(auto tk : snd->requested_tokens)
    ((ossia::graph_node*)snd.get())->run(tk, {e});


  audio_vector expected{audio_channel{0.1, 0.2, 0.3, 0.1, 0.2, 0.3, 0.1, 0.1, 0.2, 0.3, 0.1, 0.2, 0.3, 0.1}};

  auto op = snd->root_outputs()[0]->target<audio_port>()->samples;

  for(int i = 0; i < 14; i++)
  {
    REQUIRE(expected[0][i] - op[0][i] < 0.00001);
  }
}


TEST_CASE ("test_subloops_in_scenario", "test_subloops_in_scenario")
{
  test_loop l;
  l.parent.start();
  l.parent.state(simple_token_request{0_tv, 14_tv});

  audio_vector expected{ossia::audio_channel{1., 1., 1., 1., 5., 6., 5., 1., 1., 1., 1., 5., 6., 5.}};

  std::vector<float> res(64, 0.);
  l.aparam->audio.resize(1);
  l.aparam->audio[0] = {res.data(), res.size()};
  ossia::execution_state e;
  e.bufferSize = 14;
  l.g.state(e);
  e.commit();

  REQUIRE(e.m_audioState.size() > 0);
  auto op = l.aparam->audio;

  REQUIRE(op.size() > 0);
  auto chan = op[0];

  REQUIRE(op[0].size() >= 14);

  // Problème :  dans sound_ref on écrit
  // auto samples_to_write = std::abs(e.bufferSize() - t.offset);
  // mais si on ne tick que 3 tv, on voudrait en sortie n'avoir que ce qui correspond à ces 3 tv.
  // mais : si speed == 0.5 -> on n'a qu 1.5 tv
  // -> il faut multiplier par 1/speed

  for(int i = 0; i < 14; i++)
  {
    REQUIRE(chan[i] - expected[0][i] < 0.000001);
  }
  for(int i = 14; i < chan.size(); i++)
  {
    REQUIRE(0.f == chan[i]);
  }
}

TEST_CASE ("test_subloops_in_scenario_1by1", "test_subloops_in_scenario_1by1")
{
  test_loop l;

  float audio_data[2][64] {{}};
  l.parent.start();
  ossia::execution_state e;
  e.register_device(&l.d);
  for(int64_t i = 1; i <= 14; i++) {

    float* chan = audio_data[0] + i - 1 ;
    l.aparam->audio = {{chan, (std::size_t)(64 - i)}};
    l.parent.state(simple_token_request{ossia::time_value{i - 1}, ossia::time_value{i}});
    e.begin_tick();
    l.g.state(e);
    e.commit();
  }


  audio_vector expected{ossia::audio_channel{1., 1., 1., 1., 5., 6., 5., 1., 1., 1., 1., 5., 6., 5.}};

  for(int i = 0; i < 14; i++)
  {
    REQUIRE( audio_data[0][i] == expected[0][i]);
  }
}



TEST_CASE ("test_musical_bar", "test_musical_bar")
{
  using namespace ossia;

  loop l{ossia::Infinite, time_interval::exec_callback{}, time_event::exec_callback{}, time_event::exec_callback{}};

  auto& c = l.get_time_interval();
  c.set_min_duration(0_tv);
  c.set_nominal_duration(1234_tv);
  c.set_max_duration(ossia::Infinite);
  auto& t1 = l.get_end_timesync();

  bool b = false;
  t1.set_expression(::make_expression_test(b));
  // assume sampling rate is 44100 -> a quarter note is 22050
  t1.set_sync_rate(1, 22050);

  c.add_time_process(dummy_process());

  l.start();
  // Tick a bit ; nothing happens
  {
    l.state(simple_token_request{0_tv, 1000_tv});

    auto& req = c.node->requested_tokens;

    // TODO why isn't there a tick for the (0,0) case

    REQUIRE((int)req.size() == (int)1);
    REQUIRE((req[0] == simple_token_request{0_tv, 1000_tv}));
    req.clear();
  }

  // Expression becomes true, still nothing :
  b = true;

  {
    l.state(simple_token_request{1000_tv, 2000_tv});

    auto& req = c.node->requested_tokens;

    REQUIRE((int)req.size() == (int)1); // TODO sometimes this becomes 1 ?!
    std::cerr << req[0] << "\n" << req[1] << "\n" << std::endl;
    REQUIRE((req[0] == simple_token_request{1000_tv, 2000_tv}));

    req.clear();
  }


  // Tick enough to go past the quantification ratio
  {
    ossia::token_request tk;
    tk.prev_date = 2000_tv;
    tk.date = 100000_tv;
    tk.parent_duration = 100000_tv;
    tk.offset = 0_tv;
    tk.tempo = 120;
    tk.speed = 1.;
    tk.musical_start_last_bar = 0.;
    tk.musical_end_last_bar = 4.;
    tk.musical_start_position = 2000. / 22050.;
    tk.musical_end_position = 100000. / 22050.;
    tk.signature = {4, 4};

    l.state(tk);

    auto& req = c.node->requested_tokens;

    std::cout << std::endl;
    std::cerr << std::endl;
    std::cerr << "Requests: \n"
              <<  req
              << std::endl;

    REQUIRE((int)req.size() == (int)2);

    REQUIRE(req[0] == simple_token_request{2000_tv, 88199_tv});
    REQUIRE(req[1] == simple_token_request{0_tv, 100000_tv - 88200_tv + 1_tv});

    REQUIRE(c.get_date() == 11801_tv);

    req.clear();
  }

  // Tick a bit again
  {
    l.state(simple_token_request{100000_tv, 102000_tv});

    auto& req = c.node->requested_tokens;

    REQUIRE((int)req.size() == (int)1);
    REQUIRE((req[0] == simple_token_request{11801_tv, 13801_tv}));

    req.clear();
  }

  // And again enough to go past the quantification ratio

  {
    ossia::token_request tk;
    tk.prev_date = 102000_tv;
    tk.date = 200000_tv;
    tk.parent_duration = 100000_tv;
    tk.offset = 0_tv;
    tk.tempo = 120;
    tk.speed = 1.;
    tk.musical_start_last_bar = 4.;
    tk.musical_end_last_bar = 8.;
    tk.musical_start_position = 102000. / 22050.;
    tk.musical_end_position = 200000. / 22050.;
    tk.signature = {4, 4};

    l.state(tk);

    auto& req = c.node->requested_tokens;

    std::cout << std::endl;
    std::cerr << std::endl;
    std::cerr << "Requests: \n"
              <<  req
              << std::endl;

    REQUIRE((int)req.size() == (int)2);

    REQUIRE(req[0] == simple_token_request{13801_tv, 88199_tv});
    REQUIRE(req[1] == simple_token_request{0_tv, 98000_tv - (88199_tv - 13801_tv) + 1_tv});

    REQUIRE(c.get_date() == 11801_tv);

    req.clear();
  }

}
