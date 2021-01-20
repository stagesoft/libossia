#include <ossia/detail/any.hpp>
#include <ossia/editor/scenario/time_interval.hpp>
#include <ossia/editor/scenario/time_sync.hpp>
#include <ossia/editor/scenario/time_event.hpp>
#include <ossia/dataflow/nodes/automation.hpp>
#include <ossia/detail/hash_map.hpp>
#include <sstream>
#define private public
#include <ossia/dataflow/graph/graph_static.hpp>
#include <ossia/editor/scenario/scenario.hpp>
#include <valgrind/callgrind.h>
#include "../Editor/TestUtils.hpp"


static const constexpr int NUM_TAKES = 100;
static const constexpr auto NUM_CURVES = {1, 10, 20, 30, 40,
                                          50, 60, 70, 80, 90,
                                          100, 150, 200, 250,
                                          300, 400, 500
                                          , 600, 700, 800, 900, 1000};


int main()
{
  using namespace ossia;
  using namespace ossia::nodes;
  // Benchmark: how many automations can run at the same time
  // We need a graph


  for(int N : NUM_CURVES)
  {
    TestDevice t;
    tc_graph g;
    scenario s;
    g.add_node(s.node);

    auto sev = *s.get_start_time_sync()->emplace(s.get_start_time_sync()->get_time_events().end(), {}, {});
    for(int i = 0; i < N; i++)
    {
      std::shared_ptr<time_sync> tn = std::make_shared<time_sync>();
      s.add_time_sync(tn);
      auto ev = *tn->emplace(tn->get_time_events().end(), {}, {});

      auto tc = time_interval::create({}, *sev, *ev, 0_tv, 1000_tv, ossia::Infinite);
      s.add_time_interval(tc);
      g.add_node(tc->node);

      auto node = std::make_shared<ossia::nodes::automation>();
      auto autom = std::make_shared<ossia::nodes::automation_process>(node);
      node->root_outputs()[0]->address = t.all_params[std::abs(rand()) % t.all_params.size()];

      auto v = std::make_shared<ossia::curve<double, float>>();
      v->set_x0(0.); v->set_y0(0.);
      v->add_point(ossia::easing::ease{}, 1., 1.);
      node->set_behavior(v);

      tc->add_time_process(autom);
      g.add_node(node);
    }

    ossia::execution_state e;
    e.register_device(&t.device);
    ossia::time_value v{};
    s.start();
    int64_t count = 0;
    // run a first tick to init the graph

    e.clear_local_state();
    e.get_new_values();
    s.state(ossia::simple_token_request{0_tv, v});
    g.state(e);
    e.commit();

    for(int i = 0; i < NUM_TAKES; i++)
    {
      auto t0 = std::chrono::steady_clock::now();
      CALLGRIND_START_INSTRUMENTATION;
      e.clear_local_state();
      e.get_new_values();
      auto old_v = v > 0_tv ? v - 1_tv : 0_tv;
      s.state(ossia::simple_token_request{old_v, v});
      g.state(e);
      e.commit();
      CALLGRIND_STOP_INSTRUMENTATION;
      auto t1 = std::chrono::steady_clock::now();
      count += std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
      v = v + (int64_t)1;
    }

    std::cerr << N << " " << count / double(NUM_TAKES) << std::endl;
  }
  CALLGRIND_DUMP_STATS;
}
