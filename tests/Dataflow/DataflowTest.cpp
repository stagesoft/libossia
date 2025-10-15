// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "../Editor/TestUtils.hpp"
#include "../Network/TestUtils.hpp"

#include <ossia/detail/config.hpp>

#include <ossia/dataflow/graph/graph.hpp>
#include <ossia/dataflow/graph/graph_static.hpp>
#include <ossia/network/base/parameter.hpp>

#include "include_catch.hpp"

namespace ossia
{
class node_mock final : public graph_node
{

public:
  const char* lbl{};
  std::string label() const noexcept override { return lbl; }

  node_mock(inlets in, outlets out)
  {
    m_inlets = std::move(in);
    m_outlets = std::move(out);
  }

  std::function<void(token_request t, exec_state_facade e)> fun;
  void run(const token_request& t, exec_state_facade e) noexcept override
  {
    if(fun)
      fun(t, e);
  }

  void set_enabled(bool b)
  {
    if(b)
    {
      request({});
    }
    else
    {
      disable();
    }
  }
};

template <typename T>
auto pop_front(std::vector<T>& vec)
{
  if(!vec.empty())
  {
    auto val = vec.front();
    vec.erase(vec.begin());
    return val;
  }
  else
  {
    throw std::runtime_error("invalid pop");
  }
}

template <typename T, std::size_t N>
auto pop_front(ossia::small_vector<T, N>& vec)
{
  if(!vec.empty())
  {
    auto val = vec.front();
    vec.erase(vec.begin());
    return val;
  }
  else
  {
    throw std::runtime_error("invalid pop");
  }
}

auto pop_front(ossia::value_vector<ossia::timed_value> container)
{
  if(container.size() > 0)
  {
    auto val = container.front();
    auto it = container.begin();
    container.erase(it);
    return val;
  }
  else
  {
    throw std::runtime_error("invalid pop");
  }
}

struct debug_mock
{
  debug_mock(int f, std::weak_ptr<node_mock> p)
      : factor{f}
      , node{p}
  {
  }
  const int factor = 1;
  std::weak_ptr<node_mock> node;
  void operator()(ossia::token_request tk, ossia::exec_state_facade)
  {
    if(auto n = node.lock())
    {
      messages.emplace_back(factor, tk.date.impl);
    }
  }
  static std::vector<std::pair<int, int>> messages;
};
std::vector<std::pair<int, int>> debug_mock::messages;
struct execution_mock
{
  execution_mock(int f, std::weak_ptr<node_mock> p)
      : factor{f}
      , node{p}
  {
  }
  const int factor = 1;
  std::weak_ptr<node_mock> node;
  void operator()(ossia::token_request tk, ossia::exec_state_facade)
  {
    if(auto n = node.lock())
    {
      auto& in_port = *n->root_inputs()[0]->target<value_port>();
      auto& out_port = *n->root_outputs()[0]->target<value_port>();

      ossia::timed_value elt = in_port.get_data().front();
      if(auto val = elt.value.target<std::vector<ossia::value>>())
      {
        auto v = *val;
        v.push_back(ossia::value{int32_t(factor * (1 + tk.date.impl))});
        out_port.write_value(std::move(v), 0);
      }
    }
  }
};

}

struct base_graph
{
  std::unique_ptr<ossia::tc_graph> gg = std::make_unique<ossia::tc_graph>();
  ossia::tc_graph& g = *gg;
  ossia::execution_state e;

  base_graph(ossia::TestDevice& test) { e.register_device(&test.device); }

  void state()
  {
    e.begin_tick();
    g.state(e);
    e.commit();
  }
};
struct simple_explicit_graph : base_graph
{
  ossia::node_mock *n1, *n2;
  simple_explicit_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;
    auto n1_in = new value_inlet(*test.tuple_addr);
    auto n1_out = new value_outlet(*test.tuple_addr);
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1";

    auto n2_in = new value_inlet(*test.tuple_addr);
    auto n2_out = new value_outlet(*test.tuple_addr);
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n2->lbl = "n2";

    g.add_node(n1);
    g.add_node(n2);
    g.connect(g.allocate_edge(c, n1_out, n2_in, n1, n2));

    this->n1 = n1.get();
    this->n2 = n2.get();
  }
};

struct simple_implicit_graph : base_graph
{
  ossia::node_mock *n1, *n2;
  simple_implicit_graph(ossia::TestDevice& test)
      : base_graph{test}
  {
    using namespace ossia;
    auto n1_in = new value_inlet(*test.tuple_addr);
    auto n1_out = new value_outlet(*test.tuple_addr);
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1";

    auto n2_in = new value_inlet(*test.tuple_addr);
    auto n2_out = new value_outlet(*test.tuple_addr);
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n2->lbl = "n2";

    g.add_node(n1);
    g.add_node(n2);

    g.connect(g.allocate_edge(
        ossia::dependency_connection{}, outlet_ptr{}, inlet_ptr{}, n1, n2));

    this->n1 = n1.get();
    this->n2 = n2.get();
  }
};

struct no_parameter_explicit_graph : base_graph
{
  ossia::node_mock *n1, *n2;
  no_parameter_explicit_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;
    auto n1_out = new value_outlet;
    auto n1 = std::make_shared<node_mock>(inlets{}, outlets{n1_out});
    n1->fun = debug_mock{1, n1};
    n1->lbl = "n1";

    auto n2_in = new value_inlet;
    auto n2_out = new value_outlet;
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = debug_mock{10, n2};
    n2->lbl = "n2";

    g.add_node(n1);
    g.add_node(n2);
    g.connect(g.allocate_edge(c, n1_out, n2_in, n1, n2));

    this->n1 = n1.get();
    this->n2 = n2.get();
  }
};

struct three_outputs_one_input_explicit_graph : base_graph
{
  ossia::node_mock *n1, *n2, *n3, *nin;
  three_outputs_one_input_explicit_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;

    auto n1_in = new value_inlet(*test.tuple_addr);
    auto n1_out = new value_outlet;
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1";

    auto n2_in = new value_inlet(*test.tuple_addr);
    auto n2_out = new value_outlet;
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n2->lbl = "n2";

    auto n3_in = new value_inlet(*test.tuple_addr);
    auto n3_out = new value_outlet;
    auto n3 = std::make_shared<node_mock>(inlets{n3_in}, outlets{n3_out});
    n3->fun = execution_mock{100, n3};
    n3->lbl = "n3";

    auto nin_in = new value_inlet;
    auto nin_out = new value_outlet(*test.tuple_addr);
    auto nin = std::make_shared<node_mock>(inlets{nin_in}, outlets{nin_out});
    nin->fun = execution_mock{1000, nin};
    nin->lbl = "nin";

    g.add_node(n1);
    g.add_node(n2);
    g.add_node(n3);
    g.add_node(nin);

    g.connect(g.allocate_edge(c, n1_out, nin_in, n1, nin));
    g.connect(g.allocate_edge(c, n2_out, nin_in, n2, nin));
    g.connect(g.allocate_edge(c, n3_out, nin_in, n3, nin));

    g.connect(
        g.allocate_edge(dependency_connection{}, outlet_ptr{}, inlet_ptr{}, n1, n2));
    g.connect(
        g.allocate_edge(dependency_connection{}, outlet_ptr{}, inlet_ptr{}, n2, n3));

    this->n1 = n1.get();
    this->n2 = n2.get();
    this->n3 = n3.get();
    this->nin = nin.get();
  }
};

struct three_serial_nodes_explicit_graph : base_graph
{
  ossia::node_mock *n1, *n2, *n3;
  three_serial_nodes_explicit_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;

    auto n1_in = new value_inlet(*test.tuple_addr);
    auto n1_out = new value_outlet;
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1";

    auto n2_in = new value_inlet;
    auto n2_out = new value_outlet;
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n2->lbl = "n2";

    auto n3_in = new value_inlet;
    auto n3_out = new value_outlet(*test.tuple_addr);
    auto n3 = std::make_shared<node_mock>(inlets{n3_in}, outlets{n3_out});
    n3->fun = execution_mock{100, n3};
    n3->lbl = "n3";

    g.add_node(n1);
    g.add_node(n2);
    g.add_node(n3);

    g.connect(g.allocate_edge(c, n1_out, n2_in, n1, n2));
    g.connect(g.allocate_edge(c, n2_out, n3_in, n2, n3));

    this->n1 = n1.get();
    this->n2 = n2.get();
    this->n3 = n3.get();
  }
};

struct three_serial_nodes_implicit_graph : base_graph
{
  ossia::node_mock *n1, *n2, *n3;
  three_serial_nodes_implicit_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;

    auto n1_in = new value_inlet(*test.tuple_addr);
    auto n1_out = new value_outlet(*test.tuple_addr);
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1";

    auto n2_in = new value_inlet(*test.tuple_addr);
    auto n2_out = new value_outlet(*test.tuple_addr);
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n2->lbl = "n2";

    auto n3_in = new value_inlet(*test.tuple_addr);
    auto n3_out = new value_outlet(*test.tuple_addr);
    auto n3 = std::make_shared<node_mock>(inlets{n3_in}, outlets{n3_out});
    n3->fun = execution_mock{100, n3};
    n3->lbl = "n3";

    g.add_node(n1);
    g.add_node(n2);
    g.add_node(n3);

    this->n1 = n1.get();
    this->n2 = n2.get();
    this->n3 = n3.get();
  }
};
struct ab_bc_graph : base_graph
{
  ossia::node_mock *n1, *n2;
  ab_bc_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;

    auto n1_in = new value_inlet(*test.a);
    auto n1_out = new value_outlet(*test.b);
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1 (a->b)";

    auto n2_in = new value_inlet(*test.b);
    auto n2_out = new value_outlet(*test.c);
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n1->lbl = "n2 (b->c)";

    g.add_node(n1);
    g.add_node(n2);

    this->n1 = n1.get();
    this->n2 = n2.get();
  }
};

struct bc_ab_graph : base_graph
{
  ossia::node_mock *n1, *n2;
  bc_ab_graph(ossia::TestDevice& test, ossia::connection c)
      : base_graph{test}
  {
    using namespace ossia;

    auto n1_in = new value_inlet(*test.b);
    auto n1_out = new value_outlet(*test.c);
    auto n1 = std::make_shared<node_mock>(inlets{n1_in}, outlets{n1_out});
    n1->fun = execution_mock{1, n1};
    n1->lbl = "n1 (b->c)";

    auto n2_in = new value_inlet(*test.a);
    auto n2_out = new value_outlet(*test.b);
    auto n2 = std::make_shared<node_mock>(inlets{n2_in}, outlets{n2_out});
    n2->fun = execution_mock{10, n2};
    n2->lbl = "n2 (a->b)";

    g.add_node(n1);
    g.add_node(n2);

    this->n1 = n1.get();
    this->n2 = n2.get();
  }
};

TEST_CASE("test_bfs", "test_bfs")
{
  using namespace ossia;
  auto gg = std::make_unique<bfs_graph>();
  auto& g = *gg;
  auto n1 = boost::add_vertex({}, g.impl());
  auto n2 = boost::add_vertex({}, g.impl());
  auto n3 = boost::add_vertex({}, g.impl());

  boost::add_edge(n1, n2, g.impl());
  boost::add_edge(n2, n3, g.impl());

  REQUIRE(g.update_fun.find_path(n1, n3, g.impl()));
}
TEST_CASE("test_bfs_addr", "test_bfs_addr")
{
  using namespace ossia;

  TestDevice test;

  auto gg = std::make_unique<bfs_graph>();
  auto& g = *gg;
  auto n1 = std::make_shared<node_mock>(
      ossia::inlets{new value_inlet(*test.a)},
      ossia::outlets{new value_outlet(*test.b)});
  auto n2 = std::make_shared<node_mock>(
      ossia::inlets{new value_inlet(*test.b)},
      ossia::outlets{new value_outlet(*test.c)});
  auto n3 = std::make_shared<node_mock>(
      ossia::inlets{new value_inlet(*test.c)},
      ossia::outlets{new value_outlet(*test.a)});

  g.add_node(n1);
  g.add_node(n2);
  g.add_node(n3);

  g.update_fun(g, std::vector<ossia::net::device_base*>{&test.device});
}
TEST_CASE("test_tcl_addr", "test_tcl_addr")
{
  using namespace ossia;

  TestDevice test;

  auto gg = std::make_unique<tc_graph>();
  auto& g = *gg;
  auto n1 = std::make_shared<node_mock>(
      ossia::inlets{new value_inlet(*test.a)},
      ossia::outlets{new value_outlet(*test.b)});
  auto n2 = std::make_shared<node_mock>(
      ossia::inlets{new value_inlet(*test.b)},
      ossia::outlets{new value_outlet(*test.c)});
  auto n3 = std::make_shared<node_mock>(
      ossia::inlets{new value_inlet(*test.c)},
      ossia::outlets{new value_outlet(*test.a)});

  g.add_node(n1);
  g.add_node(n2);
  g.add_node(n3);

  g.update_fun(g, std::vector<ossia::net::device_base*>{&test.device});
}

TEST_CASE("test_mock", "test_mock")
{
  using namespace ossia;
  auto gg = std::make_unique<graph>();
  auto& g = *gg;

  auto n1
      = std::make_shared<node_mock>(inlets{new value_inlet}, outlets{new value_outlet});
  auto n2
      = std::make_shared<node_mock>(inlets{new value_inlet}, outlets{new value_outlet});
  auto n3
      = std::make_shared<node_mock>(inlets{new value_inlet}, outlets{new value_outlet});
  auto n4 = std::make_shared<node_mock>(
      inlets{new value_inlet, new value_inlet},
      outlets{new value_outlet, new value_outlet});
  auto n5 = std::make_shared<node_mock>(
      inlets{new value_inlet, new value_inlet},
      outlets{new value_outlet, new value_outlet});

  g.add_node(n1);
  g.add_node(n2);
  g.add_node(n3);
  g.add_node(n4);
  g.add_node(n5);

  auto c1 = g.allocate_edge(
      connection{immediate_glutton_connection{}}, n1->root_outputs()[0],
      n2->root_inputs()[0], n1, n2);
  auto c2 = g.allocate_edge(
      connection{immediate_glutton_connection{}}, n1->root_outputs()[0],
      n3->root_inputs()[0], n1, n3);
  auto c3 = g.allocate_edge(
      connection{immediate_glutton_connection{}}, n2->root_outputs()[0],
      n4->root_inputs()[0], n2, n4);
  auto c4 = g.allocate_edge(
      connection{immediate_glutton_connection{}}, n3->root_outputs()[0],
      n4->root_inputs()[1], n3, n4);

  auto c5 = g.allocate_edge(
      connection{immediate_glutton_connection{}}, n4->root_outputs()[0],
      n5->root_inputs()[0], n4, n5);
  auto c6 = g.allocate_edge(
      connection{immediate_glutton_connection{}}, n4->root_outputs()[1],
      n5->root_inputs()[1], n4, n5);

  g.connect(c1);
  g.connect(c2);
  g.connect(c3);
  g.connect(c4);
  g.connect(c5);
  g.connect(c6);

  REQUIRE(n1->root_outputs()[0]->targets[0]);
  REQUIRE(n1->root_outputs()[0]->targets[0]->in_node == std::shared_ptr<graph_node>(n2));
  REQUIRE(n1->root_outputs()[0]->targets[0]->in == n2->root_inputs()[0]);
  REQUIRE(
      n1->root_outputs()[0]->targets[0]->out_node == std::shared_ptr<graph_node>(n1));
  REQUIRE(n1->root_outputs()[0]->targets[0]->out == n1->root_outputs()[0]);

  REQUIRE(n2->root_inputs()[0]->sources[0]);
  REQUIRE(n2->root_inputs()[0]->sources[0]->in_node == std::shared_ptr<graph_node>(n2));
  REQUIRE(n2->root_inputs()[0]->sources[0]->in == n2->root_inputs()[0]);
  REQUIRE(n2->root_inputs()[0]->sources[0]->out_node == std::shared_ptr<graph_node>(n1));
  REQUIRE(n2->root_inputs()[0]->sources[0]->out == n1->root_outputs()[0]);
}

TEST_CASE("test_disable_strict_nodes", "test_disable_strict_nodes")
{
  using namespace ossia;
  auto gg = std::make_unique<graph>();
  auto& g = *gg;
  auto disable_nodes = [&](std::vector<std::shared_ptr<node_mock>> nodes) {
    node_flat_set enabled, disabled;
    for(auto node : nodes)
      if(node->enabled())
        enabled.insert(node.get());
    g.disable_strict_nodes(enabled, disabled);
    return disabled;
  };

  auto n1
      = std::make_shared<node_mock>(inlets{new value_inlet}, outlets{new value_outlet});
  auto n2
      = std::make_shared<node_mock>(inlets{new value_inlet}, outlets{new value_outlet});
  auto n3
      = std::make_shared<node_mock>(inlets{new value_inlet}, outlets{new value_outlet});
  auto n4 = std::make_shared<node_mock>(
      inlets{new value_inlet, new value_inlet}, outlets{new value_outlet});

  g.add_node(n1);
  g.add_node(n2);
  g.add_node(n3);
  g.add_node(n4);

  g.connect(g.allocate_edge(
      connection{immediate_strict_connection{}}, n1->root_outputs()[0],
      n2->root_inputs()[0], n1, n2));
  g.connect(g.allocate_edge(
      connection{immediate_strict_connection{}}, n1->root_outputs()[0],
      n3->root_inputs()[0], n1, n3));
  g.connect(g.allocate_edge(
      connection{immediate_strict_connection{}}, n2->root_outputs()[0],
      n4->root_inputs()[0], n2, n4));
  g.connect(g.allocate_edge(
      connection{immediate_strict_connection{}}, n3->root_outputs()[0],
      n4->root_inputs()[1], n3, n4));

  {
    n1->set_enabled(true);
    n2->set_enabled(true);
    n3->set_enabled(true);
    n4->set_enabled(true);
    auto res = disable_nodes({n1, n2, n3, n4});
    REQUIRE(res.empty());
  }

  {
    n1->set_enabled(false);
    n2->set_enabled(false);
    n3->set_enabled(false);
    n4->set_enabled(false);
    auto res = disable_nodes({n1, n2, n3, n4});
    REQUIRE(res.empty());
  }

  {
    n1->set_enabled(true);
    n2->set_enabled(true);
    n3->set_enabled(true);
    n4->set_enabled(false);
    auto res = disable_nodes({n1, n2, n3, n4});
    ossia::node_flat_set expected{n2.get(), n3.get()};
    REQUIRE(res == expected);
  }

  {
    n1->set_enabled(true);
    n2->set_enabled(false);
    n3->set_enabled(false);
    n4->set_enabled(false);
    auto res = disable_nodes({n1, n2, n3, n4});
    ossia::node_flat_set expected{n1.get()};
    REQUIRE(res == expected);
  }

  {
    n1->set_enabled(true);
    n2->set_enabled(true);
    n3->set_enabled(false);
    n4->set_enabled(false);
    auto res = disable_nodes({n1, n2, n3, n4});
    ossia::node_flat_set expected{n1.get(), n2.get()};
    REQUIRE(res == expected);
  }

  {
    n1->set_enabled(false);
    n2->set_enabled(true);
    n3->set_enabled(true);
    n4->set_enabled(true);
    auto res = disable_nodes({n1, n2, n3, n4});
    decltype(res) expected{n2.get(), n3.get()};
    REQUIRE(res == expected);
  }
  {
    n1->set_enabled(false);
    n2->set_enabled(false);
    n3->set_enabled(false);
    n4->set_enabled(true);
    auto res = disable_nodes({n1, n2, n3, n4});
    decltype(res) expected{n4.get()};
    REQUIRE(res == expected);
  }
}

TEST_CASE("strict_explicit_relationship_simple", "strict_explicit_relationship_simple")
{
  using namespace ossia;
  TestDevice test;

  // Functional dependency
  simple_explicit_graph g(test, immediate_strict_connection{});
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 0_tv});

  g.state(); // nothing
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 1_tv});
  g.n2->request(simple_token_request{0_tv, 1_tv});

  g.state(); // f2 o f1
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 2, 10 * 2}));

  g.n2->request(simple_token_request{1_tv, 2_tv});

  g.state(); // nothing
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 2, 10 * 2}));
}

TEST_CASE("strict_explicit_relationship_serial", "strict_explicit_relationship_serial")
{
  using namespace ossia;
  TestDevice test;

  // Functional dependency
  three_serial_nodes_explicit_graph g(test, immediate_strict_connection{});
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 0_tv});
  g.n2->request(simple_token_request{0_tv, 0_tv});
  g.n3->request(simple_token_request{0_tv, 0_tv});

  g.state(); // nothing
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 1, 10 * 1, 100 * 1}));
}

TEST_CASE("implicit_ab_bc", "implicit_ab_bc")
{
  using namespace ossia;
  TestDevice test;

  // Functional dependency
  ab_bc_graph g(test, immediate_strict_connection{});

  g.n1->request(simple_token_request{0_tv, 0_tv});
  g.n2->request(simple_token_request{0_tv, 0_tv});

  g.state(); // nothing
  REQUIRE(test.b->value() == ossia::value(std::vector<ossia::value>{1 * 1}));
  REQUIRE(test.c->value() == ossia::value(std::vector<ossia::value>{1 * 1, 10 * 1}));
}
TEST_CASE("implicit_bc_ab", "implicit_bc_ab")
{
  using namespace ossia;
  TestDevice test;

  // Functional dependency
  bc_ab_graph g(test, immediate_strict_connection{});

  g.n1->request(simple_token_request{0_tv, 0_tv});
  g.n2->request(simple_token_request{0_tv, 0_tv});

  g.state(); // nothing
  REQUIRE(test.b->value() == ossia::value(std::vector<ossia::value>{10 * 1}));
  REQUIRE(test.c->value() == ossia::value(std::vector<ossia::value>{10 * 1, 1 * 1}));
}

TEST_CASE("glutton_implicit_relationship", "glutton_implicit_relationship")
{
  using namespace ossia;
  TestDevice test;

  simple_implicit_graph g{test};
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 0_tv});

  g.state(); // f1
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{1 * 1}));

  g.n1->request(simple_token_request{0_tv, 1_tv});
  g.n2->request(simple_token_request{0_tv, 1_tv});

  g.state(); // f2 o f1
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 1, 1 * 2, 10 * 2}));

  g.n2->request(simple_token_request{1_tv, 2_tv});

  g.state(); // f2
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 1, 1 * 2, 10 * 2, 10 * 3}));
}

TEST_CASE("glutton_explicit_relationship", "glutton_explicit_relationship")
{
  // Does it make sense ??
  // Cables : used to reduce "where" things go, so yeah, makes sense
  using namespace ossia;
  TestDevice test;

  simple_explicit_graph g(test, immediate_glutton_connection{});
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 0_tv});

  g.state(); // f1
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{1 * 1}));

  g.n1->request(simple_token_request{0_tv, 1_tv});
  g.n2->request(simple_token_request{0_tv, 1_tv});

  g.state(); // f2 o f1
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 1, 1 * 2, 10 * 2}));

  g.n2->request(simple_token_request{1_tv, 2_tv});

  g.state(); // f2
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 1, 1 * 2, 10 * 2, 10 * 3}));
}

TEST_CASE("glutton_explicit_relationship_2", "glutton_explicit_relationship_2")
{
  // Does it make sense ??
  // Cables : used to reduce "where" things go, so yeah, makes sense
  using namespace ossia;
  TestDevice test;

  no_parameter_explicit_graph g(test, immediate_glutton_connection{});
  debug_mock::messages.clear();

  g.n1->request(simple_token_request{0_tv, 0_tv});

  g.state(); // f1
  REQUIRE((debug_mock::messages == std::vector<std::pair<int, int>>{{1, 0}}));

  g.n1->request(simple_token_request{0_tv, 1_tv});
  g.n2->request(simple_token_request{0_tv, 1_tv});

  debug_mock::messages.clear();
  g.state(); // f2 o f1
  REQUIRE((debug_mock::messages == std::vector<std::pair<int, int>>{{1, 1}, {10, 1}}));

  g.n2->request(simple_token_request{1_tv, 2_tv});

  debug_mock::messages.clear();
  g.state(); // f2
  REQUIRE((debug_mock::messages == std::vector<std::pair<int, int>>{{10, 2}}));
}

TEST_CASE("delayed_relationship", "delayed_relationship")
{
  using namespace ossia;
  TestDevice test;

  simple_explicit_graph g(test, delayed_strict_connection{});
  g.n1->root_outputs()[0]->address = {};
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 0_tv});

  // f1 pushes 1 * 1 in its queue
  g.state();
  REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  g.n1->request(simple_token_request{0_tv, 1_tv});
  g.n2->request(simple_token_request{0_tv, 0_tv});

  // f1(0) = 1
  // f1(1) = 2
  // f2(f1(0), 0) = [1, 10]
  g.state();
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 1, 10 * 1}));

  g.n2->request(simple_token_request{0_tv, 1_tv});

  // f2(f1(1), 1) = [2, 20]
  g.state(); // f2 o f1(t-1)
  REQUIRE(
      test.tuple_addr->value()
      == ossia::value(std::vector<ossia::value>{1 * 2, 10 * 2}));
  // 10 * 1 is not here because we start from {1 * 1} from the point of view of f1(t-1)
}

TEST_CASE("reduced_implicit_relationship", "reduced_implicit_relationship") { }

TEST_CASE("reduced_explicit_relationship", "reduced_explicit_relationship")
{
  //    using namespace ossia;
  //    TestUtils test;

  //    // Two ways to envision reduction : reduce at the input of an outlet, or reduce the execution of all nodes that did take
  //    // the same input at this tick. but would not always make sense.
  //    three_outputs_one_input_explicit_graph g(test, reduction_connection{});
  //    REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  //    g.g.enable(*g.n1);
  //    g.g.enable(*g.n2);
  //    g.g.enable(*g.n3);
  //    g.g.enable(*g.nin);

  //    g.n1->set_time(0);
  //    g.n2->set_time(0);
  //    g.n3->set_time(0);
  //    g.nin->set_time(0);

  //    g.state();

  //    // The reduction operation for values just take the last.
}

TEST_CASE("replaced_implicit_relationship", "replaced_implicit_relationship")
{
  //    using namespace ossia;
  //    TestUtils test;

  //    three_outputs_one_input_explicit_graph g(test, replacing_connection{});
  //    REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

  //    g.g.enable(*g.n1);
  //    g.g.enable(*g.n2);
  //    g.g.enable(*g.n3);
  //    g.g.enable(*g.nin);

  //    g.n1->set_time(0);
  //    g.n2->set_time(0);
  //    g.n3->set_time(0);
  //    g.nin->set_time(0);

  //    g.state();
}

TEST_CASE("replaced_explicit_relationship", "replaced_explicit_relationship") { }

TEST_CASE("temporal_ordering", "temporal_ordering")
{
  /*
    // what if both happen at exact same time.
    // orders should superimperpose themselves so that there is always
    // a "default" ordering (this could be the hierarchical one)
    using namespace ossia;

    {
      TestDevice test;
      simple_implicit_graph g(test, immediate_glutton_connection{});
      g.g.m_ordering = node_ordering::temporal;
      REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

      g.g.enable(*g.n1);
      g.g.disable(*g.n2);
      g.n1->set_date(0, 0);
      g.n1->temporal_priority = {0};
      g.n2->set_date(0, 0);

      g.state(); // f1
      REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{1 * 1}));

      g.g.enable(*g.n1);
      g.g.enable(*g.n2);
      g.n1->set_date(1, 0.5);
      g.n2->set_date(1, 0.5);
      g.n2->temporal_priority = {1};

      g.state(); // f2 o f1
      REQUIRE(test.tuple_addr->value(), ossia::value(std::vector<ossia::value>{1 * 1, 1 * 2 == 10 * 2}));

      g.g.enable(*g.n1);
      g.g.enable(*g.n2);
      g.n1->set_date(2, 1);
      g.n2->set_date(2, 1);

      g.state(); // f2 o f1
      REQUIRE(test.tuple_addr->value(), ossia::value(std::vector<ossia::value>{1 * 1, 1 * 2, 10 * 2, 1 * 3 == 10 * 3}));
    }

    {
      TestDevice test;
      simple_implicit_graph g(test, immediate_glutton_connection{});
      g.g.m_ordering = node_ordering::temporal;
      REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{}));

      g.g.enable(*g.n1);
      g.g.disable(*g.n2);
      g.n1->set_date(0, 0);
      g.n1->temporal_priority = {1};
      g.n2->set_date(0, 0);

      g.state(); // f1
      REQUIRE(test.tuple_addr->value() == ossia::value(std::vector<ossia::value>{1 * 1}));

      g.g.enable(*g.n1);
      g.g.enable(*g.n2);
      g.n1->set_date(1, 0.5);
      g.n2->set_date(1, 0.5);
      g.n2->temporal_priority = {0};

      g.state(); // f1 o f2
      REQUIRE(test.tuple_addr->value(), ossia::value(std::vector<ossia::value>{1 * 1, 10 * 2 == 1 * 2}));

      g.g.enable(*g.n1);
      g.g.enable(*g.n2);
      g.n1->set_date(2, 1);
      g.n2->set_date(2, 1);

      g.state(); // f1 o f2
      REQUIRE(test.tuple_addr->value(), ossia::value(std::vector<ossia::value>{1 * 1, 10 * 2, 1 * 2, 10 * 3 == 1 * 3}));
    }
    */
}

TEST_CASE("hierarchical_ordering", "hierarchical_ordering") { }
