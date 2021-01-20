#pragma once
#include <ossia-config.hpp>
#if defined(OSSIA_PARALLEL)
#include <ossia/detail/hash_map.hpp>
#include <ossia/dataflow/graph/graph_static.hpp>
/*
#include <tbb/flow_graph.h>

namespace ossia
{

struct parallel_exec;
template <typename Impl>
struct parallel_update
{
public:
  using cont_node = tbb::flow::continue_node<tbb::flow::continue_msg>;
  std::shared_ptr<spdlog::logger> logger;
  std::shared_ptr<bench_map> perf_map;

  template <typename Graph_T>
  parallel_update(Graph_T& g) : impl{g}
  {
  }

  void update_graph(ossia::node_map& nodes, ossia::graph_t& graph)
  {
    namespace tbf = tbb::flow;
    flow_nodes.clear();
    start_nodes.clear();
    nodes_with_incoming_edges.clear();

    flow_graph.~graph();
    new (&flow_graph) tbf::graph;

    if (logger)
    {
      if (perf_map)
      {
        for (const auto& n : nodes)
        {
          graph_node* node = n.first.get();
          (*perf_map)[node] = std::nullopt;
          flow_nodes.insert({node, std::make_unique<cont_node>(
                                       flow_graph, node_exec_logger_bench{
                                                       cur_state, *perf_map,
                                                       *logger, *node})});
        }
      }
      else
      {
        for (auto n : nodes)
        {
          graph_node* node = n.first.get();
          flow_nodes.insert(
              {node,
               std::make_unique<cont_node>(
                   flow_graph, node_exec_logger{cur_state, *logger, *node})});
        }
      }
    }
    else
    {
      for (auto n : nodes)
      {
        graph_node* node = n.first.get();
        flow_nodes.insert(
            {node, std::make_unique<cont_node>(
                       flow_graph, node_exec{cur_state, *node})});
      }
    }

    for (auto n : nodes)
    {
      graph_node* n1 = n.first.get();
      for (auto m : nodes)
      {
        graph_node* n2 = m.first.get();
        if (n2 != n1)
        {
          if (boost::edge(n.second, m.second, graph).second)
          {
            tbf::make_edge(*flow_nodes[n2], *flow_nodes[n1]);
            nodes_with_incoming_edges.push_back(n1);
          }
        }
      }
    }

    for (auto n : nodes)
    {
      if (!ossia::contains(nodes_with_incoming_edges, n.first.get()))
        start_nodes.push_back(n.first.get());
    }

    start_node
        = std::make_unique<tbf::broadcast_node<tbf::continue_msg>>(flow_graph);
    for (auto node : start_nodes)
    {
      tbf::make_edge(*start_node, *flow_nodes[node]);
    }
  }

  template <typename Graph_T, typename DevicesT>
  void operator()(Graph_T& g, const DevicesT& devices)
  {
    impl(g, devices);
    update_graph(g.m_nodes, impl.m_sub_graph);
  }

private:
  friend struct parallel_exec;

  Impl impl;
  execution_state* cur_state{};
  std::unique_ptr<tbb::flow::broadcast_node<tbb::flow::continue_msg>> start_node;
  std::vector<graph_node*> nodes_with_incoming_edges;

  tbb::flow::graph flow_graph;
  ossia::fast_hash_map<graph_node*, std::unique_ptr<cont_node>> flow_nodes;
  std::vector<graph_node*> start_nodes;
};

struct parallel_exec
{
  template <typename Graph_T>
  parallel_exec(Graph_T&)
  {
  }

  template <typename Graph_T, typename Impl>
  void operator()(
      Graph_T& g, parallel_update<Impl>& self, ossia::execution_state& e,
      const std::vector<ossia::graph_node*>&)
  {
    self.cur_state = &e;
    self.start_node->try_put(tbb::flow::continue_msg{});
    self.flow_graph.wait_for_all();
  }
};

using parallel_tc_graph
    = graph_static<parallel_update<tc_update<fast_tc>>, parallel_exec>;
}
*/
#endif

#if __has_include(<taskflow/taskflow.hpp>)
#include <taskflow/taskflow.hpp>
namespace ossia
{
struct cpptf_exec;
template <typename Impl>
struct cpptf_update
{
public:
  std::shared_ptr<spdlog::logger> logger;
  std::shared_ptr<bench_map> perf_map;

  template <typename Graph_T>
  cpptf_update(Graph_T& g) : impl{g}
  {
  }

  void update_graph(ossia::node_map& nodes, ossia::graph_t& graph)
  {
    flow_nodes.clear();
    flow_graph.clear();

    if (logger)
    {
      if (perf_map)
      {
        for (const auto& n : nodes)
        {
          graph_node* node = n.first.get();
          (*perf_map)[node] = std::nullopt;
          flow_nodes[node] = flow_graph.emplace(node_exec_logger_bench{cur_state, *perf_map, *logger, *node});
        }
      }
      else
      {
        for (auto n : nodes)
        {
          graph_node* node = n.first.get();
          flow_nodes[node] = flow_graph.emplace(node_exec_logger{cur_state, *logger, *node});
        }
      }
    }
    else
    {
      for (auto n : nodes)
      {
        graph_node* node = n.first.get();
        flow_nodes[node] = flow_graph.emplace(node_exec{cur_state, *node});
      }
    }

    // TODO instead for all edge
    for (auto n : nodes)
    {
      graph_node* n1 = n.first.get();
      for (auto m : nodes)
      {
        graph_node* n2 = m.first.get();
        if (n2 != n1)
        {
          if (boost::edge(n.second, m.second, graph).second)
          {
            auto& sender = flow_nodes[n2];
            auto& receiver = flow_nodes[n1];
            sender.precede(receiver);
          }
        }
      }
    }
  }

  template <typename Graph_T, typename DevicesT>
  void operator()(Graph_T& g, const DevicesT& devices)
  {
    impl(g, devices);
    update_graph(g.m_nodes, impl.m_sub_graph);
  }

private:
  friend struct cpptf_exec;

  Impl impl;
  execution_state* cur_state{};

  tf::Taskflow flow_graph;
  tf::Executor executor;
  ossia::fast_hash_map<graph_node*, tf::Task> flow_nodes;
};

struct cpptf_exec
{
  template <typename Graph_T>
  cpptf_exec(Graph_T&)
  {
  }

  template <typename Graph_T, typename Impl>
  void operator()(
      Graph_T& g, cpptf_update<Impl>& self, ossia::execution_state& e,
      const std::vector<ossia::graph_node*>&)
  {
    self.cur_state = &e;
    self.executor.run(self.flow_graph).get();
  }
};

using cpptf_tc_graph
    = graph_static<cpptf_update<tc_update<fast_tc>>, cpptf_exec>;
}
#endif
