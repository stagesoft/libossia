#pragma once
#include <ossia/dataflow/graph_node.hpp>
#include <ossia/dataflow/safe_nodes/node.hpp>
#include <ossia/detail/algorithms.hpp>

#include <bitset>

namespace ossia::safe_nodes
{

template <typename T, typename U>
auto timestamp(const std::pair<T, U>& p)
{
  return p.first;
}
template <typename T>
auto timestamp(const T& p)
{
  return p.timestamp;
}

struct precise_tick
{
  template <typename TickFun, typename... Args>
  void operator()(
      TickFun&& f, const ossia::token_request& req,
      const ossia::safe_nodes::timed_vec<Args>&... arg)
  {
    auto iterators = std::make_tuple(arg.begin()...);
    const auto last_iterators = std::make_tuple(--arg.end()...);

    // while all the it are != arg.rbegin(),
    //  increment the smallest one
    //  call a tick with this at the new date

    auto reached_end = [&] {
      bool b = true;
      ossia::for_each_in_range<sizeof...(arg)>(
          [&b, &iterators, &last_iterators](auto i) {
            b
                &= (std::get<i.value>(iterators)
                    == std::get<i.value>(last_iterators));
          });
      return b;
    };

    // const auto parent_dur = req.date / req.position;
    auto call_f = [&](ossia::time_value cur) {
      ossia::token_request r = req;
      // TODO r.date +=
      std::apply(
          [&](const auto&... it) {
            std::forward<TickFun>(f)(r, it->second...);
          },
          iterators);
    };

    ossia::time_value current_time = req.offset;
    while (!reached_end())
    {
      // run a tick with the current values (TODO pass the current time too)
      call_f(current_time);

      std::bitset<sizeof...(Args)> to_increment;
      to_increment.reset();
      auto min = ossia::Infinite;

      ossia::for_each_in_range<sizeof...(arg)>([&](auto idx_t) {
        constexpr auto idx = idx_t.value;
        auto& it = std::get<idx>(iterators);
        if (it != std::get<idx>(last_iterators))
        {
          auto next = it;
          ++next;
          const auto next_ts = time_value{timestamp(*next)};
          const auto diff = next_ts - current_time;
          if (diff < 0_tv)
          {
            // token before offset, we increment in all cases
            it = next;
            return;
          }

          if (diff < min)
          {
            min = diff;
            to_increment.reset();
            to_increment.set(idx);
          }
          else if (diff == min)
          {
            to_increment.set(idx);
          }
        }
      });

      current_time += min;
      ossia::for_each_in_range<sizeof...(arg)>([&](auto idx_t) {
        constexpr auto idx = idx_t.value;
        if (to_increment.test(idx))
        {
          ++std::get<idx>(iterators);
        }
      });
    }

    call_f(current_time);
  }
};

struct default_tick
{
  template <typename TickFun, typename... Args>
  void operator()(
      TickFun&& f, const ossia::token_request& req,
      const ossia::safe_nodes::timed_vec<Args>&... arg)
  {
    f(req, arg...);
  }
};

struct last_tick
{
  template <typename TickFun, typename... Args>
  void operator()(
      TickFun&& f, const ossia::token_request& req,
      const ossia::safe_nodes::timed_vec<Args>&... arg)
  {
    // TODO use largest date instead
    std::apply(
        [&](const auto&... it) {
          std::forward<TickFun>(f)(req, it->second...);
        },
        std::make_tuple(--arg.end()...));
  }
};

// pass first and last in a struct ev_t { T& first, last; }
// advanced case: regress?
struct first_last_tick
{
  template <typename TickFun, typename... Args>
  void operator()(
      TickFun&& f, const ossia::token_request& req,
      const ossia::safe_nodes::timed_vec<Args>&... arg)
  {
    // TODO use correct dates
    std::apply(
        [&](const auto&... it) {
          std::forward<TickFun>(f)(req, it->second...);
        },
        std::make_tuple({arg.begin(), --arg.end()}...));
  }
};
}
