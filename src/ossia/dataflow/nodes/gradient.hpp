#pragma once
#include <ossia/dataflow/graph_node.hpp>
#include <ossia/dataflow/node_process.hpp>
#include <ossia/dataflow/port.hpp>
#include <ossia/detail/flat_map.hpp>
#include <ossia/detail/math.hpp>
#include <ossia/editor/curve/curve_segment/easing.hpp>
#include <ossia/network/base/parameter.hpp>
#include <ossia/network/dataspace/color.hpp>

namespace ossia::nodes
{
class gradient final : public ossia::graph_node
{
public:
  using grad_type = ossia::flat_map<double, ossia::hunter_lab>;

  static auto clamp_color(ossia::argb col)
  {
    using namespace std;
    for(size_t i = 0; i < col.dataspace_value.size(); i++)
      col.dataspace_value[i] = ossia::clamp<float>(col.dataspace_value[i], 0.f, 1.f);

    return col;
  }

  gradient()
  {
    ossia::outlet_ptr vp = new ossia::value_outlet;
    vp->target<ossia::value_port>()->type = ossia::argb_u{};
    m_outlets.push_back(std::move(vp));
  }

  void set_gradient(grad_type t)
  {
    m_data = std::move(t);
  }

  void handle_before_first(const ossia::token_request& tk, int64_t tick_start)
  {
    const auto position = tk.position();
    auto& out = *m_outlets[0]->target<ossia::value_port>();
    auto beg = m_data.begin();

    if (beg->first >= position)
    {
      out.write_value(
          clamp_color(ossia::argb{beg->second}).dataspace_value, tick_start);
    }
    else if (!mustTween)
    {
      out.write_value(
          clamp_color(ossia::argb{beg->second}).dataspace_value, tick_start);
    }
    else
    {
      if (!tween)
      {
        auto addr
            = m_outlets[0]->address.target<ossia::net::parameter_base*>();
        if (addr && *addr)
        {
          // TODO if the curve is in another unit, we have to convert it to the
          // correct unit.
          tween = ossia::argb{ossia::convert<ossia::vec4f>((*addr)->value())};
        }
        else
        {
          tween = ossia::argb{beg->second};
        }
      }
      out.write_value(
          ease_color(0., *tween, beg->first, beg->second, position)
              .dataspace_value,
          tick_start);
    }
  }

  void
  run(const ossia::token_request& t, ossia::exec_state_facade e) noexcept override
  {
    auto& out = *m_outlets[0]->target<ossia::value_port>();

    const auto tick_start = e.physical_start(t);

    switch (m_data.size())
    {
      case 0:
        out.write_value(ossia::vec4f{0., 0., 0., 0.}, tick_start);
        return;
      case 1:
        handle_before_first(t, tick_start);
        return;
      default:
      {
        auto it_next = m_data.lower_bound(t.position());
        // Before start
        if (it_next == m_data.begin())
        {
          handle_before_first(t, tick_start);
        }
        // past end
        else if (it_next == m_data.end())
        {
          out.write_value(
              clamp_color(ossia::argb{m_data.rbegin()->second}).dataspace_value,
              tick_start);
        }
        else
        {
          auto it_prev = it_next;
          --it_prev;

          out.write_value(
              ease_color(
                  it_prev->first, it_prev->second, it_next->first,
                  it_next->second, t.position())
                  .dataspace_value,
              tick_start);
        }
      }
    }
  }

  ossia::argb ease_color(
      double prev_pos, ossia::hunter_lab prev, double next_pos,
      ossia::hunter_lab next, double pos)
  {
    // Interpolate in La*b* domain
    const auto coeff = (pos - prev_pos) / (next_pos - prev_pos);

    ossia::hunter_lab res;
    ossia::easing::ease e{};
    res.dataspace_value = ossia::make_vec(
        e(prev.dataspace_value[0], next.dataspace_value[0], coeff),
        e(prev.dataspace_value[1], next.dataspace_value[1], coeff),
        e(prev.dataspace_value[2], next.dataspace_value[2], coeff));

    return clamp_color(ossia::argb{res});
  }

public:
  std::optional<ossia::argb> tween;

private:
  grad_type m_data;

public:
  bool mustTween{};
};

class gradient_process final : public ossia::node_process
{
public:
  using ossia::node_process::node_process;
  void start() override
  {
    static_cast<gradient*>(node.get())->tween = std::nullopt;
  }
};
}
