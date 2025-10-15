#pragma once

#include <ossia/detail/optional.hpp>

#include <ossia-pd/src/parameter_base.hpp>

namespace ossia::pd
{

class remote : public parameter_base
{
public:
  using is_view = std::true_type;

  remote();

  bool register_node(const std::vector<t_matcher>& node);
  bool do_registration(const std::vector<t_matcher>& node);
  bool unregister();

  ossia::net::device_base* m_dev{};
  float m_rate_min;

  void set_unit();
  void set_rate();

  void on_parameter_created_callback(const ossia::net::parameter_base& addr);
  static void update_attribute(
      remote* x, ossia::string_view attribute, const ossia::net::node_base* node);
  static void bind(remote* x, t_symbol* address);
  static void click(
      remote* x, t_floatarg xpos, t_floatarg ypos, t_floatarg shift, t_floatarg ctrl,
      t_floatarg alt);
  static t_pd_err
  notify(remote* x, t_symbol* s, t_symbol* msg, void* sender, void* data);

  static void destroy(remote* x);
  static void* create(t_symbol* name, int argc, t_atom* argv);

  static ossia::safe_set<remote*>& quarantine();

  static void get_mess_cb(remote* x, t_symbol* s);
  static void get_unit(remote* x);
  static void get_mute(remote* x);
  static void get_rate(remote* x);
  static void get_enable(remote* x);

  void on_device_deleted(const ossia::net::node_base&);
};
} // namespace ossia
