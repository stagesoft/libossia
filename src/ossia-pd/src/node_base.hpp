#pragma once

#include <ossia-pd/src/object_base.hpp>

namespace ossia::pd
{

class node_base : public object_base
{
public:
  node_base(t_eclass* x);

  static void preset(node_base* x, t_symbol* s, int argc, t_atom* argv);
  static void class_setup(t_eclass* c);
  static void set(node_base* x, t_symbol* s, int argc, t_atom* argv);
  static void push_default_value(node_base* x);

  /**
   * @brief obj_namespace send the namespace through dump outlet
   * @note only relevant for client, device, model and view objects.
   * @param x
   * @details with argc = 0, it will return only parameter (no node without parameter)
   */
  static void get_namespace(object_base* x, t_symbol* s, long argc, t_atom* argv);
};

} // namespace ossia
