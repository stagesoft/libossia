// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <ossia-qt/serial/serial_parameter.hpp>
#include <ossia-qt/serial/serial_device.hpp>
#include <ossia-qt/serial/serial_node.hpp>

namespace ossia
{
namespace net
{

serial_node::serial_node(
    const serial_parameter_data& data, serial_device& aDevice,
    serial_node& aParent)
    : m_device{aDevice}, m_parent{&aParent}
{
  m_name = data.name;
  if (!data.request.isEmpty() || data.type)
    m_parameter = std::make_unique<serial_parameter>(data, *this);
}

serial_node::serial_node(
    const serial_parameter_data& data, serial_device& aDevice)
    : m_device{aDevice}
{
  m_name = data.name;
  if (!data.request.isEmpty() || data.type)
    m_parameter = std::make_unique<serial_parameter>(data, *this);
}

ossia::net::device_base& serial_node::get_device() const
{
  return m_device;
}

ossia::net::node_base* serial_node::get_parent() const
{
  return m_parent;
}

ossia::net::node_base& serial_node::set_name(std::string)
{
  return *this;
}

ossia::net::parameter_base* serial_node::get_parameter() const
{
  return m_parameter.get();
}

ossia::net::parameter_base* serial_node::create_parameter(ossia::val_type)
{
  return get_parameter();
}

bool serial_node::remove_parameter()
{
  return false;
}

void serial_node::add_child(std::unique_ptr<node_base> p)
{
  if (p)
  {
    write_lock_t lock{m_mutex};
    m_children.push_back(std::move(p));
  }
}
}
}
