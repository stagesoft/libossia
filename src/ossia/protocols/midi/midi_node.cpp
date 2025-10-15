// This is an open source non-commercial project. Dear PVS-Studio, please check
// it. PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <ossia/protocols/midi/midi_device.hpp>
#include <ossia/protocols/midi/midi_node.hpp>
#include <ossia/protocols/midi/midi_parameter.hpp>
#include <ossia/protocols/midi/midi_protocol.hpp>

#include <charconv>
namespace ossia::net::midi
{
struct midi_name_table
{
  midi_name_table()
  {
    for(int i = 0; i < 128; i++)
    {
      char str[16] = {0};
      std::to_chars(str, str + 16, i);
      names[i] = str;
    }
  }

  std::array<std::string, 128> names;
};

const std::string& midi_node_name(midi_size_t i)
{
  static const midi_name_table tbl;
  return tbl.names[i];
}

midi_node::~midi_node() = default;

midi_node::midi_node(midi_device& aDevice, node_base& aParent)
    : m_device{aDevice}
    , m_parent{&aParent}
{
}

midi_node::midi_node(midi_device& aDevice)
    : m_device{aDevice}
{
}

device_base& midi_node::get_device() const
{
  return m_device;
}

node_base* midi_node::get_parent() const
{
  return m_parent;
}

node_base& midi_node::set_name(std::string)
{
  return *this;
}
parameter_base* midi_node::get_parameter() const
{
  return m_parameter.get();
}

parameter_base* midi_node::create_parameter(val_type)
{
  return m_parameter.get();
}

bool midi_node::remove_parameter()
{
  return false;
}

std::unique_ptr<node_base> midi_node::make_child(const std::string& name)
{
  return nullptr;
}

void midi_node::removing_child(node_base& node) { }

midi_node* midi_node::add_midi_node(std::unique_ptr<midi_node> n)
{
  assert(n);
  auto ptr = n.get();
  {
    write_lock_t lock{m_mutex};
    m_children.push_back(std::move(n));
  }
  m_device.on_node_created(*ptr);
  return ptr;
}

}
