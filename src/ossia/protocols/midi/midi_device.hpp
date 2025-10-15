#pragma once

#include <ossia/network/base/device.hpp>
#include <ossia/protocols/midi/midi_node.hpp>

namespace ossia::net::midi
{
class OSSIA_EXPORT midi_device final
    : public ossia::net::device_base
    , public midi_node
{
public:
  midi_device(std::string name, std::unique_ptr<ossia::net::protocol_base> prot);
  ~midi_device();

  //! Create a default MIDI tree with all the nodes available
  bool create_full_tree();

  using midi_node::get_name;
  using midi_node::get_parameter;

  node_base& set_name(std::string n) override;

  const ossia::net::node_base& get_root_node() const override;
  ossia::net::node_base& get_root_node() override;

  std::unique_ptr<node_base> make_child(const std::string& name) override;
};
}
