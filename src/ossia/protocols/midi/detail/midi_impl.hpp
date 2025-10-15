#pragma once
#include <ossia/editor/state/message.hpp>
#include <ossia/network/base/osc_address.hpp>
#include <ossia/network/domain/domain.hpp>
#include <ossia/network/value/value.hpp>
#include <ossia/protocols/midi/detail/channel.hpp>
#include <ossia/protocols/midi/midi_device.hpp>
#include <ossia/protocols/midi/midi_node.hpp>
#include <ossia/protocols/midi/midi_parameter.hpp>
#include <ossia/protocols/midi/midi_protocol.hpp>

namespace ossia::net::midi
{
const std::string& midi_node_name(midi_size_t i);

class generic_node final
    : public midi_node
    , public midi_parameter
{
public:
  generic_node(address_info addr, midi_device& dev, ossia::net::node_base& p)
      : midi_node{dev, p}
      , midi_parameter{addr, *this}
  {
    using namespace std::literals;
    switch(addr.type)
    {
      case address_info::Type::NoteOn:
        m_name = "on"s;
        break;
      case address_info::Type::NoteOn_N:
        m_name = midi_node_name(addr.note);
        break;
      case address_info::Type::NoteOff:
        m_name = "off"s;
        break;
      case address_info::Type::NoteOff_N:
        m_name = midi_node_name(addr.note);
        break;
      case address_info::Type::CC:
        m_name = "control"s;
        break;
      case address_info::Type::CC_N:
        m_name = midi_node_name(addr.note);
        break;
      case address_info::Type::PC:
        m_name = "program"s;
        break;
      case address_info::Type::PC_N:
        m_name = midi_node_name(addr.note);
        break;
      case address_info::Type::PB:
        m_name = "pitchbend"s;
        break;
      case address_info::Type::Any:
        m_name = "TODO"s;
        break;
      default:
        break;
    }

    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
  }

  std::unique_ptr<node_base> make_child(const std::string& name) override
  {
    int num = -1;

    try
    {
      num = std::stoi(name);
    }
    catch(...)
    {
    }

    if(num == -1)
    {
      return nullptr;
    }

    address_info ai{m_info.channel, {}, midi_size_t(num)};
    switch(m_info.type)
    {
      case address_info::Type::NoteOn:
        ai.type = address_info::Type::NoteOn_N;
        break;
      case address_info::Type::NoteOff:
        ai.type = address_info::Type::NoteOff_N;
        break;
      case address_info::Type::CC:
        ai.type = address_info::Type::CC_N;
        break;
      case address_info::Type::PC:
        ai.type = address_info::Type::PC_N;
        break;
      default:
        return nullptr;
    }

    return std::make_unique<generic_node>(ai, m_device, *this);
  }

  ~generic_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class note_on_N_node final
    : public midi_node
    , public midi_parameter
{
public:
  note_on_N_node(
      midi_size_t channel, midi_size_t note, midi_device& aDevice,
      ossia::net::node_base& aParent)
      : midi_node{aDevice, aParent}
      , midi_parameter{address_info{channel, address_info::Type::NoteOn_N, note}, *this}
  {
    m_name = midi_node_name(note);
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
  }

  ~note_on_N_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class note_off_N_node final
    : public midi_node
    , public midi_parameter
{
public:
  note_off_N_node(
      midi_size_t channel, midi_size_t note, midi_device& aDevice,
      ossia::net::node_base& aParent)
      : midi_node{aDevice, aParent}
      , midi_parameter{address_info{channel, address_info::Type::NoteOff_N, note}, *this}
  {
    m_name = midi_node_name(note);
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
  }

  ~note_off_N_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class control_N_node final
    : public midi_node
    , public midi_parameter
{
public:
  control_N_node(
      midi_size_t channel, midi_size_t param, midi_device& aDevice,
      ossia::net::node_base& aParent)
      : midi_node{aDevice, aParent}
      , midi_parameter{address_info{channel, address_info::Type::CC_N, param}, *this}
  {
    m_name = midi_node_name(param);
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
  }

  ~control_N_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class program_N_node final
    : public midi_node
    , public midi_parameter
{
public:
  program_N_node(
      midi_size_t channel, midi_size_t param, midi_device& aDevice,
      ossia::net::node_base& aParent)
      : midi_node{aDevice, aParent}
      , midi_parameter{address_info{channel, address_info::Type::PC_N, param}, *this}
  {
    m_name = midi_node_name(param);
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
  }

  ~program_N_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class program_node final
    : public midi_node
    , public midi_parameter
{
public:
  program_node(midi_size_t channel, midi_device& aDevice, ossia::net::node_base& aParent)
      : midi_node(aDevice, aParent)
      , midi_parameter{address_info{channel, address_info::Type::PC, 0}, *this}
  {
    using namespace std::literals;
    m_name = "program"s;
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
    m_children.reserve(128);
    for(int i = 0; i < 128; i++)
    {
      auto ptr = std::make_unique<program_N_node>(channel, i, m_device, *this);
      m_children.push_back(std::move(ptr));
    }
  }

  ~program_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class note_on_node final
    : public midi_node
    , public midi_parameter
{
public:
  note_on_node(midi_size_t channel, midi_device& aDevice, ossia::net::node_base& aParent)
      : midi_node(aDevice, aParent)
      , midi_parameter{address_info{channel, address_info::Type::NoteOn, 0}, *this}
  {
    using namespace std::literals;
    m_name = "on"s;
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
    m_children.reserve(128);
    for(int i = 0; i < 128; i++)
    {
      auto ptr = std::make_unique<note_on_N_node>(channel, i, m_device, *this);
      m_children.push_back(std::move(ptr));
    }
  }

  ~note_on_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class note_off_node final
    : public midi_node
    , public midi_parameter
{
public:
  note_off_node(
      midi_size_t channel, midi_device& aDevice, ossia::net::node_base& aParent)
      : midi_node(aDevice, aParent)
      , midi_parameter{address_info{channel, address_info::Type::NoteOff, 0}, *this}
  {
    using namespace std::literals;
    m_name = "off"s;
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);

    m_children.reserve(128);
    for(int i = 0; i < 128; i++)
    {
      auto ptr = std::make_unique<note_off_N_node>(channel, i, m_device, *this);
      m_children.push_back(std::move(ptr));
    }
  }

  ~note_off_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class control_node final
    : public midi_node
    , public midi_parameter
{
public:
  control_node(midi_size_t channel, midi_device& aDevice, ossia::net::node_base& aParent)
      : midi_node(aDevice, aParent)
      , midi_parameter{address_info{channel, address_info::Type::CC, 0}, *this}
  {
    using namespace std::literals;
    m_name = "control"s;
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);

    m_children.reserve(128);
    for(int i = 0; i < 128; i++)
    {
      auto ptr = std::make_unique<control_N_node>(channel, i, m_device, *this);
      m_children.push_back(std::move(ptr));
    }
  }

  ~control_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class pitch_bend_node final
    : public midi_node
    , public midi_parameter
{
public:
  pitch_bend_node(
      midi_size_t channel, midi_device& aDevice, ossia::net::node_base& aParent)
      : midi_node(aDevice, aParent)
      , midi_parameter{address_info{channel, address_info::Type::PB, 0}, *this}
  {
    using namespace std::literals;
    m_name = "pitchbend"s;
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_parameter.reset(this);
  }

  ~pitch_bend_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);

    m_device.on_parameter_removing(*this);
    m_device.get_protocol().observe(*this, false);

    m_parameter.release();
  }
};

class channel_node final : public midi_node
{
public:
  const midi_size_t channel;

  channel_node(
      bool init, midi_size_t channel, midi_device& aDevice,
      ossia::net::node_base& aParent)
      : midi_node(aDevice, aParent)
      , channel{channel}
  {
    m_name = midi_node_name(channel);
    m_oscAddressCache = ossia::net::osc_parameter_string((ossia::net::node_base&)*this);
    m_children.reserve(5);

    if(init)
    {
      m_children.push_back(std::make_unique<note_on_node>(channel, m_device, *this));

      m_children.push_back(std::make_unique<note_off_node>(channel, m_device, *this));

      m_children.push_back(std::make_unique<control_node>(channel, m_device, *this));

      m_children.push_back(std::make_unique<program_node>(channel, m_device, *this));

      m_children.push_back(std::make_unique<pitch_bend_node>(channel, m_device, *this));
    }
  }

  ~channel_node()
  {
    m_children.clear();

    about_to_be_deleted(*this);
  }

  std::array<ossia::message, 2> note_on(midi_size_t note, midi_size_t vel)
  {
    const auto& c = children();
    return {
        {ossia::message{
             *c[0]->get_parameter(),
             value{std::vector<ossia::value>{int32_t{note}, int32_t{vel}}}},
         ossia::message{*c[0]->children()[note]->get_parameter(), int32_t{vel}}}};
  }

  std::array<ossia::message, 2> note_off(midi_size_t note, midi_size_t vel)
  {
    const auto& c = children();
    return {
        {ossia::message{
             *c[1]->get_parameter(),
             value{std::vector<ossia::value>{int32_t{note}, int32_t{vel}}}},
         ossia::message{*c[1]->children()[note]->get_parameter(), int32_t{vel}}}};
  }

  std::unique_ptr<node_base> make_child(const std::string& name) override
  {
    address_info ai{channel, {}, 0};
    if(name == "on")
    {
      ai.type = address_info::Type::NoteOn;
    }
    else if(name == "off")
    {
      ai.type = address_info::Type::NoteOff;
    }
    else if(name == "control")
    {
      ai.type = address_info::Type::CC;
    }
    else if(name == "program")
    {
      ai.type = address_info::Type::PC;
    }
    else if(name == "pitchbend")
    {
      ai.type = address_info::Type::PB;
    }
    else
    {
      return nullptr;
    }

    return std::make_unique<generic_node>(ai, m_device, *this);
  }
};

}
