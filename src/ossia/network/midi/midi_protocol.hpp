#pragma once
#include <ossia/network/base/device.hpp>
#include <ossia/network/base/parameter.hpp>
#include <ossia/network/base/protocol.hpp>
#include <ossia/network/common/parameter_properties.hpp>
#include <ossia/network/domain/domain.hpp>
#include <ossia/network/midi/detail/channel.hpp>
#include <ossia/network/value/value.hpp>

#include <ossia/detail/lockfree_queue.hpp>

#include <rtmidi17/message.hpp>
#include <array>
#include <atomic>
#include <cassert>
namespace rtmidi
{
class midi_in;
class midi_out;
struct message;
}
namespace ossia::net::midi
{
class midi_device;
struct OSSIA_EXPORT midi_info
{
  enum class Type
  {
    Input,
    Output
  };

  midi_info() = default;
  midi_info(Type t, std::string d, int p)
      : type{t}, device{std::move(d)}, port{p}
  {
  }

  Type type{};
  std::string device{};
  int port{};
};

class OSSIA_EXPORT midi_protocol final : public ossia::net::protocol_base
{
public:
  midi_protocol();
  midi_protocol(midi_info);
  ~midi_protocol();

  bool set_info(midi_info);
  midi_info get_info() const;

  std::vector<midi_info> scan();

  void push_value(const rtmidi::message&);

  template <typename T>
  void clone_value(T& port)
  {
    typename T::value_type mess;
    while (messages.try_dequeue(mess))
    {
      port.push_back(mess);
    }
  }

  void enable_registration();

  bool learning() const;
  void set_learning(bool);

private:
  ossia::spsc_queue<rtmidi::message> messages;
  std::unique_ptr<rtmidi::midi_in> m_input;
  std::unique_ptr<rtmidi::midi_out> m_output;

  std::array<midi_channel, 16> m_channels;

  midi_info m_info{};
  midi_device* m_dev{};
  bool m_registers{};
  std::atomic_bool m_learning{};

  friend class midi_device;
  friend class midi_parameter;
  bool pull(ossia::net::parameter_base&) override;
  bool push(const ossia::net::parameter_base&, const ossia::value& v) override;
  bool
  push_raw(const ossia::net::full_parameter_data& parameter_base) override;
  bool observe(ossia::net::parameter_base&, bool) override;
  bool update(ossia::net::node_base& node_base) override;
  void set_device(ossia::net::device_base& dev) override;

  void
  value_callback(ossia::net::parameter_base& param, const ossia::value& val);

  void midi_callback(const rtmidi::message&);
  void on_learn(const rtmidi::message& m);
};
}
