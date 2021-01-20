#pragma once

#include <ossia/network/base/protocol.hpp>
#include <ossia/network/common/complex_type.hpp>
#include <ossia/network/common/device_parameter.hpp>
#include <ossia/network/domain/domain.hpp>
#include <ossia/network/oscquery/oscquery_server.hpp>

#include <vector>

typedef struct _SDL_Joystick SDL_Joystick;

namespace ossia::net
{

class OSSIA_EXPORT joystick_protocol final : public ossia::net::protocol_base
{
  friend class joystick_protocol_manager;

public:
  joystick_protocol(const int32_t joystick_id, const int joystick_index);
  joystick_protocol(const joystick_protocol&) = delete;
  joystick_protocol(joystick_protocol&&) = delete;
  joystick_protocol& operator=(const joystick_protocol&) = delete;
  joystick_protocol& operator=(joystick_protocol&&) = delete;
  ~joystick_protocol() override;

  void set_device(ossia::net::device_base& dev) override;

  bool pull(ossia::net::parameter_base& param) override;
  bool push(const ossia::net::parameter_base& param, const ossia::value& v) override;
  bool push_raw(const ossia::net::full_parameter_data&) override;
  bool observe(ossia::net::parameter_base& param, bool enable) override;

  bool update(ossia::net::node_base&) override;
  void stop() override;

  static unsigned int get_joystick_count();
  static const char* get_joystick_name(const int index);
  static int32_t get_joystick_id(const int index);
  static void write_joystick_uuid(const int index, uint8_t* dst);

  // {device id, device index} or {-1, -1} if no suitable joystick is available
  static std::pair<int32_t, int32_t> get_available_id_for_uid(const uint8_t* uid);

private:
  ossia::net::device_base* m_device{};

  std::vector<device_parameter*> m_axis_parameters;
  std::vector<device_parameter*> m_hat_parameters;
  std::vector<device_parameter*> m_ball_parameters;
  std::vector<device_parameter*> m_button_parameters;

  int32_t m_joystick_id;
  SDL_Joystick* m_joystick{};
};
}
