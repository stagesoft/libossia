#pragma once
#include <ossia/detail/hash_map.hpp>
#include <ossia/network/common/device_parameter.hpp>

#include <cstdint>

struct wiimote_t;

namespace ossia::net
{

class rumble_parameter : public device_parameter
{

public:
  rumble_parameter(ossia::net::node_base& node, struct wiimote_t* wiimote);

protected:
  void device_update_value() override;

private:
  struct wiimote_t* m_wiimote{};
};

class led_parameter : public device_parameter
{

public:
  led_parameter(
      ossia::net::node_base& node, struct wiimote_t* wiimote, const uint8_t led);

  ~led_parameter();

protected:
  void device_update_value() override;

private:
  struct wiimote_t* m_wiimote{};
  const uint8_t m_led{};
  static ossia::hash_map<wiimote_t*, uint8_t> m_led_mask;
};
}
