// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <ossia/detail/config.hpp>

#include <ossia/network/generic/generic_device.hpp>
#include <ossia/network/local/local.hpp>
#include <ossia/network/oscquery/oscquery_server.hpp>
#include <ossia/network/phidgets/phidgets_protocol.hpp>

#include "include_catch.hpp"

#include <chrono>
#include <iostream>

using namespace ossia;
using namespace ossia::net;
TEST_CASE("phidget", "phidget")
{
  auto phid = new ossia::phidget_protocol;
  auto prot = new ossia::net::multiplex_protocol;
  ossia::net::generic_device dev{
      std::unique_ptr<ossia::net::multiplex_protocol>(prot), "phidgets"};
  prot->expose_to(std::unique_ptr<ossia::phidget_protocol>(phid));
  prot->expose_to(std::make_unique<ossia::oscquery::oscquery_server_protocol>());

  using namespace std::chrono;
  std::this_thread::sleep_for(2s);
  phid->run_commands();
  std::this_thread::sleep_for(10s);
}
