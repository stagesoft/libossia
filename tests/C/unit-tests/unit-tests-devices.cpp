// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <ossia/detail/config.hpp>

#include "catch.hpp"

#include <string>
#include <iostream>

#include <ossia-c/preset/preset.h>
#include <ossia/preset/preset.hpp>
#include <ossia/network/common/path.hpp>
#include <ossia/network/generic/generic_device.hpp>

#include <ossia/ossia.hpp>

TEST_CASE ("Device exceptions") {
  ossia::net::generic_device localDevice{"test"};

  auto rootnode = localDevice.get_root_node().create_child("root");
  auto childnode = rootnode->create_child("child");
  childnode->create_parameter(ossia::val_type::BOOL);

  SECTION("Invalid address: target node has children") {
    ossia::presets::preset preset;
    bool b;
    preset.push_back(std::make_pair("/root", b));

    REQUIRE_THROWS(ossia::presets::apply_preset(localDevice, preset, ossia::presets::keep_arch_off));
  }

  SECTION("Invalid address: keep_arch_type") {
    ossia::presets::preset preset;
    bool b;
    preset.push_back(std::make_pair ("/root/child_that_does_not_exist", b));

    REQUIRE_THROWS(ossia::presets::apply_preset(localDevice, preset, ossia::presets::keep_arch_on));
    REQUIRE_NOTHROW(ossia::presets::apply_preset(localDevice, preset, ossia::presets::keep_arch_off));

  }
}

TEST_CASE ("Building device from preset") {
  ossia::net::generic_device localDevice{"device"};

  ossia::presets::preset p;
  p.emplace_back("/device/a.0/b.0/c.0", 1);
  p.emplace_back("/device/a.0/b.0/c.1", 2);
  p.emplace_back("/device/a.1/b.1/c", 3);
  p.emplace_back("/device/a.1/b.1/d", 4);

  REQUIRE_NOTHROW(ossia::presets::apply_preset(localDevice, p, ossia::presets::keep_arch_off));

  using namespace ossia::presets;
  SECTION("Presence of nodes") {
    REQUIRE(get_node(localDevice, "/device/a.0") != nullptr);
    REQUIRE(get_node(localDevice, "/device/a.0/b.0") != nullptr);
    REQUIRE(get_node(localDevice, "/device/a.0/b.0/c.0") != nullptr);
    REQUIRE(get_node(localDevice, "/device/a.0/b.0/c.1") != nullptr);
    REQUIRE(get_node(localDevice, "/device/a.1/b.1") != nullptr);
    REQUIRE(get_node(localDevice, "/device/a.1/b.1/c") != nullptr);
    REQUIRE(get_node(localDevice, "/device/a.1/b.1/d") != nullptr);
  }

  SECTION("Value of nodes") {
    REQUIRE(get_node(localDevice, "/device")->children().size() == 2);
    REQUIRE(get_node(localDevice, "/device/a.0")->children().size() == 1);
    REQUIRE(get_node(localDevice, "/device/a.0/b.0")->children().size() == 2);
    REQUIRE(get_node(localDevice, "/device/a.0/b.0/c.0")->get_parameter()->value().get<int32_t>() == 1);
    REQUIRE(get_node(localDevice, "/device/a.0/b.0/c.1")->get_parameter()->value().get<int32_t>() == 2);
    REQUIRE(get_node(localDevice, "/device/a.1/b.1")->children().size() == 2);
    REQUIRE(get_node(localDevice, "/device/a.1/b.1/c")->get_parameter()->value().get<int32_t>() == 3);
    REQUIRE(get_node(localDevice, "/device/a.1/b.1/d")->get_parameter()->value().get<int32_t>() == 4);
  }
}

TEST_CASE ("Functions on instances") {
  ossia::net::generic_device localDevice{"device"};

  ossia::presets::instance_functions funcs;
  using namespace ossia::regex_path;
  int number_of_a_nodes = 0;
  int number_of_a_nodes_regex = 0;
  int number_of_b_nodes = 0;
  int number_of_d_nodes = 0;

  funcs.emplace_back(std::regex((device("device") / any_instance("a")).address),
                     [&] (const ossia::net::node_base& node) {
    std::cerr << "Case 1: "
              << ossia::net::address_string_from_node(node)
              << " was inserted" << std::endl;

    number_of_a_nodes++;
  });

  funcs.emplace_back(std::regex(R"(device:/a\.?[0-9]*$)"),
                     [&] (const ossia::net::node_base& node) {
    std::cerr << "Case 3: "
              << ossia::net::address_string_from_node(node)
              << " was inserted" << std::endl;

    number_of_a_nodes_regex++;
  });

  funcs.emplace_back(std::regex((device("device") / any_instance("a") / any_instance("b") / stop()).address),
                     [&] (const ossia::net::node_base& node) {
    std::cerr << "Case 2: "
              << ossia::net::address_string_from_node(node)
              << " was inserted" << std::endl;

    number_of_b_nodes++;
  });

  funcs.emplace_back(std::regex((device("device") / "a.1" / "b.1" / "d").address),
                     [&] (const ossia::net::node_base& node) {
    std::cerr << "Case 3: "
              << ossia::net::address_string_from_node(node)
              << " was inserted" << std::endl;

    number_of_d_nodes++;
  });

  ossia::presets::preset p;
  p.emplace_back("/device/a.0/b.0/c.0", 1);
  p.emplace_back("/device/a.0/b.0/c.1", 2);
  p.emplace_back("/device/a.1/b.1/c", 3);
  p.emplace_back("/device/a.1/b.1/d", 4);

  REQUIRE_NOTHROW(ossia::presets::apply_preset(localDevice, p, ossia::presets::keep_arch_off, funcs));

  REQUIRE(number_of_a_nodes == 2);
  REQUIRE(number_of_a_nodes_regex == 2);
  REQUIRE(number_of_b_nodes == 2);
  REQUIRE(number_of_d_nodes == 1);
}
