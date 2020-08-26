// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#define CATCH_CONFIG_MAIN
#include "../catch/catch.hpp"
#include <ossia/ossia.hpp>
#include <iostream>
#include "Random.hpp"
#include <thread>
#include <atomic>
#include <ossia/network/oscquery/oscquery_mirror.hpp>
#include <ossia/network/oscquery/oscquery_server.hpp>
#include <boost/range/algorithm/find_if.hpp>
static Random r;
using namespace ossia;

std::atomic<int> num_received{0};

TEST_CASE ("test_oscq", "test_oscq")
{
  std::map<int, double> dur;
  for(auto k : {0, 1, 2, 5, 10, 50, 100, 200, 300, 400, 500, 600,
      700, 800, 900, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000,
      20000})
  {
    ossia::net::generic_device src{std::make_unique<ossia::oscquery::oscquery_server_protocol>(1122, 5566), "dev"};
    for(int i = 0; i < k; i++)
    {
      auto n = src.create_child(std::to_string(i));
      n->create_parameter(ossia::val_type::FLOAT);
    }

    {
        REQUIRE(src.children().size() == k);

        auto proto = new ossia::oscquery::oscquery_mirror_protocol("ws://127.0.0.1:5566");
        std::unique_ptr<ossia::net::protocol_base> p(proto);
        ossia::net::generic_device dest{std::move(p), "dev"};

        std::cerr << "K : " << k << std::endl;
        auto t0 = std::chrono::high_resolution_clock::now();
        proto->update(dest);
        auto t1 = std::chrono::high_resolution_clock::now();
        auto tick_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        std::cerr << "WRITE: " << tick_us << std::endl;

        //REQUIRE(dest.children().size() == k);
        std::cerr << "deleting dest " << std::endl;
    }
    std::cerr << "deleting src " << std::endl;
  }
}
