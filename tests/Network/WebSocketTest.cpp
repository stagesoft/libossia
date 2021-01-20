// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <catch.hpp>
#include <ossia/detail/config.hpp>

#include <ossia/context.hpp>
#include <ossia-qt/websocket-generic-client/ws_generic_client_protocol.hpp>
#include <iostream>
#include <QCoreApplication>
#include <QTimer>
using namespace ossia;

TEST_CASE ("test_websockets", "test_websockets")
{
  int argc{}; char** argv{};
  QCoreApplication app(argc, argv);

  ossia::context context;
  QFile f("testdata/websocket/ws_example.qml");
  f.open(QFile::ReadOnly);

  ossia::net::ws_generic_client_device ws_device{
    std::make_unique<ossia::net::ws_generic_client_protocol>(
          "ws://echo.websocket.org",
          f.readAll()),
        "test" };

  // We have to wait a bit for the event loop to run.
  QTimer t;
  QObject::connect(&t, &QTimer::timeout, [&] () {
    auto node = ossia::net::find_node(ws_device, "/tata/tutu");
    if(node)
    {
      node->get_parameter()->push_value(32.325);
    }
  });
  t.setInterval(1000);
  t.setSingleShot(true);
  t.start();

  QTimer::singleShot(3000, [&] () { app.exit(); });

  app.exec();
}
