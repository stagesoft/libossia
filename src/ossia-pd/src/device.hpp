#pragma once
#include "device_base.hpp"
#include "m_pd.h" // for post()

namespace ossia::pd
{

namespace Protocol_Settings
{
struct minuit
{
  std::string remoteip{"localhost"};
  unsigned int remoteport = 13579;
  unsigned int localport = 9998;
};

struct oscquery
{
  unsigned int oscport = 9999;
  unsigned int wsport = 5678;
};

struct osc
{
  std::string remoteip{"localhost"};
  unsigned int remoteport = 9997;
  unsigned int localport = 9996;
};

static void print_protocol_help()
{
  post("expose <protocol> <args> ...");
  post("Available protocols (case sensitive): Minuit, oscquery, osc");
  post("Protocols parameters :");
  post(
      "Minuit <remoteip> <remoteport> <localport> :\n"
      "\tremoteip (symbol): ip of target device\n"
      "\tremoteport (float): port on which packet should be send\n"
      "\tlocalport (float): port to which this device is listening\n"
      "\tdefault sending on port 13579, listening on 9998");
  post(
      "oscquery <oscport> <wsport> :\n"
      "\toscport (float) : port on which osc packet are sent\n"
      "\twsport (float) : WebSocket port on which distant application will "
      "connect.\n"
      "\tdefault ports: OSC 9999, WebSocket 5678");
  post(
      "osc <remoteip> <remoteport> <localpoort>\n"
      "\tremoteip (symbol): ip of target device\n"
      "\tremoteport (float): port on which packet should be send\n"
      "\tlocalport (port): port this device is listening.\n"
      "\tdefault sending on port 9997, listening on 9996");
}
}

class device : public device_base
{
public:
  device();

  using is_device = std::true_type;

  static void register_children(device* x);
  void unregister_children();
  static void loadbang(device* x, t_float type);

  std::vector<std::vector<t_atom>> m_protocols{};

  static void* create(t_symbol* name, int argc, t_atom* argv);
  static void destroy(device* x);
  static void expose(device* x, t_symbol*, int argc, t_atom* argv);
  static void name(device* x, t_symbol*, int argc, t_atom* argv);
  static void get_mess_cb(device* x, t_symbol* s);
  static void get_protocols(device* x);
  static void get_oscq_clients(device* x);
  static void stop_expose(device* x, float index);
};

} // namespace
