#pragma once
#include <ossia/detail/mutex.hpp>
#include <ossia/detail/string_map.hpp>
#include <ossia/network/base/listening.hpp>
#include <ossia/network/base/protocol.hpp>
#include <ossia/network/minuit/detail/minuit_name_table.hpp>
#include <ossia/network/value/value.hpp>
#include <ossia/network/zeroconf/zeroconf.hpp>

#include <atomic>
#include <future>
#include <string>

namespace oscpack
{
class ReceivedMessage;
class IpEndpointName;
}
namespace osc
{
template <typename T>
class sender;
class receiver;
}

namespace ossia::net
{
struct osc_1_0_outbound_stream_visitor;
class generic_device;
class OSSIA_EXPORT minuit_protocol final : public ossia::net::protocol_base
{
private:
  using lock_type = lock_t;

public:
  minuit_protocol(
      const std::string& local_name, const std::string& remote_ip, uint16_t remote_port,
      uint16_t local_port);

  minuit_protocol(const minuit_protocol&) = delete;
  minuit_protocol(minuit_protocol&&) = delete;
  minuit_protocol& operator=(const minuit_protocol&) = delete;
  minuit_protocol& operator=(minuit_protocol&&) = delete;

  ~minuit_protocol();

  void set_device(ossia::net::device_base& dev) override;

  const std::string& get_ip() const;
  minuit_protocol& set_ip(std::string);

  uint16_t get_remote_port() const;
  minuit_protocol& set_remote_port(uint16_t);

  uint16_t get_local_port() const;
  minuit_protocol& set_local_port(uint16_t);

  bool update(ossia::net::node_base& node_base) override;

  bool pull(ossia::net::parameter_base& parameter_base) override;
  bool push_raw(const ossia::net::full_parameter_data& parameter_base) override;
  std::future<void> pull_async(parameter_base&) override;
  void request(ossia::net::parameter_base& parameter_base) override;

  bool
  push(const ossia::net::parameter_base& parameter_base, const ossia::value& v) override;

  bool observe(ossia::net::parameter_base& parameter_base, bool enable) override;
  bool observe_quietly(ossia::net::parameter_base& parameter_base, bool enable) override;

  void namespace_refresh(std::string_view req, const std::string& addr);
  void namespace_refreshed(std::string_view addr);

  void
  get_refresh(std::string_view req, const std::string& addr, std::promise<void>&& p);
  void get_refreshed(std::string_view req);

  osc::sender<osc_1_0_outbound_stream_visitor>& sender() const;
  ossia::minuit::name_table name_table;

private:
  void on_received_message(
      const oscpack::ReceivedMessage& m, const oscpack::IpEndpointName& ip);

  void update_zeroconf();

  std::string m_localName;
  std::string m_ip;
  uint16_t m_remotePort{}; /// the port that a remote device opens
  uint16_t m_localPort{};  /// the port where a remote device sends OSC
                           /// messages to (opened in this library)

  listened_parameters m_listening;

  std::promise<void> m_namespaceFinishedPromise;
  ossia::net::device_base* m_device{};

  mutex_t m_nsRequestMutex;
  ossia::hash_set<std::string> m_nsRequests;

  mutex_t m_getRequestMutex;
  ossia::string_map<std::promise<void>> m_getRequests;

  std::unique_ptr<osc::sender<osc_1_0_outbound_stream_visitor>> m_sender;
  std::unique_ptr<osc::receiver> m_receiver;

  zeroconf_server m_zcServer;

  message_origin_identifier m_id;

  std::atomic<long long> m_lastSentMessage;
  std::atomic<long long> m_lastRecvMessage;
};
}
