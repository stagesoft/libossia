#pragma once
#include <ossia/detail/for_each.hpp>
#include <ossia/network/oscquery/detail/attributes.hpp>
#include <ossia/network/oscquery/detail/json_writer_detail.hpp>
#include <ossia/protocols/osc/osc_factory.hpp>
namespace ossia
{
namespace net
{
class network_logger;
}
namespace oscquery
{
class oscquery_server_protocol;
//! Creates the JSON message to send through OSCQuery
class OSSIA_EXPORT json_writer
{
public:
  // Initialisation
  using string_t = rapidjson::StringBuffer;
  using writer_t = ossia::json_writer;

  //! Sends the port at which a server opens its OSC port
  static string_t device_info(int port);

  static string_t query_host_info(
      std::string_view name,
      const std::vector<ossia::net::osc_server_configuration>& osc_port,
      std::string_view local_ip, int ws_port);

  // Format interface
  // Queries
  //! Reply to the namespace query : /foo/bar
  static string_t query_namespace(const ossia::net::node_base& node);

  //! Reply to a query of attributes : /foo/bar?VALUE&RANGE
  template <typename StringVec_T>
  static string_t
  query_attributes(const ossia::net::node_base& node, const StringVec_T& methods)
  {
    string_t buf;
    writer_t wr(buf);

    detail::json_writer_impl p{wr};

    // Here we just write the attributes in the object directly
    wr.StartObject();
    for(auto& method : methods)
    {
      // Here we reply to the query which already has
      // the key in the "oscquery" format so no need to convert
      write_json_key(wr, method);
      p.writeAttribute(node, method);
    }
    wr.EndObject();

    return buf;
  }

  // Listen messages
  static string_t listen(std::string_view address);
  static string_t ignore(std::string_view address);

  // Extensions
  static string_t start_osc_streaming(int local_server_port, int local_sender_port);

  // Update messages
  //! Sent when a new node is added
  static string_t path_added(const ossia::net::node_base& n);

  //! Sent when the content of a node has changed
  static string_t path_changed(const ossia::net::node_base& n);

  //! Sent when a node is being removed
  static string_t path_removed(std::string_view path);

  //! Sent when a node is renamed
  static string_t path_renamed(std::string_view old_path, std::string_view new_path);

  static string_t
  attributes_changed(const ossia::net::node_base& n, std::string_view attribute);

  static string_t attributes_changed(
      const ossia::net::node_base& n, const std::vector<std::string_view>& attributes);

  static string_t paths_added(const std::vector<const ossia::net::node_base*>& vec);

  static string_t paths_changed(const std::vector<const ossia::net::node_base*>& vec);

  static string_t paths_removed(const std::vector<std::string>& vec);

  static string_t attributes_changed_array(
      const std::vector<
          std::pair<const ossia::net::node_base*, std::vector<std::string_view>>>& vec);

private:
  static void
  path_added_impl(detail::json_writer_impl& p, const ossia::net::node_base& n);
  static void
  path_changed_impl(detail::json_writer_impl& p, const ossia::net::node_base& n);
  static void path_removed_impl(writer_t& wr, std::string_view path);
  static void path_renamed_impl(
      json_writer::writer_t& wr, std::string_view path, std::string_view old);
  static void attribute_changed_impl(
      detail::json_writer_impl& p, const ossia::net::node_base& n,
      std::string_view attribute);
  static void attributes_changed_impl(
      detail::json_writer_impl& p, const ossia::net::node_base& n,
      const std::vector<std::string_view>& attributes);
};

}
}
