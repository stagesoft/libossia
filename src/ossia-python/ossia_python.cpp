// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
namespace pybind11
{
namespace py = pybind11;
}

#include <ossia/detail/logger.hpp>
#include <ossia/network/base/message_queue.hpp>
#include <ossia/network/base/node_attributes.hpp>
#include <ossia/network/base/osc_address.hpp>
#include <ossia/network/common/network_logger.hpp>
#include <ossia/network/common/path.hpp>
#include <ossia/network/context_functions.hpp>
#include <ossia/network/dataspace/dataspace.hpp>
#include <ossia/network/dataspace/dataspace_visitors.hpp>
#include <ossia/network/domain/domain.hpp>
#include <ossia/network/generic/generic_device.hpp>
#include <ossia/network/generic/generic_node.hpp>
#include <ossia/network/generic/generic_parameter.hpp>
#include <ossia/network/local/local.hpp>
#include <ossia/network/minuit/minuit.hpp>
#include <ossia/network/osc/osc.hpp>
#include <ossia/network/oscquery/oscquery_mirror.hpp>
#include <ossia/network/oscquery/oscquery_server.hpp>
#include <ossia/preset/preset.hpp>
#include <ossia/protocols/midi/midi.hpp>

#include <pybind11/functional.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <Python.h>

#include <string_view>

namespace py = pybind11;

// Custom exception classes for ossia-python
class OssiaError : public std::runtime_error {
public:
    explicit OssiaError(const std::string& msg) : std::runtime_error(msg) {}
};

class OssiaDeviceError : public OssiaError {
public:
    explicit OssiaDeviceError(const std::string& msg) : OssiaError("Device error: " + msg) {}
};

class OssiaNetworkError : public OssiaError {
public:
    explicit OssiaNetworkError(const std::string& msg) : OssiaError("Network error: " + msg) {}
};

class OssiaParameterError : public OssiaError {
public:
    explicit OssiaParameterError(const std::string& msg) : OssiaError("Parameter error: " + msg) {}
};

class OssiaPresetError : public OssiaError {
public:
    explicit OssiaPresetError(const std::string& msg) : OssiaError("Preset error: " + msg) {}
};

// Exception context utilities for enhanced error messages
struct ExceptionContext {
    std::string operation;      // e.g., "create_oscquery_server"
    std::string object_type;    // e.g., "LocalDevice"
    std::string object_name;    // e.g., device name
    std::map<std::string, std::string> parameters; // operation-specific params

    std::string format_message(const std::string& base_error) const {
        std::ostringstream oss;
        oss << operation;
        if (!object_type.empty()) oss << " on " << object_type;
        if (!object_name.empty()) oss << " '" << object_name << "'";
        oss << ": " << base_error;

        if (!parameters.empty()) {
            oss << " (";
            bool first = true;
            for (const auto& [key, value] : parameters) {
                if (!first) oss << ", ";
                oss << key << "=" << value;
                first = false;
            }
            oss << ")";
        }
        return oss.str();
    }
};

// Safe wrapper function template for exception handling
template<typename Func>
auto safe_call(Func&& func, const std::string& context = "") {
    try {
        return func();
    } catch (const std::exception& e) {
        std::string msg = context.empty() ? e.what() : context + ": " + e.what();
        throw OssiaError(msg);
    } catch (...) {
        std::string msg = context.empty() ? "Unknown error occurred" : context + ": Unknown error occurred";
        throw OssiaError(msg);
    }
}

// Safe callback wrapper for exception barriers in async operations
void safe_callback_wrapper(const std::function<void()>& callback) {
    try {
        callback();
    } catch (const std::exception& e) {
        // Log the error but don't propagate to avoid crashing
        ossia::logger().error("Exception in callback: {}", e.what());
    } catch (...) {
        ossia::logger().error("Unknown exception in callback");
    }
}

namespace ossia {
  namespace python {

/**
 * @brief To cast python value into OSSIA value
 *
 */
struct to_python_value
{
  py::object operator()(const ossia::impulse& i) const { return py::none{}; }

  template <typename T>
  py::object operator()(const T& t) const
  {
    return py::cast(t);
  }

  py::object operator()(const std::vector<ossia::value>& v) const
  {
    std::vector<py::object> vec;
    vec.reserve(v.size());

    for(const auto& i : v)
      vec.push_back(i.apply(to_python_value{}));

    return py::cast(vec);
  }

  py::object operator()() { return py::none{}; }
};

ossia::value from_python_value(PyObject* source)
{
  ossia::value returned_value;

  PyObject* tmp = nullptr;
  if(PyNumber_Check(source))
  {
    if(PyBool_Check(source))
      returned_value = (source == Py_True);
#if PY_MAJOR_VERSION < 3
    else if(PyInt_Check(source))
      returned_value = (int)PyInt_AsLong(source);
#endif
    else if(PyLong_Check(source))
      returned_value = (int)PyLong_AsLong(source);
    else if(PyFloat_Check(source))
      returned_value = (float)PyFloat_AsDouble(source);
  }
#if PY_MAJOR_VERSION >= 3
  else if(PyUnicode_Check(source))
    returned_value = (std::string)PyUnicode_AsUTF8(source);
#endif
  else if(PyBytes_Check(source))
    returned_value = (std::string)PyBytes_AsString(source);
  else if(PyList_Check(source))
  {
    std::vector<ossia::value> vec;
    int n = PyList_Size(source);
    vec.reserve(n);

    PyObject* iterator = PyObject_GetIter(source);
    PyObject* item;

    while((item = PyIter_Next(iterator)))
    {
      vec.push_back(from_python_value(item));
      Py_DECREF(item);
    }

    returned_value = std::move(vec);
  }
  else if((tmp = PyByteArray_FromObject(source)))
    returned_value = (std::string)PyByteArray_AsString(tmp);

  if(tmp)
    Py_DECREF(tmp);

  return returned_value;
}

}
}

/**
 * @brief Local device class
 *
 * A local device is required to build any OSSIA network
 */
class ossia_local_device
{
  ossia::net::generic_device m_device;
  ossia::net::local_protocol& m_local_protocol;

public:
  /** Constructor
  \param std::string name of the local device */
  ossia_local_device(std::string name)
      : m_device{std::make_unique<ossia::net::local_protocol>(), std::move(name)}
      , m_local_protocol{
            static_cast<ossia::net::local_protocol&>(m_device.get_protocol())}
  {
  }

  operator ossia::net::generic_device&() { return m_device; }
  /** get local device name
  \return std::string */
  std::string get_name() { return m_device.get_name(); }

  /** Make the local device able to handle oscquery request
  \param int port where OSC requests have to be sent by any remote client to
  deal with the local device
  \param int port where WebSocket requests have to be sent by any remote client
  to deal with the local device
  \param bool enable protocol logging
  \return bool */
  bool create_oscquery_server(int osc_port, int ws_port, bool log = false)
  {
    ExceptionContext ctx;
    ctx.operation = "create_oscquery_server";
    ctx.object_type = "LocalDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["osc_port"] = std::to_string(osc_port);
    ctx.parameters["ws_port"] = std::to_string(ws_port);

    try
    {
      m_local_protocol.expose_to(
          std::make_unique<ossia::oscquery::oscquery_server_protocol>(
              osc_port, ws_port));

      if(log)
      {
        ossia::net::network_logger logger;

        logger.inbound_logger = spdlog::stderr_logger_mt("oscquery input");
        logger.inbound_logger->set_pattern("oscquery input: %v");
        logger.inbound_logger->set_level(spdlog::level::info);

        logger.outbound_logger = spdlog::stderr_logger_mt("oscquery output");
        logger.outbound_logger->set_pattern("oscquery output: %v");
        logger.outbound_logger->set_level(spdlog::level::info);

        // attach the logger to the OSCQuery Server protocol only
        for(const auto& p : m_local_protocol.get_protocols())
        {
          try
          {
            ossia::oscquery::oscquery_server_protocol& oscquery_server
                = dynamic_cast<ossia::oscquery::oscquery_server_protocol&>(*p);

            oscquery_server.set_logger(std::move(logger));
            break;
          }
          catch(std::exception& e)
          {
            continue;
          }
        }
      }

      return true;
    }
    catch (const std::exception& e)
    {
      throw OssiaNetworkError(ctx.format_message(e.what()));
    }
    catch(...)
    {
      throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
    }
  }

  /** Make the local device able to handle osc request and emit osc message
  \param int port where osc messages have to be sent to be catch by a remote
  client to listen to the local device
  \param int port where OSC requests have to be sent by any remote client to
  deal with the local device
  \param bool enable protocol logging
  \return bool */
  bool
  create_osc_server(std::string ip, int remote_port, int local_port, bool log = false)
  {
    ExceptionContext ctx;
    ctx.operation = "create_osc_server";
    ctx.object_type = "LocalDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["ip"] = ip;
    ctx.parameters["remote_port"] = std::to_string(remote_port);
    ctx.parameters["local_port"] = std::to_string(local_port);

    try
    {
      m_local_protocol.expose_to(std::make_unique<ossia::net::osc_protocol>(
          ip, remote_port, local_port, m_device.get_name()));

      if(log)
      {
        ossia::net::network_logger logger;

        logger.inbound_logger = spdlog::stderr_logger_mt("osc input");
        logger.inbound_logger->set_pattern("osc input: %v");
        logger.inbound_logger->set_level(spdlog::level::info);

        logger.outbound_logger = spdlog::stderr_logger_mt("osc output");
        logger.outbound_logger->set_pattern("osc output: %v");
        logger.outbound_logger->set_level(spdlog::level::info);

        // attach the logger to the OSC protocol only
        for(const auto& p : m_local_protocol.get_protocols())
        {
          try
          {
            ossia::net::osc_protocol& osc_server
                = dynamic_cast<ossia::net::osc_protocol&>(*p);

            osc_server.set_logger(std::move(logger));
            break;
          }
          catch(std::exception& e)
          {
            continue;
          }
        }
      }

      return true;
    }
    catch (const std::exception& e)
    {
      throw OssiaNetworkError(ctx.format_message(e.what()));
    }
    catch (...)
    {
      throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
    }
  }

  bool create_minuit_server(
      std::string local_name, std::string ip, int remote_port, int local_port,
      bool log = false)
  {
    ExceptionContext ctx;
    ctx.operation = "create_minuit_server";
    ctx.object_type = "LocalDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["local_name"] = local_name;
    ctx.parameters["ip"] = ip;
    ctx.parameters["remote_port"] = std::to_string(remote_port);
    ctx.parameters["local_port"] = std::to_string(local_port);

    try
    {
      auto proto = std::make_unique<ossia::net::minuit_protocol>(
          local_name, ip, remote_port, local_port);

      if(log)
      {
        ossia::net::network_logger logger;

        logger.inbound_logger = spdlog::stderr_logger_mt("minuit input");
        logger.inbound_logger->set_pattern("minuit input: %v");
        logger.inbound_logger->set_level(spdlog::level::info);

        logger.outbound_logger = spdlog::stderr_logger_mt("minuit output");
        logger.outbound_logger->set_pattern("minuit output: %v");
        logger.outbound_logger->set_level(spdlog::level::info);

        proto->set_logger(std::move(logger));
      }

      m_local_protocol.expose_to(std::move(proto));
      return true;
    }
    catch (const std::exception& e)
    {
      throw OssiaNetworkError(ctx.format_message(e.what()));
    }
    catch (...)
    {
      throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* add_node(const std::string& address)
  {
    ExceptionContext ctx;
    ctx.operation = "add_node";
    ctx.object_type = "LocalDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["address"] = address;

    try
    {
      return &ossia::net::find_or_create_node(m_device.get_root_node(), address);
    }
    catch (const std::exception& e)
    {
      throw OssiaParameterError(ctx.format_message(e.what()));
    }
    catch (...)
    {
      throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* find_node(const std::string& address)
  {
    ExceptionContext ctx;
    ctx.operation = "find_node";
    ctx.object_type = "LocalDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["address"] = address;

    try
    {
      return ossia::net::find_node(m_device.get_root_node(), address);
    }
    catch (const std::exception& e)
    {
      throw OssiaParameterError(ctx.format_message(e.what()));
    }
    catch (...)
    {
      throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* get_root_node() { return &m_device.get_root_node(); }
};

/**
 * @brief OSCQuery device class
 *
 * An OSCQuery device is required to deal with a remote application using
 * OSCQuery protocol
 */
class ossia_oscquery_device
{
  ossia::net::generic_device m_device;
  ossia::oscquery::oscquery_mirror_protocol& m_oscquery_protocol;

public:
  ossia_oscquery_device(
      std::string name, std::string host, uint16_t local_osc_port)
      : m_device{[&]() -> ossia::net::generic_device {
          ExceptionContext ctx;
          ctx.operation = "constructor";
          ctx.object_type = "OSCQueryDevice";
          ctx.object_name = name;
          ctx.parameters["host"] = host;
          ctx.parameters["local_osc_port"] = std::to_string(local_osc_port);

          try {
            return ossia::net::generic_device{
              std::make_unique<ossia::oscquery::oscquery_mirror_protocol>(
                host, local_osc_port),
              std::move(name)
            };
          } catch (const std::exception& e) {
            throw OssiaNetworkError(ctx.format_message(e.what()));
          } catch (...) {
            throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
          }
        }()}
      , m_oscquery_protocol{
            static_cast<ossia::oscquery::oscquery_mirror_protocol&>(
                m_device.get_protocol())}
  {
  }

  operator ossia::net::generic_device&() { return m_device; }

  bool update()
  {
    ExceptionContext ctx;
    ctx.operation = "update";
    ctx.object_type = "OSCQueryDevice";
    ctx.object_name = m_device.get_name();

    try {
      return m_oscquery_protocol.update(m_device.get_root_node());
    } catch (const std::exception& e) {
      throw OssiaNetworkError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* find_node(const std::string& address)
  {
    ExceptionContext ctx;
    ctx.operation = "find_node";
    ctx.object_type = "OSCQueryDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["address"] = address;

    try {
      return ossia::net::find_node(m_device.get_root_node(), address);
    } catch (const std::exception& e) {
      throw OssiaParameterError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* get_root_node() { return &m_device.get_root_node(); }
};

/**
 * @brief Minuit device class
 *
 * A Minuit device is required to deal with a remote application using
 * Minuit protocol
 */
class ossia_minuit_device
{
  ossia::net::generic_device m_device;
  ossia::net::minuit_protocol& m_protocol;

public:
  ossia_minuit_device(
      std::string name, std::string host, uint16_t remote_port, uint16_t local_port)
      : m_device{[&]() -> ossia::net::generic_device {
          ExceptionContext ctx;
          ctx.operation = "constructor";
          ctx.object_type = "MinuitDevice";
          ctx.object_name = name;
          ctx.parameters["host"] = host;
          ctx.parameters["remote_port"] = std::to_string(remote_port);
          ctx.parameters["local_port"] = std::to_string(local_port);

          try {
            return ossia::net::generic_device{
              std::make_unique<ossia::net::minuit_protocol>(
                name, host, remote_port, local_port),
              name
            };
          } catch (const std::exception& e) {
            throw OssiaNetworkError(ctx.format_message(e.what()));
          } catch (...) {
            throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
          }
        }()}
      , m_protocol{
            static_cast<ossia::net::minuit_protocol&>(
                m_device.get_protocol())}
  {
  }

  operator ossia::net::generic_device&() { return m_device; }

  bool update()
  {
    ExceptionContext ctx;
    ctx.operation = "update";
    ctx.object_type = "MinuitDevice";
    ctx.object_name = m_device.get_name();

    try {
      return m_protocol.update(m_device.get_root_node());
    } catch (const std::exception& e) {
      throw OssiaNetworkError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* find_node(const std::string& address)
  {
    ExceptionContext ctx;
    ctx.operation = "find_node";
    ctx.object_type = "MinuitDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["address"] = address;

    try {
      return ossia::net::find_node(m_device.get_root_node(), address);
    } catch (const std::exception& e) {
      throw OssiaParameterError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* get_root_node() { return &m_device.get_root_node(); }
};

/**
 * @brief OSC device class
 *
 * An OSC device is required to deal with a remote application using
 * OSC protocol
 */
class ossia_osc_device
{
  ossia::net::generic_device m_device;
  ossia::net::osc_protocol& m_osc_protocol;

public:
  ossia_osc_device(
      std::string name, std::string ip, uint16_t remote_port, uint16_t local_port)
      : m_device{[&]() -> ossia::net::generic_device {
          ExceptionContext ctx;
          ctx.operation = "constructor";
          ctx.object_type = "OSCDevice";
          ctx.object_name = name;
          ctx.parameters["ip"] = ip;
          ctx.parameters["remote_port"] = std::to_string(remote_port);
          ctx.parameters["local_port"] = std::to_string(local_port);

          try {
            return ossia::net::generic_device{
              std::make_unique<ossia::net::osc_protocol>(
                ip, remote_port, local_port),
              std::move(name)
            };
          } catch (const std::exception& e) {
            throw OssiaNetworkError(ctx.format_message(e.what()));
          } catch (...) {
            throw OssiaNetworkError(ctx.format_message("Unknown error occurred"));
          }
        }()}
      , m_osc_protocol{
            static_cast<ossia::net::osc_protocol&>(
                m_device.get_protocol())}
  {
  }

  operator ossia::net::generic_device&() { return m_device; }

  bool get_learning()
  {
    ExceptionContext ctx;
    ctx.operation = "get_learning";
    ctx.object_type = "OSCDevice";
    ctx.object_name = m_device.get_name();

    try {
      return m_osc_protocol.learning();
    } catch (const std::exception& e) {
      throw OssiaDeviceError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaDeviceError(ctx.format_message("Unknown error occurred"));
    }
  }

  void set_learning(bool l)
  {
    ExceptionContext ctx;
    ctx.operation = "set_learning";
    ctx.object_type = "OSCDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["learning"] = l ? "true" : "false";

    try {
      m_osc_protocol.set_learning(l);
    } catch (const std::exception& e) {
      throw OssiaDeviceError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaDeviceError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* add_node(const std::string& address)
  {
    ExceptionContext ctx;
    ctx.operation = "add_node";
    ctx.object_type = "OSCDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["address"] = address;

    try {
      return &ossia::net::find_or_create_node(m_device.get_root_node(), address);
    } catch (const std::exception& e) {
      throw OssiaParameterError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* find_node(const std::string& address)
  {
    ExceptionContext ctx;
    ctx.operation = "find_node";
    ctx.object_type = "OSCDevice";
    ctx.object_name = m_device.get_name();
    ctx.parameters["address"] = address;

    try {
      return ossia::net::find_node(m_device.get_root_node(), address);
    } catch (const std::exception& e) {
      throw OssiaParameterError(ctx.format_message(e.what()));
    } catch (...) {
      throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
    }
  }

  ossia::net::node_base* get_root_node() { return &m_device.get_root_node(); }
};

// /**
//  * @brief MIDI device class
//  *
//  * A MIDI device is required to deal with a controller using
//  * MIDI protocol
//  */
// std::vector<ossia::net::midi::midi_info> list_midi_devices()
// {
//   ExceptionContext ctx;
//   ctx.operation = "list_midi_devices";
//   ctx.object_type = "MidiProtocol";

//   try {
//     ossia::net::midi::midi_protocol midi_protocol{};
//     return midi_protocol.scan();
//   } catch (const std::exception& e) {
//     throw OssiaDeviceError(ctx.format_message(e.what()));
//   } catch (...) {
//     throw OssiaDeviceError(ctx.format_message("Unknown error occurred"));
//   }
// }

// class ossia_midi_device
// {
//   ossia::net::midi::midi_device m_device;
//   ossia::net::midi::midi_protocol& m_protocol;

// public:
//     ossia_midi_device(std::string name, ossia::net::midi::midi_info d)
//     : m_device{[&]() -> ossia::net::midi::midi_device {
//         ExceptionContext ctx;
//         ctx.operation = "constructor";
//         ctx.object_type = "MidiDevice";
//         ctx.object_name = name;
//         ctx.parameters["device"] = d.device;
//         ctx.parameters["port"] = std::to_string(d.port);

//         try {
//           ossia::net::midi::midi_device device{ std::make_unique<ossia::net::midi::midi_protocol>(d) };
//           device.set_name(name);
//           device.create_full_tree();
//           return device;
//         } catch (const std::exception& e) {
//           throw OssiaDeviceError(ctx.format_message(e.what()));
//         } catch (...) {
//           throw OssiaDeviceError(ctx.format_message("Unknown error occurred"));
//         }
//       }()}
//     , m_protocol{ static_cast<ossia::net::midi::midi_protocol&>(m_device.get_protocol()) }
//   {
//   }

//   operator ossia::net::midi::midi_device&() { return m_device; }

//   ossia::net::node_base* find_node(const std::string& address)
//   {
//     ExceptionContext ctx;
//     ctx.operation = "find_node";
//     ctx.object_type = "MidiDevice";
//     ctx.object_name = m_device.get_name();
//     ctx.parameters["address"] = address;

//     try {
//       return ossia::net::find_node(m_device.get_root_node(), address);
//     } catch (const std::exception& e) {
//       throw OssiaParameterError(ctx.format_message(e.what()));
//     } catch (...) {
//       throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
//     }
//   }

//   ossia::net::node_base* get_root_node()
//   {
//     return &m_device.get_root_node();
//   }
// };

class ossia_device_callback : public Nano::Observer
{
  ossia::net::generic_device& m_device;
  std::function<void(const py::object&)> m_on_node_created;
  std::function<void(const py::object&)> m_on_node_renamed;
  std::function<void(const py::object&)> m_on_node_removing;

public:
  ossia_device_callback(
      ossia::net::generic_device& device,
      std::function<void(const py::object&)> on_node_created_clbk,
      std::function<void(const py::object&)> on_node_renamed_clbk,
      std::function<void(const py::object&)> on_node_removing_clbk)
      : m_device{device}
      , m_on_node_created(on_node_created_clbk)
      , m_on_node_renamed(on_node_renamed_clbk)
      , m_on_node_removing(on_node_removing_clbk)
  {
    device.on_node_created.connect<&ossia_device_callback::on_node_created>(*this);
    device.on_node_created.connect<&ossia_device_callback::on_node_renamed>(*this);
    device.on_node_removing.connect<&ossia_device_callback::on_node_removing>(*this);
  }

private:
  void on_node_created(const ossia::net::node_base& node)
  {
    m_on_node_created(py::cast(&node));
  }

  void on_node_renamed(const ossia::net::node_base& node)
  {
    m_on_node_renamed(py::cast(&node));
  }

  void on_node_removing(const ossia::net::node_base& node)
  {
    m_on_node_removing(py::cast(&node));
  }
};

// Exception translator registration function
void register_exception_translators(py::module& m) {
    // Register custom exception classes and export them to Python module namespace
    auto ossiaError = py::register_exception<OssiaError>(m, "OssiaError", PyExc_RuntimeError);
    auto ossiaDeviceError = py::register_exception<OssiaDeviceError>(m, "OssiaDeviceError");
    auto ossiaNetworkError = py::register_exception<OssiaNetworkError>(m, "OssiaNetworkError", PyExc_ConnectionError);
    auto ossiaParameterError = py::register_exception<OssiaParameterError>(m, "OssiaParameterError", PyExc_ValueError);
    auto ossiaPresetError = py::register_exception<OssiaPresetError>(m, "OssiaPresetError", PyExc_IOError);

    // Export exception classes to module namespace for direct access
    m.attr("OssiaError") = ossiaError;
    m.attr("OssiaDeviceError") = ossiaDeviceError;
    m.attr("OssiaNetworkError") = ossiaNetworkError;
    m.attr("OssiaParameterError") = ossiaParameterError;
    m.attr("OssiaPresetError") = ossiaPresetError;

    // Register translators for standard C++ exceptions
    py::register_exception_translator([](std::exception_ptr p) {
        try {
            if (p) std::rethrow_exception(p);
        } catch (const std::bad_alloc& e) {
            PyErr_SetString(PyExc_MemoryError, e.what());
        } catch (const std::invalid_argument& e) {
            PyErr_SetString(PyExc_ValueError, e.what());
        } catch (const std::out_of_range& e) {
            PyErr_SetString(PyExc_IndexError, e.what());
        } catch (const std::ios_base::failure& e) {
            PyErr_SetString(PyExc_IOError, e.what());
        } catch (const std::exception& e) {
            PyErr_SetString(PyExc_RuntimeError, e.what());
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError, "Unknown C++ exception occurred");
        }
    });
}

// to get children of a node
PYBIND11_MAKE_OPAQUE(std::vector<ossia::net::node_base*>);

PYBIND11_MODULE(ossia_python, m)
{
  m.doc() = "python binding of ossia library";

  // Register exception translators
  register_exception_translators(m);

  py::class_<ossia_local_device>(m, "LocalDevice")
      .def(py::init<std::string>())
      .def_property_readonly(
          "name", &ossia_local_device::get_name, py::return_value_policy::reference)
      .def_property_readonly(
          "root_node", &ossia_local_device::get_root_node,
          py::return_value_policy::reference)
      .def("create_oscquery_server", &ossia_local_device::create_oscquery_server)
      .def("create_osc_server", &ossia_local_device::create_osc_server)
      .def("create_minuit_server", &ossia_local_device::create_minuit_server)
      .def("add_node", &ossia_local_device::add_node, py::return_value_policy::reference)
      .def(
          "find_node", &ossia_local_device::find_node,
          py::return_value_policy::reference);

  py::class_<ossia_minuit_device>(m, "MinuitDevice")
      .def(py::init<std::string, std::string, uint16_t, uint16_t>())
      .def("update", &ossia_minuit_device::update)
      .def(
          "find_node", &ossia_minuit_device::find_node,
          py::return_value_policy::reference)
      .def_property_readonly(
          "root_node", &ossia_minuit_device::get_root_node,
          py::return_value_policy::reference);

  py::class_<ossia_oscquery_device>(m, "OSCQueryDevice")
      .def(py::init<std::string, std::string, uint16_t>())
      .def("update", &ossia_oscquery_device::update)
      .def(
          "find_node", &ossia_oscquery_device::find_node,
          py::return_value_policy::reference)
      .def_property_readonly(
          "root_node", &ossia_oscquery_device::get_root_node,
          py::return_value_policy::reference);

  py::class_<ossia::net::oscquery_connection_data>(m, "OSCQueryConnectionData")
      .def_readwrite("name", &ossia::net::oscquery_connection_data::name)
      .def_readwrite("host", &ossia::net::oscquery_connection_data::host)
      .def_readwrite("port", &ossia::net::oscquery_connection_data::port);

  m.def("list_oscquery_devices", &ossia::net::list_oscquery_devices);

  py::class_<ossia_osc_device>(m, "OSCDevice")
      .def(py::init<std::string, std::string, uint16_t, uint16_t>())
      .def_property(
          "learning", &ossia_osc_device::get_learning, &ossia_osc_device::set_learning)
      .def("add_node", &ossia_osc_device::add_node, py::return_value_policy::reference)
      .def("find_node", &ossia_osc_device::find_node, py::return_value_policy::reference)
      .def_property_readonly(
          "root_node", &ossia_osc_device::get_root_node,
          py::return_value_policy::reference);


  py::class_<ossia_midi_device>(m, "MidiDevice")
      .def(py::init<ossia_network_context, std::string, ossia::net::midi::midi_info>())
      .def(
          "find_node", &ossia_midi_device::find_node, py::return_value_policy::reference)
      .def_property_readonly(
          "root_node", &ossia_midi_device::get_root_node,
          py::return_value_policy::reference);

  py::class_<ossia::net::midi::midi_info>(m, "MidiInfo")
      .def(py::init())
      .def_readonly("type", &ossia::net::midi::midi_info::type)
      .def_readonly("handle", &ossia::net::midi::midi_info::handle)
      .def_readonly("virtual", &ossia::net::midi::midi_info::is_virtual);

  py::enum_<ossia::net::midi::midi_info::Type>(m, "MidiDeviceType", py::arithmetic())
      .value("Output", ossia::net::midi::midi_info::Type::Output)
      .value("Input", ossia::net::midi::midi_info::Type::Input)
      .export_values();

  py::class_<ossia_device_callback>(m, "DeviceCallback")
      .def(py::init<
           ossia_local_device&, std::function<void(const py::object&)>,
           std::function<void(const py::object&)>,
           std::function<void(const py::object&)>>())
      .def(py::init<
           ossia_oscquery_device&, std::function<void(const py::object&)>,
           std::function<void(const py::object&)>,
           std::function<void(const py::object&)>>())
      .def(py::init<
           ossia_osc_device&, std::function<void(const py::object&)>,
           std::function<void(const py::object&)>,
           std::function<void(const py::object&)>>())
      .def(py::init<
           ossia_minuit_device&, std::function<void(const py::object&)>,
           std::function<void(const py::object&)>,
           std::function<void(const py::object&)>>());

  py::class_<std::vector<ossia::net::node_base*>>(m, "NodeVector")
      .def(py::init<>())
      .def("clear", &std::vector<ossia::net::node_base*>::clear)
      .def("pop_back", &std::vector<ossia::net::node_base*>::pop_back)
      .def(
          "__len__",
          [](const std::vector<ossia::net::node_base*>& v) { return v.size(); })
      .def(
          "__iter__",
          [](std::vector<ossia::net::node_base*>& v) {
    return py::make_iterator(v.begin(), v.end());
          },
          py::keep_alive<0, 1>()) // Keep vector alive while iterator is used
      ;

  py::class_<ossia::net::node_base>(m, "Node")
      .def_property_readonly(
          "parameter", &ossia::net::node_base::get_parameter,
          py::return_value_policy::reference)
      .def_property_readonly("name", &ossia::net::node_base::get_name)
      .def_property(
          "description",
          [](ossia::net::node_base& node) -> ossia::net::description {
            ossia::net::description empty{};
            return ossia::net::get_description(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::net::description v) {
    ossia::net::set_description(node, v);
          })
      .def_property(
          "tags",
          [](ossia::net::node_base& node) -> ossia::net::tags {
            ossia::net::tags empty{};
            return ossia::net::get_tags(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::net::tags v) {
    ossia::net::set_tags(node, v);
          })
      .def_property(
          "priority",
          [](ossia::net::node_base& node) -> ossia::net::priority {
            ossia::net::priority empty{};
            return ossia::net::get_priority(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::net::priority v) {
    ossia::net::set_priority(node, v);
          })
      .def_property(
          "refresh_rate",
          [](ossia::net::node_base& node) -> ossia::net::refresh_rate {
            ossia::net::refresh_rate empty{};
            return ossia::net::get_refresh_rate(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::net::refresh_rate v) {
    ossia::net::set_refresh_rate(node, v);
          })
      .def_property(
          "value_step_size",
          [](ossia::net::node_base& node) -> ossia::net::value_step_size {
            ossia::net::value_step_size empty{};
            return ossia::net::get_value_step_size(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::net::value_step_size v) {
    ossia::net::set_value_step_size(node, v);
          })
      .def_property(
          "extended_type",
          [](ossia::net::node_base& node) -> ossia::extended_type {
            ossia::extended_type empty{};
            return ossia::net::get_extended_type(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::extended_type v) {
    ossia::net::set_extended_type(node, v);
          })
      .def_property(
          "instance_bounds",
          [](ossia::net::node_base& node) -> ossia::net::instance_bounds {
            ossia::net::instance_bounds empty{};
            return ossia::net::get_instance_bounds(node).value_or(empty);
          },
          [](ossia::net::node_base& node, const ossia::net::instance_bounds v) {
    ossia::net::set_instance_bounds(node, v);
          })
      .def_property_readonly(
          "zombie",
          [](ossia::net::node_base& node) -> ossia::net::zombie {
            return ossia::net::get_zombie(node);
          })
      .def_property(
          "critical",
          [](ossia::net::node_base& node) -> ossia::net::critical {
            return ossia::net::get_critical(node);
          },
          [](ossia::net::node_base& node, const ossia::net::critical v) {
    ossia::net::set_critical(node, v);
          })
      .def_property(
          "disabled",
          [](ossia::net::node_base& node) -> ossia::net::disabled {
            return ossia::net::get_disabled(node);
          },
          [](ossia::net::node_base& node, const ossia::net::disabled v) {
    ossia::net::set_disabled(node, v);
          })
      .def_property(
          "hidden",
          [](ossia::net::node_base& node) -> ossia::net::hidden {
            return ossia::net::get_hidden(node);
          },
          [](ossia::net::node_base& node, const ossia::net::hidden v) {
    ossia::net::set_hidden(node, v);
          })
      .def_property(
          "muted",
          [](ossia::net::node_base& node) -> ossia::net::muted {
            return ossia::net::get_muted(node);
          },
          [](ossia::net::node_base& node, const ossia::net::muted v) {
    ossia::net::set_muted(node, v);
          })
      .def(
          "add_node",
          [](ossia::net::node_base& node,
             const std::string& adrs) -> ossia::net::node_base& {
            return ossia::net::find_or_create_node(node, adrs);
          },
          py::return_value_policy::reference)
      .def(
          "create_parameter",
          [](ossia::net::node_base& node, int type) {
            ExceptionContext ctx;
            ctx.operation = "create_parameter";
            ctx.object_type = "Node";
            ctx.object_name = ossia::net::osc_parameter_string(node);
            ctx.parameters["type"] = std::to_string(type);

            try {
              // Validate parameter type
              if (type < 0 || type >= static_cast<int>(ossia::val_type::LIST) + 1) {
                throw OssiaParameterError(ctx.format_message("Invalid parameter type: " + std::to_string(type)));
              }
              
              auto param = node.create_parameter(static_cast<ossia::val_type>(type));
              if (!param) {
                throw OssiaParameterError(ctx.format_message("Failed to create parameter"));
              }
              
              return param;
            } catch (const OssiaParameterError&) {
              throw; // Re-throw our custom exceptions
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          },
          py::return_value_policy::reference)
      .def("children", &ossia::net::node_base::children_copy)
      .def("__str__", [](ossia::net::node_base& node) -> std::string {
        return ossia::net::osc_parameter_string(node);
      });

  py::class_<ossia::net::parameter_base>(m, "Parameter")
      .def_property_readonly(
          "node", &ossia::net::parameter_base::get_node,
          py::return_value_policy::reference)
      .def_property_readonly(
          "callback_count",
          [](ossia::net::parameter_base& addr) -> int { return addr.callback_count(); })
      .def_property(
          "value",
          [](ossia::net::parameter_base& addr) -> py::object {
            ExceptionContext ctx;
            ctx.operation = "get_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              return addr.fetch_value().apply(ossia::python::to_python_value{});
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          },
          [](ossia::net::parameter_base& addr, const py::object& v) {
            ExceptionContext ctx;
            ctx.operation = "set_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              auto ossia_val = ossia::python::from_python_value(v.ptr());
              addr.push_value(ossia_val);
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def_property(
          "default_value",
          [](ossia::net::parameter_base& addr) -> py::object {
            ExceptionContext ctx;
            ctx.operation = "get_default_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              ossia::value empty{};
              return addr.get_default_value().value_or(empty).apply(ossia::python::to_python_value{});
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          },
          [](ossia::net::parameter_base& addr, const py::object& v) {
            ExceptionContext ctx;
            ctx.operation = "set_default_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              auto ossia_val = ossia::python::from_python_value(v.ptr());
              addr.set_default_value(ossia_val);
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def_property(
          "value_type", &ossia::net::parameter_base::get_value_type,
          &ossia::net::parameter_base::set_value_type)
      .def_property(
          "access_mode", &ossia::net::parameter_base::get_access,
          &ossia::net::parameter_base::set_access)
      .def_property(
          "bounding_mode", &ossia::net::parameter_base::get_bounding,
          &ossia::net::parameter_base::set_bounding)
      .def_property(
          "repetition_filter", &ossia::net::parameter_base::get_repetition_filter,
          &ossia::net::parameter_base::set_repetition_filter)
      .def_property(
          "unit",
          [](ossia::net::parameter_base& addr) -> std::string_view {
            return ossia::get_pretty_unit_text(addr.get_unit());
          },
          [](ossia::net::parameter_base& addr, std::string_view u) {
    addr.set_unit(ossia::parse_pretty_unit(u));
          })
      .def_property_readonly(
          "domain", &ossia::net::parameter_base::get_domain,
          py::return_value_policy::reference)
      .def(
          "have_domain",
          [](ossia::net::parameter_base& addr) -> bool {
            return bool(addr.get_domain());
          })
      .def(
          "make_domain",
          [](ossia::net::parameter_base& addr, const py::object& min, const py::object& max) {
            ExceptionContext ctx;
            ctx.operation = "make_domain";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              auto min_val = ossia::python::from_python_value(min.ptr());
              auto max_val = ossia::python::from_python_value(max.ptr());
              
              // Validate that min and max are compatible with parameter type
              auto param_type = addr.get_value_type();
              if (min_val.get_type() != param_type || max_val.get_type() != param_type) {
                throw OssiaParameterError(ctx.format_message("Domain values must match parameter type"));
              }
              
              addr.set_domain(ossia::make_domain(min_val, max_val));
            } catch (const OssiaParameterError&) {
              throw; // Re-throw our custom exceptions
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "make_domain",
          [](ossia::net::parameter_base& addr, const std::vector<py::object>& values) {
            ExceptionContext ctx;
            ctx.operation = "make_domain";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());
            ctx.parameters["values_count"] = std::to_string(values.size());

            try {
              if (values.empty()) {
                throw OssiaParameterError(ctx.format_message("Domain values list cannot be empty"));
              }

              auto dom = ossia::init_domain(addr.get_value_type());
              auto param_type = addr.get_value_type();

              std::vector<ossia::value> vec;
              vec.reserve(values.size());

              for (const auto& v : values) {
                auto ossia_val = ossia::python::from_python_value(v.ptr());
                
                // Validate that each value is compatible with parameter type
                if (ossia_val.get_type() != param_type) {
                  throw OssiaParameterError(ctx.format_message("All domain values must match parameter type"));
                }
                
                vec.push_back(ossia_val);
              }

              ossia::set_values(dom, vec);
              addr.set_domain(dom);
            } catch (const OssiaParameterError&) {
              throw; // Re-throw our custom exceptions
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "apply_domain",
          [](ossia::net::parameter_base& addr) {
            ExceptionContext ctx;
            ctx.operation = "apply_domain";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              if (!addr.get_domain()) {
                throw OssiaParameterError(ctx.format_message("Parameter has no domain to apply"));
              }
              
              addr.push_value(ossia::apply_domain(
                  addr.get_domain(), addr.get_bounding(), addr.fetch_value()));
            } catch (const OssiaParameterError&) {
              throw; // Re-throw our custom exceptions
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def("pull_value", [](ossia::net::parameter_base& addr) {
            ExceptionContext ctx;
            ctx.operation = "pull_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              return addr.pull_value();
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "clone_value",
          [](ossia::net::parameter_base& addr) -> py::object {
            ExceptionContext ctx;
            ctx.operation = "clone_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              return addr.value().apply(ossia::python::to_python_value{});
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "fetch_value",
          [](ossia::net::parameter_base& addr) -> py::object {
            ExceptionContext ctx;
            ctx.operation = "fetch_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              return addr.fetch_value().apply(ossia::python::to_python_value{});
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "push_value", [](ossia::net::parameter_base& addr,
                           const py::object& v) { 
            ExceptionContext ctx;
            ctx.operation = "push_value";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              auto ossia_val = ossia::python::from_python_value(v.ptr());
              addr.push_value(ossia_val);
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "add_callback",
          [](ossia::net::parameter_base& addr,
             std::function<void(const py::object&)> clbk) {
            ExceptionContext ctx;
            ctx.operation = "add_callback";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              addr.add_callback([clbk, ctx] (const auto& val) {
                safe_callback_wrapper([&]() {
                  clbk(val.apply(ossia::python::to_python_value{}));
                });
              });
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def(
          "add_callback_param",
          [](ossia::net::parameter_base& addr,
             std::function<void(ossia::net::node_base&, const py::object&)> clbk) {
            ExceptionContext ctx;
            ctx.operation = "add_callback_param";
            ctx.object_type = "Parameter";
            ctx.object_name = ossia::net::osc_parameter_string(addr.get_node());

            try {
              addr.add_callback([clbk, &addr, ctx] (const ossia::value& val) {
                safe_callback_wrapper([&]() {
                  clbk(addr.get_node(), val.apply(ossia::python::to_python_value{}));
                });
              });
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def("__str__", [](ossia::net::parameter_base& addr) -> std::string {
        return ossia::value_to_pretty_string(addr.value());
      });

  py::enum_<ossia::val_type>(m, "ValueType", py::arithmetic())
      .value("Float", ossia::val_type::FLOAT)
      .value("Int", ossia::val_type::INT)
      .value("Vec2f", ossia::val_type::VEC2F)
      .value("Vec3f", ossia::val_type::VEC3F)
      .value("Vec4f", ossia::val_type::VEC4F)
      .value("Impulse", ossia::val_type::IMPULSE)
      .value("Bool", ossia::val_type::BOOL)
      .value("String", ossia::val_type::STRING)
      .value("List", ossia::val_type::LIST)
      .export_values();

  py::enum_<ossia::access_mode>(m, "AccessMode", py::arithmetic())
      .value("Bi", ossia::access_mode::BI)
      .value("Get", ossia::access_mode::GET)
      .value("Set", ossia::access_mode::SET)
      .export_values();

  py::enum_<ossia::bounding_mode>(m, "BoundingMode", py::arithmetic())
      .value("Free", ossia::bounding_mode::FREE)
      .value("Clip", ossia::bounding_mode::CLIP)
      .value("Wrap", ossia::bounding_mode::WRAP)
      .value("Fold", ossia::bounding_mode::FOLD)
      .value("Low", ossia::bounding_mode::CLAMP_LOW)
      .value("High", ossia::bounding_mode::CLAMP_HIGH)
      .export_values();

  py::enum_<ossia::repetition_filter>(m, "RepetitionFilter", py::arithmetic())
      .value("Off", ossia::repetition_filter::OFF)
      .value("On", ossia::repetition_filter::ON)
      .export_values();

  py::class_<ossia::domain>(m, "Domain")
      .def(py::init())
      .def_property(
          "min",
          [](ossia::domain& d) -> py::object { 
            ExceptionContext ctx;
            ctx.operation = "get_min";
            ctx.object_type = "Domain";

            try {
              return ossia::get_min(d).apply(ossia::python::to_python_value{});
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          },
          [](ossia::domain& d, const py::object& v) {
            ExceptionContext ctx;
            ctx.operation = "set_min";
            ctx.object_type = "Domain";

            try {
              auto ossia_val = ossia::python::from_python_value(v.ptr());
              ossia::set_min(d, ossia_val);
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          })
      .def_property(
          "max",
          [](ossia::domain& d) -> py::object { 
            ExceptionContext ctx;
            ctx.operation = "get_max";
            ctx.object_type = "Domain";

            try {
              return ossia::get_max(d).apply(ossia::python::to_python_value{});
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          },
          [](ossia::domain& d, const py::object& v) {
            ExceptionContext ctx;
            ctx.operation = "set_max";
            ctx.object_type = "Domain";

            try {
              auto ossia_val = ossia::python::from_python_value(v.ptr());
              ossia::set_max(d, ossia_val);
            } catch (const std::exception& e) {
              throw OssiaParameterError(ctx.format_message(e.what()));
            } catch (...) {
              throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
            }
          });

  py::class_<ossia::net::instance_bounds>(m, "InstanceBounds")
      .def(py::init<int32_t, int32_t>())
      .def_readwrite("min", &ossia::net::instance_bounds::min_instances)
      .def_readwrite("max", &ossia::net::instance_bounds::max_instances);

  py::class_<ossia::message_queue>(m, "MessageQueue")
      .def(py::init<ossia_local_device&>())
      .def(py::init<ossia_osc_device&>())
      .def(py::init<ossia_oscquery_device&>())
      .def(py::init<ossia_minuit_device&>())
    //   .def(py::init<ossia_midi_device&>())
      .def("register", [] (ossia::message_queue& mq, ossia::net::parameter_base& p) {
        ExceptionContext ctx;
        ctx.operation = "register";
        ctx.object_type = "MessageQueue";
        ctx.object_name = ossia::net::osc_parameter_string(p.get_node());

        try {
          mq.reg(p);
        } catch (const std::exception& e) {
          throw OssiaParameterError(ctx.format_message(e.what()));
        } catch (...) {
          throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
        }
      })
      .def("unregister", [] (ossia::message_queue& mq, ossia::net::parameter_base& p) {
        ExceptionContext ctx;
        ctx.operation = "unregister";
        ctx.object_type = "MessageQueue";
        ctx.object_name = ossia::net::osc_parameter_string(p.get_node());

        try {
          mq.unreg(p);
        } catch (const std::exception& e) {
          throw OssiaParameterError(ctx.format_message(e.what()));
        } catch (...) {
          throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
        }
      })
      .def("pop", [] (ossia::message_queue& mq) -> py::object {
        ExceptionContext ctx;
        ctx.operation = "pop";
        ctx.object_type = "MessageQueue";

        try {
          ossia::received_value v;
          bool res = mq.try_dequeue(v);
          if (res)
          {
            return py::make_tuple(py::cast(v.address), v.value.apply(ossia::python::to_python_value{}));
          }
          return py::none{};
        } catch (const std::exception& e) {
          throw OssiaParameterError(ctx.format_message(e.what()));
        } catch (...) {
          throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
        }
  });

  py::class_<ossia::global_message_queue>(m, "GlobalMessageQueue")
      .def(py::init<ossia_local_device&>())
      .def(py::init<ossia_osc_device&>())
      .def(py::init<ossia_oscquery_device&>())
      .def(py::init<ossia_minuit_device&>())
    //   .def(py::init<ossia_midi_device&>())
      .def("pop", [] (ossia::global_message_queue& mq) -> py::object {
        ExceptionContext ctx;
        ctx.operation = "pop";
        ctx.object_type = "GlobalMessageQueue";

        try {
          ossia::received_value v;
          bool res = mq.try_dequeue(v);
          if(res)
          {
            return py::make_tuple(py::cast(v.address), v.value.apply(ossia::python::to_python_value{}));
          }
          return py::none{};
        } catch (const std::exception& e) {
          throw OssiaParameterError(ctx.format_message(e.what()));
        } catch (...) {
          throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
        }
        });

  m.def("list_node_pattern",
    [] (const std::vector<py::object>& start_nodes, std::string pattern) -> std::vector<py::object> {
      ExceptionContext ctx;
      ctx.operation = "list_node_pattern";
      ctx.object_type = "NodePattern";
      ctx.parameters["pattern"] = pattern;
      ctx.parameters["node_count"] = std::to_string(start_nodes.size());

      try {
        if (pattern.empty()) {
          throw std::invalid_argument("Pattern cannot be empty");
        }

        std::vector<ossia::net::node_base*> vec;
        vec.reserve(start_nodes.size());
        for (auto node : start_nodes) {
          if (node.is_none()) {
            throw std::invalid_argument("Node cannot be None");
          }
          vec.push_back(node.cast<ossia::net::node_base*>());
        }

        if (auto path = ossia::traversal::make_path(pattern)) {
          ossia::traversal::apply(*path, vec);
        } else {
          throw std::invalid_argument("Invalid pattern syntax");
        }

        std::vector<py::object> res;
        for (auto node : vec)
          res.push_back(py::cast(node));

        return res;
      } catch (const std::exception& e) {
        throw OssiaParameterError(ctx.format_message(e.what()));
      } catch (...) {
        throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
      }
    });

  m.def("create_node_pattern",
    [] (const py::object& start_node, std::string pattern) -> std::vector<py::object> {
      ExceptionContext ctx;
      ctx.operation = "create_node_pattern";
      ctx.object_type = "NodePattern";
      ctx.parameters["pattern"] = pattern;

      try {
        if (pattern.empty()) {
          throw std::invalid_argument("Pattern cannot be empty");
        }

        if (start_node.is_none()) {
          throw std::invalid_argument("Start node cannot be None");
        }

        std::vector<ossia::net::node_base*> vec = ossia::net::create_nodes(start_node.cast<ossia::net::node_base&>(), pattern);

        std::vector<py::object> res;
        for (auto node : vec)
          res.push_back(py::cast(node));

        return res;
      } catch (const std::exception& e) {
        throw OssiaParameterError(ctx.format_message(e.what()));
      } catch (...) {
        throw OssiaParameterError(ctx.format_message("Unknown error occurred"));
      }
    });

  m.def("save_preset", [] (const py::object& start_node, std::string filename, std::string name) -> void {
      ExceptionContext ctx;
      ctx.operation = "save_preset";
      ctx.object_type = "Preset";
      ctx.parameters["filename"] = filename;
      ctx.parameters["name"] = name;

      try {
        auto preset = ossia::presets::make_preset(start_node.cast<ossia::net::node_base&>());
        auto json = ossia::presets::write_json(name, preset);
        ossia::presets::write_file(json, filename);
      } catch (const std::ios_base::failure& e) {
        throw OssiaPresetError(ctx.format_message("File operation failed: " + std::string(e.what())));
      } catch (const std::exception& e) {
        throw OssiaPresetError(ctx.format_message(e.what()));
      } catch (...) {
        throw OssiaPresetError(ctx.format_message("Unknown error occurred"));
      }
    });

  m.def("load_preset", [] (const py::object& start_node, std::string filename) -> void {
      ExceptionContext ctx;
      ctx.operation = "load_preset";
      ctx.object_type = "Preset";
      ctx.parameters["filename"] = filename;

      try {
        auto json = ossia::presets::read_file(filename);
        auto preset = ossia::presets::read_json(json);
        ossia::presets::apply_preset(start_node.cast<ossia::net::node_base&>(), preset,  ossia::presets::keep_arch_on, {}, true);
      } catch (const std::ios_base::failure& e) {
        throw OssiaPresetError(ctx.format_message("File operation failed: " + std::string(e.what())));
      } catch (const std::exception& e) {
        throw OssiaPresetError(ctx.format_message(e.what()));
      } catch (...) {
        throw OssiaPresetError(ctx.format_message("Unknown error occurred"));
      }
    });
}
