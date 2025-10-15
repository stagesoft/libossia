// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "ossia_utils.hpp"

#include <ossia/detail/config.hpp>

#include <ossia/network/base/message_queue.hpp>
#include <ossia/network/base/node_functions.hpp>
#include <ossia/network/dataspace/dataspace_visitors.hpp>

#include <readerwriterqueue.h>

extern "C" {

ossia_node_t ossia_parameter_get_node(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_node_t {
    if(!address)
    {
      ossia_log_error("ossia_parameter_get_node: address is null");
      return nullptr;
    }

    return convert(&convert_parameter(address)->get_node());
  });
}

void ossia_parameter_set_access_mode(ossia_parameter_t address, ossia_access_mode am)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_set_access_mode: address is null");
      return;
    }

    convert_parameter(address)->set_access(convert(am));
  });
}

ossia_access_mode ossia_parameter_get_access_mode(ossia_parameter_t address)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_get_access_mode: address is null");
      return BI;
    }

    return convert(convert_parameter(address)->get_access());
  });
}

void ossia_parameter_set_bounding_mode(ossia_parameter_t address, ossia_bounding_mode am)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_set_bounding_mode: address is null");
      return;
    }

    convert_parameter(address)->set_bounding(convert(am));
  });
}

ossia_bounding_mode ossia_parameter_get_bounding_mode(ossia_parameter_t address)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_get_bounding_mode: address is null");
      return FREE;
    }

    return convert(convert_parameter(address)->get_bounding());
  });
}

void ossia_parameter_set_domain(ossia_parameter_t address, ossia_domain_t domain)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_set_domain: address is null");
      return;
    }
    if(!domain)
    {
      ossia_log_error("ossia_parameter_set_domain: domain is null");
      return;
    }

    convert_parameter(address)->set_domain(domain->domain);
  });
}

ossia_domain_t ossia_parameter_get_domain(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_domain_t {
    if(!address)
    {
      ossia_log_error("ossia_parameter_get_domain: address is null");
      return nullptr;
    }

    return new ossia_domain{convert_parameter(address)->get_domain()};
  });
}

void ossia_parameter_set_value(ossia_parameter_t address, ossia_value_t value)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_set_value: address is null");
      return;
    }
    if(!value)
    {
      ossia_log_error("ossia_parameter_set_value: value is null");
      return;
    }

    convert_parameter(address)->set_value(value->value);
  });
}

ossia_value_t ossia_parameter_get_value(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_value_t {
    if(!address)
    {
      ossia_log_error("ossia_parameter_get_value: address is null");
      return nullptr;
    }

    return convert(convert_parameter(address)->value());
  });
}

int ossia_parameter_to_int(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> int {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_int: address is null");
      return {};
    }

    return convert_parameter(address)->value().get<int>();
  });
}

float ossia_parameter_to_float(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> float {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_float: address is null");
      return {};
    }

    return convert_parameter(address)->value().get<float>();
  });
}

ossia_vec2f ossia_parameter_to_2f(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_vec2f {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_2f: address is null");
      return {};
    }

    auto res = convert_parameter(address)->value().get<ossia::vec2f>();
    return {res[0], res[1]};
  });
}

ossia_vec3f ossia_parameter_to_3f(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_vec3f {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_3f: address is null");
      return {};
    }

    auto res = convert_parameter(address)->value().get<ossia::vec3f>();
    return {res[0], res[1], res[2]};
  });
}

ossia_vec4f ossia_parameter_to_4f(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_vec4f {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_4f: address is null");
      return {};
    }

    auto res = convert_parameter(address)->value().get<ossia::vec4f>();
    return {res[0], res[1], res[2], res[3]};
  });
}

int ossia_parameter_to_bool(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> int {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_bool: address is null");
      return {};
    }

    return convert_parameter(address)->value().get<bool>();
  });
}

void ossia_parameter_to_byte_array(ossia_parameter_t address, char** out, size_t* size)
{
  return safe_function(__func__, [=]() -> void {
    if(!address || !out || !size)
    {
      ossia_log_error("ossia_parameter_to_byte_array: a parameter is null");
      if(out)
        *out = nullptr;
      if(size)
        *size = 0;
      return;
    }
    else
    {
      const auto& val = convert_parameter(address)->value();
      if(auto casted_val = val.target<std::string>())
        copy_bytes(*casted_val, out, size);
      return;
    }
  });
}

const char* ossia_parameter_to_string(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> const char* {
    if(!address)
    {
      ossia_log_error("ossia_parameter_to_string: address is null");
      return {};
    }

    const auto& val = convert_parameter(address)->value();
    if(auto casted_val = val.target<std::string>())
      return copy_string(*casted_val);
    else
      return nullptr;
  });
}

void ossia_parameter_to_list(
    ossia_parameter_t parameter, ossia_value_t** out, size_t* size)
{
  return safe_function(__func__, [=]() -> void {
    if(!parameter || !out || !size)
    {
      ossia_log_error("ossia_parameter_to_list: a parameter is null");
      if(out)
        *out = nullptr;
      if(size)
        *size = 0;
      return;
    }
    else
    {
      const auto& val = convert_parameter(parameter)->value();
      if(auto casted_val = val.target<std::vector<ossia::value>>())
      {
        size_t N = casted_val->size();
        auto ptr = new ossia_value_t[N];
        *size = N;
        for(size_t i = 0; i < N; i++)
        {
          ptr[i] = convert((*casted_val)[i]);
        }
        *out = ptr;
      }
      return;
    }
  });
}

void ossia_parameter_to_fn(ossia_parameter_t parameter, float** out, size_t* size)
{
  return safe_function(__func__, [=]() -> void {
    if(!parameter || !out || !size)
    {
      ossia_log_error("ossia_parameter_to_fn: a parameter is null");
      if(out)
        *out = nullptr;
      if(size)
        *size = 0;
      return;
    }
    else
    {
      const auto& val = convert_parameter(parameter)->value();
      if(auto casted_val = val.target<std::vector<ossia::value>>())
      {
        const size_t N = casted_val->size();
        auto ptr = new float[N];
        *size = N;
        for(size_t i = 0; i < N; i++)
        {
          ptr[i] = (*casted_val)[i].get<float>();
        }
        *out = ptr;
      }
      return;
    }
  });
}

void ossia_parameter_to_in(ossia_parameter_t parameter, int** out, size_t* size)
{
  return safe_function(__func__, [=]() -> void {
    if(!parameter || !out || !size)
    {
      ossia_log_error("ossia_parameter_to_fn: a parameter is null");
      if(out)
        *out = nullptr;
      if(size)
        *size = 0;
      return;
    }
    else
    {
      const auto& val = convert_parameter(parameter)->value();
      if(auto casted_val = val.target<std::vector<ossia::value>>())
      {
        const size_t N = casted_val->size();
        auto ptr = new int[N];
        *size = N;
        for(size_t i = 0; i < N; i++)
        {
          ptr[i] = (*casted_val)[i].get<int>();
        }
        *out = ptr;
      }
      return;
    }
  });
}
void ossia_parameter_push_value(ossia_parameter_t address, ossia_value_t value)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_value: address is null");
      return;
    }
    if(!value)
    {
      ossia_log_error("ossia_parameter_push_value: value is null");
      return;
    }

    convert_parameter(address)->push_value(value->value);
  });
}

void ossia_parameter_push_impulse(ossia_parameter_t address)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_impulse: address is null");
      return;
    }

    convert_parameter(address)->push_value(ossia::impulse{});
  });
}
void ossia_parameter_push_i(ossia_parameter_t address, int i)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_i: address is null");
      return;
    }

    convert_parameter(address)->push_value(i);
  });
}
void ossia_parameter_push_b(ossia_parameter_t address, int i)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_b: address is null");
      return;
    }

    convert_parameter(address)->push_value(bool(i != 0));
  });
}
void ossia_parameter_push_f(ossia_parameter_t address, float f)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_f: address is null");
      return;
    }

    convert_parameter(address)->push_value(f);
  });
}
void ossia_parameter_push_2f(ossia_parameter_t address, float f1, float f2)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_2f: address is null");
      return;
    }

    convert_parameter(address)->push_value(ossia::make_vec(f1, f2));
  });
}
void ossia_parameter_push_3f(ossia_parameter_t address, float f1, float f2, float f3)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_3f: address is null");
      return;
    }

    convert_parameter(address)->push_value(ossia::make_vec(f1, f2, f3));
  });
}
void ossia_parameter_push_4f(
    ossia_parameter_t address, float f1, float f2, float f3, float f4)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_4f: address is null");
      return;
    }

    convert_parameter(address)->push_value(ossia::make_vec(f1, f2, f3, f4));
  });
}
void ossia_parameter_push_c(ossia_parameter_t address, char c)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_c: address is null");
      return;
    }

    convert_parameter(address)->push_value(c);
  });
}
void ossia_parameter_push_s(ossia_parameter_t address, const char* s)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_s: address is null");
      return;
    }

    if(s)
      convert_parameter(address)->push_value(std::string(s));
    else
      convert_parameter(address)->push_value(std::string());
  });
}

void ossia_parameter_push_in(ossia_parameter_t address, const int* in, size_t sz)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_in: address is null");
      return;
    }
    if(!in)
    {
      ossia_log_error("ossia_parameter_push_in: value is null");
      return;
    }

    std::vector<ossia::value> v;
    v.resize(sz);
    for(size_t i = 0; i < sz; i++)
    {
      v[i] = in[i];
    }
    convert_parameter(address)->push_value(std::move(v));
  });
}
void ossia_parameter_push_fn(ossia_parameter_t address, const float* in, size_t sz)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_fn: address is null");
      return;
    }
    if(!in)
    {
      ossia_log_error("ossia_parameter_push_fn: value is null");
      return;
    }

    std::vector<ossia::value> v;
    v.resize(sz);
    for(size_t i = 0; i < sz; i++)
    {
      v[i] = in[i];
    }
    convert_parameter(address)->push_value(std::move(v));
  });
}
void ossia_parameter_push_cn(ossia_parameter_t address, const char* in, size_t sz)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_cn: address is null");
      return;
    }
    if(!in)
    {
      ossia_log_error("ossia_parameter_push_cn: value is null");
      return;
    }

    convert_parameter(address)->push_value(std::string(in, sz));
  });
}

void ossia_parameter_push_list(
    ossia_parameter_t address, const ossia_value_t* in, size_t sz)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_push_list: address is null");
      return;
    }
    if(!in)
    {
      ossia_log_error("ossia_parameter_push_list: value is null");
      return;
    }

    std::vector<ossia::value> v;
    v.resize(sz);
    for(size_t i = 0; i < sz; i++)
    {
      v[i] = in[i]->value;
    }
    convert_parameter(address)->push_value(std::move(v));
  });
}
ossia_value_t ossia_parameter_fetch_value(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> ossia_value_t {
    if(!address)
    {
      ossia_log_error("ossia_parameter_fetch_value: address is null");
      return nullptr;
    }

    return convert(convert_parameter(address)->fetch_value());
  });
}

void ossia_parameter_set_listening(ossia_parameter_t address, int listening)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_set_listening: address is null");
      return;
    }

    auto addr = convert_parameter(address);
    if(listening)
    {
      auto cb_it = addr->get_node().get_attribute(ossia::string_view("_impl_callback"));
      auto cb_ptr = ossia::any_cast<ossia::net::parameter_base::callback_index>(&cb_it);
      if(cb_ptr)
      {
        addr->remove_callback(*cb_ptr);
      }
    }
    else
    {
      auto it = addr->add_callback([](const ossia::value&) {});
      ossia::set_attribute(
          (ossia::extended_attributes&)addr->get_node(),
          ossia::string_view("_impl_callback"), it);
    }
  });
}
ossia_value_callback_idx_t ossia_parameter_add_callback(
    ossia_parameter_t address, ossia_value_callback_t callback, void* ctx)
{
  return safe_function(__func__, [=]() -> ossia_value_callback_idx_t {
    if(!address)
    {
      ossia_log_error("ossia_parameter_add_callback: address is null");
      return nullptr;
    }
    if(!callback)
    {
      ossia_log_error("ossia_parameter_add_callback: callback is null");
      return nullptr;
    }

    return new ossia_value_callback_index{convert_parameter(address)->add_callback(
        [=](const ossia::value& val) { callback(ctx, convert(val)); })};
  });
}

void ossia_parameter_push_callback(
    ossia_parameter_t address, ossia_value_callback_t callback, void* ctx)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_add_callback: address is null");
      return;
    }
    if(!callback)
    {
      ossia_log_error("ossia_parameter_add_callback: callback is null");
      return;
    }

    convert_parameter(address)->add_callback(
        [=](const ossia::value& val) { callback(ctx, convert(val)); });
  });
}

void ossia_parameter_free_callback_idx(ossia_value_callback_idx_t cb)
{
  delete cb;
}

void ossia_parameter_remove_callback(
    ossia_parameter_t address, ossia_value_callback_idx_t index)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_parameter_remove_callback: address is null");
      return;
    }
    if(!index)
    {
      ossia_log_error("ossia_parameter_remove_callback: index is null");
      return;
    }

    convert_parameter(address)->remove_callback(index->it);
    delete index;
  });
}

void ossia_parameter_set_unit(ossia_parameter_t address, const char* unit)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_node_set_unit: address is null");
      return;
    }

    auto u = ossia::parse_pretty_unit(unit);
    convert_parameter(address)->set_unit(u);
  });
}

const char* ossia_parameter_get_unit(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> const char* {
    if(!address)
    {
      ossia_log_error("ossia_node_get_unit: address is null");
      return nullptr;
    }

    return ossia::get_pretty_unit_text(convert_parameter(address)->get_unit()).data();
  });
}

void ossia_parameter_set_disabled(ossia_parameter_t address, int disabled)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_node_set_disabled: address is null");
      return;
    }

    convert_parameter(address)->set_disabled(disabled != 0);
  });
}

int ossia_parameter_get_disabled(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> int {
    if(!address)
    {
      ossia_log_error("ossia_node_get_disabled: address is null");
      return 0;
    }

    return (int)convert_parameter(address)->get_disabled();
  });
}
void ossia_parameter_set_muted(ossia_parameter_t address, int muted)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_node_set_muted: address is null");
      return;
    }

    convert_parameter(address)->set_muted(muted != 0);
  });
}

int ossia_parameter_get_muted(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> int {
    if(!address)
    {
      ossia_log_error("ossia_node_get_muted: address is null");
      return 0;
    }

    return (int)convert_parameter(address)->get_muted();
  });
}
void ossia_parameter_set_critical(ossia_parameter_t address, int critical)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_node_set_critical: address is null");
      return;
    }

    convert_parameter(address)->set_critical(critical != 0);
  });
}

int ossia_parameter_get_critical(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> int {
    if(!address)
    {
      ossia_log_error("ossia_node_get_critical: address is null");
      return 0;
    }

    return (int)convert_parameter(address)->get_critical();
  });
}

void ossia_parameter_set_repetition_filter(ossia_parameter_t address, int rf)
{
  return safe_function(__func__, [=] {
    if(!address)
    {
      ossia_log_error("ossia_node_set_hidden: node is null");
      return;
    }

    convert_parameter(address)->set_repetition_filter(
        rf ? ossia::repetition_filter::ON : ossia::repetition_filter::OFF);
  });
}

int ossia_parameter_get_repetition_filter(ossia_parameter_t address)
{
  return safe_function(__func__, [=]() -> int {
    if(!address)
    {
      ossia_log_error("ossia_node_get_hidden: node is null");
      return 0;
    }

    auto rf = convert_parameter(address)->get_repetition_filter();
    return (rf == ossia::repetition_filter::ON) ? 1 : 0;
  });
}

ossia_mq_t ossia_mq_create(ossia_device_t dev)
{
  return new ossia::message_queue{*convert_device(dev)};
}

void ossia_mq_register(ossia_mq_t mq, ossia_parameter_t p)
{
  reinterpret_cast<ossia::message_queue*>(mq)->reg(*convert_parameter(p));
}

void ossia_mq_unregister(ossia_mq_t mq, ossia_parameter_t p)
{
  reinterpret_cast<ossia::message_queue*>(mq)->unreg(*convert_parameter(p));
}

int ossia_mq_pop(ossia_mq_t mq, ossia_parameter_t* address, ossia_value_t* val)
{
  auto messq = reinterpret_cast<ossia::message_queue*>(mq);

  ossia::received_value m;
  if(messq->try_dequeue(m))
  {
    *address = convert(m.address);
    *val = new ossia_value{std::move(m.value)};
    return 1;
  }
  return 0;
}

void ossia_mq_free(ossia_mq_t mq)
{
  delete reinterpret_cast<ossia::message_queue*>(mq);
}
}
