// This is an open source non-commercial project. Dear PVS-Studio, please check
// it. PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "minuit_common.hpp"

#include <ossia/detail/string_map.hpp>
#include <ossia/network/value/value.hpp>

namespace ossia::minuit
{

std::string_view to_minuit_type_text(const ossia::value& val)
{
  // integer, decimal, string, generic, boolean, none, array.
  struct ValueStringVisitor
  {
    std::string_view operator()(ossia::impulse) const
    {
      constexpr_return(ossia::make_string_view("none"));
    }
    std::string_view operator()(int32_t i) const
    {
      constexpr_return(ossia::make_string_view("integer"));
    }
    std::string_view operator()(float f) const
    {
      constexpr_return(ossia::make_string_view("decimal"));
    }
    std::string_view operator()(bool b) const
    {
      constexpr_return(ossia::make_string_view("boolean"));
    }
    std::string_view operator()(char c) const
    {
      constexpr_return(ossia::make_string_view("string"));
    }
    std::string_view operator()(const std::string& str) const
    {
      constexpr_return(ossia::make_string_view("string"));
    }
    std::string_view operator()(const ossia::vec2f& vec) const
    {
      constexpr_return(ossia::make_string_view("array"));
    }
    std::string_view operator()(const ossia::vec3f& vec) const
    {
      constexpr_return(ossia::make_string_view("array"));
    }
    std::string_view operator()(const ossia::vec4f& vec) const
    {
      constexpr_return(ossia::make_string_view("array"));
    }
    std::string_view operator()(const std::vector<ossia::value>& t) const
    {
      constexpr_return(ossia::make_string_view("array"));
    }
    std::string_view operator()(const value_map_type& t) const
    {
      constexpr_return(ossia::make_string_view("map"));
    }
    std::string_view operator()() const
    {
      throw invalid_value_type_error(
          "to_minuit_type_text: "
          "Trying to send null value");
      return {};
    }
  };

  return val.apply(ValueStringVisitor{});
}

static const auto& attribute_unordered_map()
{
  static const string_view_map<minuit_attribute> attr{
      {make_string_view("value"), minuit_attribute::Value},
      {make_string_view("type"), minuit_attribute::Type},
      {make_string_view("service"), minuit_attribute::Service},
      {make_string_view("priority"), minuit_attribute::Priority},
      {make_string_view("rangeBounds"), minuit_attribute::RangeBounds},
      {make_string_view("rangeClipmode"), minuit_attribute::RangeClipMode},
      {make_string_view("description"), minuit_attribute::Description},
      {make_string_view("repetitionsFilter"), minuit_attribute::RepetitionFilter},
      {make_string_view("tags"), minuit_attribute::Tags},
      {make_string_view("active"), minuit_attribute::Active},
      {make_string_view("valueDefault"), minuit_attribute::ValueDefault},
      {make_string_view("priority"), minuit_attribute::Priority},
      {make_string_view("dataspace"), minuit_attribute::Dataspace},
      {make_string_view("dataspaceUnit"), minuit_attribute::DataspaceUnit},
      {make_string_view("rampFunction"), minuit_attribute::RampFunction},
      {make_string_view("rampDrive"), minuit_attribute::RampDrive},
      {make_string_view("valueStepsize"), minuit_attribute::ValueStepSize},
      {make_string_view("rampFunctionParameters"),
       minuit_attribute::RampFunctionParameters}};
  return attr;
}

minuit_attribute get_attribute(std::string_view str)
{
  const auto& map = attribute_unordered_map();
  auto it = map.find(str);
  if(it != map.end())
    return it->second;
  else
    throw parse_error("get_attribute: unhandled attribute");
  return {};
}

std::string_view to_minuit_attribute_text(minuit_attribute str)
{
  switch(str)
  {
    case minuit_attribute::Value:
      constexpr_return(ossia::make_string_view("value"));
    case minuit_attribute::Service:
      constexpr_return(ossia::make_string_view("service"));
    case minuit_attribute::Type:
      constexpr_return(ossia::make_string_view("type"));
    case minuit_attribute::RangeBounds:
      constexpr_return(ossia::make_string_view("rangeBounds"));
    case minuit_attribute::RangeClipMode:
      constexpr_return(ossia::make_string_view("rangeClipmode"));
    case minuit_attribute::Description:
      constexpr_return(ossia::make_string_view("description"));
    case minuit_attribute::RepetitionFilter:
      constexpr_return(ossia::make_string_view("repetitionsFilter"));
    case minuit_attribute::Tags:
      constexpr_return(ossia::make_string_view("tags"));
    case minuit_attribute::Active:
      constexpr_return(ossia::make_string_view("active"));
    case minuit_attribute::ValueDefault:
      constexpr_return(ossia::make_string_view("valueDefault"));
    case minuit_attribute::Priority:
      constexpr_return(ossia::make_string_view("priority"));
    case minuit_attribute::Dataspace:
      constexpr_return(ossia::make_string_view("dataspace"));
    case minuit_attribute::DataspaceUnit:
      constexpr_return(ossia::make_string_view("dataspaceUnit"));
    case minuit_attribute::RampFunction:
      constexpr_return(ossia::make_string_view("rampFunction"));
    case minuit_attribute::RampDrive:
      constexpr_return(ossia::make_string_view("rampDrive"));
    case minuit_attribute::ValueStepSize:
      constexpr_return(ossia::make_string_view("valueStepsize"));
    case minuit_attribute::RampFunctionParameters:
      constexpr_return(ossia::make_string_view("rampFunctionParameters"));
    default:
      throw parse_error("to_minuit_attribute_text: unhandled attribute");
  }
  return {};
}
}
