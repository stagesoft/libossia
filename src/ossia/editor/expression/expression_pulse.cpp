// This is an open source non-commercial project. Dear PVS-Studio, please check
// it. PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <ossia/editor/expression/expression_pulse.hpp>
#include <ossia/network/value/destination.hpp>
namespace ossia::expressions
{

expression_pulse::expression_pulse(const ossia::destination& destination)
    : m_destination(destination)
    , m_result(false)
{
  // start destination observation
  m_callback = m_destination.address().add_callback(
      [&](const ossia::value& result) { destination_callback(result); });
}

expression_pulse::~expression_pulse()
{
  // stop destination observation
  m_destination.address().remove_callback(m_callback);
}

bool expression_pulse::evaluate() const
{
  return m_result;
}

void expression_pulse::update() const
{
  // the result will be false until the next
  // #expression_pulse::destinationCallback call
  m_result = false;
}

void expression_pulse::reset()
{
  m_result = false;
}

void expression_pulse::on_first_callback_added() { }

void expression_pulse::on_removing_last_callback() { }

const destination& expression_pulse::get_destination() const
{
  return m_destination;
}

void expression_pulse::destination_callback(const ossia::value& value)
{
  m_result = true;
  send(true);
}
}
