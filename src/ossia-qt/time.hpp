#pragma once
#include <ossia/dataflow/token_request.hpp>

#include <ossia-qt/time_value.hpp>

#include <verdigris>

namespace ossia
{
struct bar_time {
  int32_t bars{};
  int16_t quarters{};
  int8_t semiquavers{};
  int8_t cents{};

  friend bool operator==(const bar_time& lhs, const bar_time& rhs) noexcept
  {
    return lhs.bars == rhs.bars
        && lhs.quarters == rhs.quarters
        && lhs.semiquavers == rhs.semiquavers
        && lhs.cents == rhs.cents
    ;
  }
  friend bool operator!=(const bar_time& lhs, const bar_time& rhs) noexcept
  {
    return !(lhs == rhs);
  }
};
}

Q_DECLARE_METATYPE(ossia::bar_time)
W_REGISTER_ARGTYPE(ossia::bar_time)

Q_DECLARE_METATYPE(ossia::token_request)
W_REGISTER_ARGTYPE(ossia::token_request)
