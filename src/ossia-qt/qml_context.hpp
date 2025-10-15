#pragma once
#include <ossia/detail/config.hpp>

#include <ossia/preset/preset.hpp>

#include <ossia-qt/score/qml_util.hpp>

#include <QDebug>
#include <QFile>
#include <QObject>
#include <QQmlEngine>
#include <QUrl>

#include <verdigris>
namespace spdlog
{
class logger;
}
namespace ossia::qt
{
class qml_device;
class OSSIA_EXPORT qml_val_type
{
  W_GADGET(qml_val_type)
public:
  enum val_type
  {
    Float,   //! \see float
    Int,     //! \see int32_t
    Vec2f,   //! \see ossia::vec2f
    Vec3f,   //! \see ossia::vec3f
    Vec4f,   //! \see ossia::vec4f
    Impulse, //! \see ossia::impulse
    Bool,    //! \see bool
    String,  //! \see std::string
    List,    //! \see std::vector<ossia::value>
    Map      //! \see value_map_type
  };
  W_ENUM(val_type, Float, Int, Vec2f, Vec3f, Vec4f, Impulse, Bool, String, List, Map)
};

class OSSIA_EXPORT qml_access_mode
{
  W_GADGET(qml_access_mode)
public:
  enum access_mode
  {
    Bi,
    Get,
    Set
  };
  W_ENUM(access_mode, Bi, Get, Set)
};

class OSSIA_EXPORT qml_bounding_mode
{
  W_GADGET(qml_bounding_mode)
public:
  enum bounding_mode
  {
    Free,
    Clip,
    Wrap,
    Fold,
    Low,
    High
  };
  W_ENUM(bounding_mode, Free, Clip, Wrap, Fold, Low, High)
};

class OSSIA_EXPORT qml_rep_filter
{
  W_GADGET(qml_rep_filter)
public:
  enum repetition_filter
  {
    Unfiltered,
    Filtered
  };

  W_ENUM(repetition_filter, Unfiltered, Filtered)
};

class OSSIA_EXPORT qml_duration
{
  W_GADGET(qml_duration)
public:
  enum duration : qint32
  {
    Infinite = ossia::qt::infinite()
  };

  W_ENUM(duration, Infinite)
};
}

Q_DECLARE_METATYPE(ossia::qt::qml_val_type::val_type)
Q_DECLARE_METATYPE(ossia::qt::qml_access_mode::access_mode)
Q_DECLARE_METATYPE(ossia::qt::qml_bounding_mode::bounding_mode)
Q_DECLARE_METATYPE(ossia::qt::qml_rep_filter::repetition_filter)
Q_DECLARE_METATYPE(ossia::qt::qml_duration::duration)

W_REGISTER_ARGTYPE(ossia::qt::qml_val_type::val_type)
W_REGISTER_ARGTYPE(ossia::qt::qml_access_mode::access_mode)
W_REGISTER_ARGTYPE(ossia::qt::qml_bounding_mode::bounding_mode)
W_REGISTER_ARGTYPE(ossia::qt::qml_rep_filter::repetition_filter)
W_REGISTER_ARGTYPE(ossia::qt::qml_duration::duration)
