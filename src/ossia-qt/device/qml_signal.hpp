#pragma once
#include <ossia/network/base/parameter.hpp>

#include <ossia-qt/device/qml_node_base.hpp>
#include <ossia-qt/qml_context.hpp>

#include <QObject>
#include <QQmlProperty>

#include <verdigris>
namespace ossia
{
namespace qt
{
class qml_node;
class qml_device;

class qml_signal : public qml_property_base
{
  W_OBJECT(qml_signal)

public:
  qml_signal(QQuickItem* parent = nullptr);
  ~qml_signal();

  void resetNode() override;
  void setDevice(QObject* device) override;

public:
  void triggered() E_SIGNAL(OSSIA_EXPORT, triggered);
  void trigger() E_SIGNAL(OSSIA_EXPORT, trigger);

private:
  void setupAddress(bool reading);
};
}
}
