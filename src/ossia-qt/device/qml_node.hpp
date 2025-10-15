#pragma once
#include <ossia-qt/device/qml_node_base.hpp>

#include <verdigris>

namespace ossia
{
namespace qt
{
class qml_node : public qml_node_base
{
  W_OBJECT(qml_node)
public:
  qml_node(QQuickItem* parent = nullptr);
  ~qml_node() override;

  void resetNode() override;

public:
  void reset_parent();
  W_SLOT(reset_parent);
  void node_destroyed();
  W_SLOT(node_destroyed);

private:
  void on_node_deleted(const ossia::net::node_base&);
  void setDevice(QObject* device) override;
};
}
}
