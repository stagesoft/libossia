#pragma once
#include <ossia/dataflow/nodes/automation.hpp>
#include <ossia/editor/scenario/time_process.hpp>

#include <ossia-qt/device/qml_node_base.hpp>
#include <ossia-qt/score/qml_interval.hpp>

#include <QEasingCurve>
#include <QPointer>
#include <QQuickItem>

#include <verdigris>

namespace ossia
{
namespace qt
{
class qml_interval;
class qml_process : public QQuickItem
{
  W_OBJECT(qml_process)
public:
  qml_process(QQuickItem* parent = nullptr);
  ~qml_process() override;

  qml_interval* interval() const;
  virtual void setup();

  virtual std::shared_ptr<ossia::time_process> process() const = 0;

protected:
  void reset();
  virtual void reset_impl();

  QPointer<qml_interval> m_cur_parent{};
};

class qml_breakpoint : public QQuickItem
{
  W_OBJECT(qml_breakpoint)

public:
  using QQuickItem::QQuickItem;
  std::function<float(double, float, float)> segment();

  QEasingCurve::Type type() const { return m_type; }

public:
  void typeChanged(QEasingCurve::Type arg_1) E_SIGNAL(OSSIA_EXPORT, typeChanged, arg_1);

public:
  void setType(QEasingCurve::Type t)
  {
    if(m_type != t)
    {
      m_type = t;
      typeChanged(t);
    }
  };
  W_SLOT(setType)

private:
  QEasingCurve::Type m_type{QEasingCurve::Linear};

  W_PROPERTY(QEasingCurve::Type, type READ type WRITE setType NOTIFY typeChanged)
};

class qml_autom : public qml_process
{
  W_OBJECT(qml_autom)

public:
  qml_autom(QQuickItem* parent = nullptr);
  ~qml_autom() override;
  void setup() override;

  QVariant target() const;
  double xMin() const;
  double xMax() const;
  double yMin() const;
  double yMax() const;
  std::shared_ptr<ossia::time_process> process() const override;

public:
  void setTarget(QVariant target);
  W_SLOT(setTarget);
  void setXMin(double xMin);
  W_SLOT(setXMin);
  void setXMax(double xMax);
  W_SLOT(setXMax);
  void setYMin(double yMin);
  W_SLOT(setYMin);
  void setYMax(double yMax);
  W_SLOT(setYMax);

public:
  void targetChanged(QVariant target) E_SIGNAL(OSSIA_EXPORT, targetChanged, target);
  void xMinChanged(double xMin) E_SIGNAL(OSSIA_EXPORT, xMinChanged, xMin);
  void xMaxChanged(double xMax) E_SIGNAL(OSSIA_EXPORT, xMaxChanged, xMax);
  void yMinChanged(double yMin) E_SIGNAL(OSSIA_EXPORT, yMinChanged, yMin);
  void yMaxChanged(double yMax) E_SIGNAL(OSSIA_EXPORT, yMaxChanged, yMax);

private:
  void reset_impl() override;
  /*
  std::shared_ptr<ossia::automation> m_impl;
  */
  QVariant m_target;
  double m_xMin{0.};
  double m_xMax{1.};
  double m_yMin{0.};
  double m_yMax{1.};
  QMetaObject::Connection m_death;

  W_PROPERTY(double, yMax READ yMax WRITE setYMax NOTIFY yMaxChanged)

  W_PROPERTY(double, yMin READ yMin WRITE setYMin NOTIFY yMinChanged)

  W_PROPERTY(double, xMax READ xMax WRITE setXMax NOTIFY xMaxChanged)

  W_PROPERTY(double, xMin READ xMin WRITE setXMin NOTIFY xMinChanged)

  W_PROPERTY(QVariant, target READ target WRITE setTarget NOTIFY targetChanged)
};
}
}
