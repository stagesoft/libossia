#pragma once
#include <ossia/editor/scenario/time_sync.hpp>

#include <ossia-qt/score/qml_cond.hpp>

#include <QQmlExpression>
#include <QQmlListProperty>
#include <QQmlScriptString>
#include <QQuickItem>

#include <verdigris>
namespace ossia
{
namespace qt
{
class qml_cond;
class qml_sync : public QQuickItem
{
  W_OBJECT(qml_sync)

public:
  qml_sync(QQuickItem* parent = nullptr);
  ~qml_sync() override;

  QQmlScriptString expr() const;
  qml_cond* defaultCond();

  void registerCond(qml_cond*);
  void unregisterCond(qml_cond*);

  void setup();
  std::shared_ptr<ossia::time_sync> sync() const { return m_impl; }
  void setSync(std::shared_ptr<ossia::time_sync> s) { m_impl = s; }

public:
  void setExpr(QQmlScriptString expr);
  W_SLOT(setExpr);

public:
  void exprChanged(QQmlScriptString expr) E_SIGNAL(OSSIA_EXPORT, exprChanged, expr);

private:
  void reset();
  QQmlScriptString m_expr;
  std::shared_ptr<ossia::time_sync> m_impl;
  qml_cond m_default;
  ossia::hash_set<qml_cond*> m_conds;

  W_PROPERTY(QQmlScriptString, expr READ expr WRITE setExpr NOTIFY exprChanged)
};
}
}
