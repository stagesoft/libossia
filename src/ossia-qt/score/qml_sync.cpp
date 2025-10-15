#include "qml_sync.hpp"

namespace ossia
{
namespace qt
{

qml_sync::qml_sync(QQuickItem* parent)
    : QQuickItem{parent}
    , m_default{this}
{
  m_impl = std::make_shared<ossia::time_sync>();
  connect(this, &QQuickItem::parentChanged, this, &qml_sync::reset);
  reset();
}

qml_sync::~qml_sync() { }

QQmlScriptString qml_sync::expr() const
{
  return m_expr;
}

qml_cond* qml_sync::defaultCond()
{
  return &m_default;
}

void qml_sync::setup()
{
  m_impl->set_expression(
      make_expression(m_expr, this, ossia::expressions::make_expression_true()));
  for(qml_cond* ev :
      this->findChildren<qml_cond*>(QString{}, Qt::FindDirectChildrenOnly))
  {
    ev->setSync(this);
    ev->setup();
    if(auto c = ev->cond())
    {
      if(!ossia::contains(m_impl->get_time_events(), c))
      {
        m_impl->insert(m_impl->get_time_events().end(), c);
      }
    }
  }
}

void qml_sync::setExpr(QQmlScriptString expr)
{
  if(m_expr == expr)
    return;

  m_expr = expr;
  exprChanged(m_expr);
}

void qml_sync::reset() { }

void qml_sync::registerCond(qml_cond* s)
{
  if(m_conds.find(s) == m_conds.end())
  {
    m_conds.insert(s);
  }
}

void qml_sync::unregisterCond(qml_cond* s)
{
  auto it = m_conds.find(s);
  if(it != m_conds.end())
  {
    m_conds.erase(it);
  }
}
}
}
