#include "qml_interval.hpp"

#include <ossia-qt/score/qml_cond.hpp>
#include <ossia-qt/score/qml_exec.hpp>
#include <ossia-qt/score/qml_scenario.hpp>

namespace ossia
{
namespace qt
{

qml_interval::qml_interval(QQuickItem* parent)
    : QQuickItem{parent}
{
  connect(this, &QQuickItem::parentChanged, this, &qml_interval::reset);
  reset();
}

qml_interval::~qml_interval() { }

qint32 qml_interval::nominalDuration() const
{
  return m_nominalDuration;
}

qint32 qml_interval::minDuration() const
{
  return m_minDuration;
}

qint32 qml_interval::maxDuration() const
{
  return m_maxDuration;
}

qint32 qml_interval::playDuration() const
{
  return m_playDuration;
}

qml_cond* qml_interval::follows() const
{
  return m_follows;
}

qml_cond* qml_interval::precedes() const
{
  return m_precedes;
}

std::shared_ptr<time_interval> qml_interval::interval() const
{
  return m_interval;
}

double qml_interval::speed() const
{
  return m_speed;
}

void qml_interval::setup()
{
  /*
  if(!m_interval)
  {
    auto scd = follows();
    auto ecd = precedes();
    if(scd && ecd)
    {
      auto sev = scd->cond();
      auto eev = ecd->cond();
      if(sev && eev)
      {
        m_interval = ossia::time_interval::create(
                       [=] (double pos, ossia::time_value tv, const
  ossia::state_element&) { setPlayDuration(reverseTime(tv)); }, *sev, *eev,
                       defaultTime(m_nominalDuration),
                       defaultTime(m_minDuration),
                       defaultTime(m_maxDuration));
      }
    }

    if(!m_interval)
      return;
  }
  m_interval->set_min_duration(defaultTime(m_minDuration));
  m_interval->set_max_duration(defaultTime(m_maxDuration));

  auto cld = this->findChildren<qml_process*>(QString{}, Qt::FindDirectChildrenOnly);
  for(auto child : cld)
  {
    child->setup();
    if(auto proc = child->process())
    {
      m_interval->add_time_process(proc);
    }
  }
  */
}

void qml_interval::registerProcess(qml_process*) { }

void qml_interval::unregisterProcess(qml_process*) { }

void qml_interval::setNominalDuration(qint32 nominalDuration)
{
  if(m_nominalDuration == nominalDuration)
    return;

  m_nominalDuration = nominalDuration;
  nominalDurationChanged(m_nominalDuration);
}

void qml_interval::setMinDuration(qint32 minDuration)
{
  if(m_minDuration == minDuration)
    return;

  m_minDuration = minDuration;
  minDurationChanged(m_minDuration);
}

void qml_interval::setMaxDuration(qint32 maxDuration)
{
  if(m_maxDuration == maxDuration)
    return;

  m_maxDuration = maxDuration;
  maxDurationChanged(m_maxDuration);
}

void qml_interval::setPlayDuration(qint32 playDuration)
{
  if(m_playDuration == playDuration)
    return;

  m_playDuration = playDuration;
  playDurationChanged(m_playDuration);
}

void qml_interval::setFollows(qml_cond* follows)
{
  if(m_follows == follows)
    return;

  m_follows = follows;
  followsChanged(m_follows);
}

void qml_interval::setPrecedes(qml_cond* precedes)
{
  if(m_precedes == precedes)
    return;

  m_precedes = precedes;
  precedesChanged(m_precedes);
}

void qml_interval::setFollows(qml_sync* follows)
{
  if(m_follows == follows->defaultCond())
    return;

  m_follows = follows->defaultCond();
  followsChanged(m_follows);
}

void qml_interval::setPrecedes(qml_sync* precedes)
{
  if(m_precedes == precedes->defaultCond())
    return;

  m_precedes = precedes->defaultCond();
  precedesChanged(m_precedes);
}

void qml_interval::setFollows(QObject* follows)
{
  if(auto sync = qobject_cast<qml_sync*>(follows))
    return setFollows(sync);
  else if(auto cond = qobject_cast<qml_cond*>(follows))
    return setFollows(cond);
}

void qml_interval::setPrecedes(QObject* precedes)
{
  if(auto sync = qobject_cast<qml_sync*>(precedes))
    return setPrecedes(sync);
  else if(auto cond = qobject_cast<qml_cond*>(precedes))
    return setPrecedes(cond);
}

void qml_interval::play()
{
  qml_exec::get(this)->play(this);
}

void qml_interval::pause()
{
  qml_exec::get(this)->pause(this);
}

void qml_interval::stop()
{
  qml_exec::get(this)->stop(this);
}

void qml_interval::setSpeed(double speed)
{
  if(qFuzzyCompare(m_speed, speed))
    return;

  m_speed = speed;
  speedChanged(m_speed);
}

void qml_interval::reset()
{
  if(m_parent)
  {
    if(auto scen = qobject_cast<qml_scenario*>(m_parent))
    {
      scen->unregisterInterval(this);
    }
  }

  if(auto scen = findParent<qml_scenario*>(this))
  {
    scen->registerInterval(this);
  }
}

}
}
