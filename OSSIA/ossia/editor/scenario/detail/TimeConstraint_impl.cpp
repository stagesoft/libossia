#include <ossia/editor/scenario/detail/TimeConstraint_impl.hpp>
#include <iostream>
#include <ossia/detail/algorithms.hpp>
namespace impl
{
JamomaTimeConstraint::JamomaTimeConstraint(TimeConstraint::ExecutionCallback callback,
                                           std::shared_ptr<TimeEvent> startEvent,
                                           std::shared_ptr<TimeEvent> endEvent,
                                           TimeValue nominal,
                                           TimeValue min,
                                           TimeValue max) :
JamomaClock([=] (TimeValue t, TimeValue t2, unsigned char c) { return ClockCallback(t, t2, c); }),
mCallback(callback),
mStartEvent(startEvent),
mEndEvent(endEvent),
mDurationNominal(nominal),
mDurationMin(min),
mDurationMax(max)
{
}

JamomaTimeConstraint::JamomaTimeConstraint(const JamomaTimeConstraint * other) :
JamomaClock(other),
mCallback(other->mCallback),
mStartEvent(other->mStartEvent),
mEndEvent(other->mEndEvent),
mDurationNominal(other->mDurationNominal),
mDurationMin(other->mDurationMin),
mDurationMax(other->mDurationMax)
{
}

std::shared_ptr<TimeConstraint> JamomaTimeConstraint::clone() const
{
  return std::make_shared<JamomaTimeConstraint>(this);
}

JamomaTimeConstraint::~JamomaTimeConstraint()
{}

# pragma mark -
# pragma mark Execution

void JamomaTimeConstraint::start()
{
  if (mRunning)
    throw std::runtime_error("time constraint is running");

  // set clock duration using maximal duration
  setDuration(mDurationMax);

  // start all jamoma time processes
  for (const auto& timeProcess : timeProcesses())
  {
    timeProcess->start();
  }

  // launch the clock
  do_start();
}

void JamomaTimeConstraint::stop()
{
  // stop the clock
  do_stop();

  // stop all jamoma time processes
  for (const auto& timeProcess : timeProcesses())
  {
    timeProcess->stop();
  }
}

State JamomaTimeConstraint::offset(TimeValue date)
{
  if (mRunning)
    throw std::runtime_error("time constraint is running");

  do_setOffset(date);

  const auto& processes = timeProcesses();
  OSSIA::State state;
  state.reserve(processes.size());

  // get the state of each TimeProcess at current clock position and date
  for (const auto& timeProcess : processes)
  {
    state.add(timeProcess->offset(date));
  }

  return state;
}

State JamomaTimeConstraint::state()
{
  if (!mRunning)
    throw std::runtime_error("time constraint is not running");

  const auto& processes = timeProcesses();
  OSSIA::State state;
  state.reserve(processes.size());

  // get the state of each TimeProcess at current clock position and date
  for (const auto& timeProcess : processes)
  {
    state.add(timeProcess->state());
  }

  return state;
}

void JamomaTimeConstraint::pause()
{
  mPaused = true;

  // pause all jamoma time processes
  for (const auto& timeProcess : timeProcesses())
  {
    timeProcess->pause();
  }
}

void JamomaTimeConstraint::resume()
{
  mPaused = false;

  // reset the time reference
  mLastTime = steady_clock::now();

  // resume all jamoma time processes
  for (const auto& timeProcess : timeProcesses())
  {
    timeProcess->resume();
  }
}

# pragma mark -
# pragma mark Accessors

void JamomaTimeConstraint::setCallback(TimeConstraint::ExecutionCallback callback)
{
  mCallback = callback;
}

const TimeValue & JamomaTimeConstraint::getDurationNominal() const
{
  return mDurationNominal;
}

TimeConstraint & JamomaTimeConstraint::setDurationNominal(TimeValue durationNominal)
{
  mDurationNominal = durationNominal;

  if (mDurationNominal < mDurationMin)
    setDurationMin(mDurationNominal);

  if (mDurationNominal > mDurationMax)
    setDurationMax(mDurationNominal);

  return *this;
}

const TimeValue & JamomaTimeConstraint::getDurationMin() const
{
  return mDurationMin;
}

TimeConstraint & JamomaTimeConstraint::setDurationMin(TimeValue durationMin)
{
  mDurationMin = durationMin;

  if (mDurationMin > mDurationNominal)
    setDurationNominal(mDurationMin);

  return *this;
}

const TimeValue & JamomaTimeConstraint::getDurationMax() const
{
  return mDurationMax;
}

TimeConstraint & JamomaTimeConstraint::setDurationMax(TimeValue durationMax)
{
  mDurationMax = durationMax;

  if (durationMax < mDurationNominal)
    setDurationNominal(mDurationMax);

  return *this;
}

const std::shared_ptr<TimeEvent> & JamomaTimeConstraint::getStartEvent() const
{
  return mStartEvent;
}

const std::shared_ptr<TimeEvent> & JamomaTimeConstraint::getEndEvent() const
{
  return mEndEvent;
}

# pragma mark -
# pragma mark TimeProcesses

void JamomaTimeConstraint::addTimeProcess(std::shared_ptr<TimeProcess> timeProcess)
{
  assert(timeProcess.get());
  // store a TimeProcess if it is not already stored
  if (find(timeProcesses().begin(),
           timeProcesses().end(),
           timeProcess) == timeProcesses().end())
  {
    timeProcesses().push_back(timeProcess);
    timeProcess->parent = shared_from_this();
  }
}

void JamomaTimeConstraint::removeTimeProcess(std::shared_ptr<TimeProcess> timeProcess)
{
  auto it = find(timeProcesses().begin(), timeProcesses().end(), timeProcess);
  if (it != timeProcesses().end())
  {
      timeProcesses().erase(it);
      timeProcess.reset();
  }
}

# pragma mark -
# pragma mark Implementation specific

void JamomaTimeConstraint::ClockCallback(TimeValue position, TimeValue date, unsigned char droppedTicks)
{
  if (mCallback)
      (mCallback)(position, date, state());
}

}
