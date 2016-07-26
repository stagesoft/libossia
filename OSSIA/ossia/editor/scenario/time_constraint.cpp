#include <ossia/editor/scenario/detail/TimeConstraint_impl.hpp>
#include <cassert>
#include <algorithm>
#include <iostream> //! \todo to remove. only here for debug purpose

# pragma mark -
# pragma mark Life cycle

namespace OSSIA
{
  std::shared_ptr<TimeConstraint> TimeConstraint::create(TimeConstraint::ExecutionCallback callback,
                                                    std::shared_ptr<TimeEvent> startEvent,
                                                    std::shared_ptr<TimeEvent> endEvent,
                                                    TimeValue nominal,
                                                    TimeValue min,
                                                    TimeValue max)
  {
    auto timeConstraint = std::make_shared<impl::JamomaTimeConstraint>(callback, startEvent, endEvent, nominal, min, max);

    // store the TimeConstraint into the start event as a next constraint
    if (std::find(startEvent->nextTimeConstraints().begin(),
                  startEvent->nextTimeConstraints().end(),
                  timeConstraint) == startEvent->nextTimeConstraints().end())
    {
      startEvent->nextTimeConstraints().push_back(timeConstraint);
    }

    // store the TimeConstraint into the end event as a previous constraint
    if (std::find(endEvent->previousTimeConstraints().begin(),
                  endEvent->previousTimeConstraints().end(),
                  timeConstraint) == endEvent->previousTimeConstraints().end())
    {
      endEvent->previousTimeConstraints().push_back(timeConstraint);
    }

    return timeConstraint;
  }

  TimeConstraint::~TimeConstraint()
  {}
}
