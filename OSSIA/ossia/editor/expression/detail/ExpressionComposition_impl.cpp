#include "ExpressionComposition_impl.hpp"

namespace impl
{

JamomaExpressionComposition::JamomaExpressionComposition(std::shared_ptr<Expression> expr1, Operator op, std::shared_ptr<Expression> expr2) :
mFirstExpression(expr1),
mOperator(op),
mSecondExpression(expr2)
{}

JamomaExpressionComposition::JamomaExpressionComposition(const JamomaExpressionComposition * other) :
//! \todo mFirstExpression(other->mFirstExpression->clone()),
mOperator(other->mOperator)
//! \todo mSecondExpression(other->mSecondExpression->clone())
{}

std::shared_ptr<ExpressionComposition> JamomaExpressionComposition::clone() const
{
  return std::make_shared<JamomaExpressionComposition>(this);
}

JamomaExpressionComposition::~JamomaExpressionComposition()
{}
# pragma mark -
# pragma mark Execution

bool JamomaExpressionComposition::evaluate() const
{
  return do_evaluation(mFirstExpression->evaluate(), mSecondExpression->evaluate());
}

void JamomaExpressionComposition::update() const
{
  mFirstExpression->update();
  mSecondExpression->update();
}

# pragma mark -
# pragma mark Operator

bool JamomaExpressionComposition::operator== (const Expression& expression) const
{
  if (expression.getType() == Expression::Type::COMPOSITION)
  {
    const JamomaExpressionComposition e = dynamic_cast<const JamomaExpressionComposition&>(expression);
    return *mFirstExpression == *e.mFirstExpression && mOperator == e.mOperator && *mSecondExpression == *e.mSecondExpression;
  }
  else
    return false;
}

bool JamomaExpressionComposition::operator!= (const Expression& expression) const
{
  if (expression.getType() == Expression::Type::COMPOSITION)
  {
    const JamomaExpressionComposition e = dynamic_cast<const JamomaExpressionComposition&>(expression);
    return *mFirstExpression != *e.mFirstExpression || mOperator != e.mOperator || *mSecondExpression != *e.mSecondExpression;
  }
  else
    return true;
}

# pragma mark -
# pragma mark Callback Container

Expression::iterator JamomaExpressionComposition::addCallback(ResultCallback callback)
{
  auto it = CallbackContainer::addCallback(std::move(callback));

  if (callbacks().size() == 1)
  {
    // start first expression observation
    mFirstResultCallbackIndex = mFirstExpression->addCallback([&] (bool result) { firstResultCallback(result); });

    // start second expression observation
    mSecondResultCallbackIndex = mSecondExpression->addCallback([&] (bool result) { secondResultCallback(result); });
  }

  return it;
}

void JamomaExpressionComposition::removeCallback(Expression::iterator callback)
{
  CallbackContainer::removeCallback(callback);

  if (callbacks().size() == 0)
  {
    // stop first expression observation
    mFirstExpression->removeCallback(mFirstResultCallbackIndex);

    // stop second expression observation
    mSecondExpression->removeCallback(mSecondResultCallbackIndex);
  }
}

# pragma mark -
# pragma mark Accessors

const std::shared_ptr<Expression> & JamomaExpressionComposition::getFirstOperand() const
{
  return mFirstExpression;
}

ExpressionComposition::Operator JamomaExpressionComposition::getOperator() const
{
  return mOperator;
}

const std::shared_ptr<Expression> & JamomaExpressionComposition::getSecondOperand() const
{
  return mSecondExpression;
}

# pragma mark -
# pragma mark Implementation Specific

bool JamomaExpressionComposition::do_evaluation(bool first, bool second) const
{
  switch (mOperator)
  {
    case Operator::AND :
    {
      return first && second;
    }
    case Operator::OR :
    {
      return first || second;
    }
    case Operator::XOR :
    {
      return first ^ second;
    }
    default :
      return false;
  }
}

void JamomaExpressionComposition::firstResultCallback(bool first_result)
{
  bool result = do_evaluation(first_result, mSecondExpression->evaluate());
  send(result);
}

void JamomaExpressionComposition::secondResultCallback(bool second_result)
{
  bool result = do_evaluation(mFirstExpression->evaluate(), second_result);
  send(result);
}
}
