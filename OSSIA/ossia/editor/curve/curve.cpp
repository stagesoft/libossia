#include <ossia/editor/curve/detail/Curve_impl.tpp>
#include <ossia/editor/value/value.hpp>

namespace OSSIA
{
    // Curve implementation
    template<class X, class Y>
    std::shared_ptr<Curve<X, Y>> Curve<X, Y>::create()
    {
        return std::make_shared<impl::JamomaCurve<X, Y>>();
    }
    template<class X, class Y>
    Curve<X, Y>::~Curve() = default;

}

// Explicit instantiation
template class OSSIA_EXPORT OSSIA::Curve<double, bool>;
template class OSSIA_EXPORT OSSIA::Curve<double, int>;
template class OSSIA_EXPORT OSSIA::Curve<double, float>;

template class OSSIA_EXPORT OSSIA::Curve<bool, bool>;
template class OSSIA_EXPORT OSSIA::Curve<bool, int>;
template class OSSIA_EXPORT OSSIA::Curve<bool, float>;

template class OSSIA_EXPORT OSSIA::Curve<int, bool>;
template class OSSIA_EXPORT OSSIA::Curve<int, int>;
template class OSSIA_EXPORT OSSIA::Curve<int, float>;

template class OSSIA_EXPORT OSSIA::Curve<float, bool>;
template class OSSIA_EXPORT OSSIA::Curve<float, int>;
template class OSSIA_EXPORT OSSIA::Curve<float, float>;


