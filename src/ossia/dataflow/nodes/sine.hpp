#pragma once
#include <ossia/dataflow/graph_node.hpp>
#include <ossia/dataflow/port.hpp>
#include <ossia/detail/math.hpp>

#include <boost/predef.h>

namespace ossia::nodes
{
template <std::size_t N>
struct sin_table
{
  template <typename T>
  constexpr sin_table(T t) : values{}
  {
    for (std::size_t i = 0; i < N; ++i)
    {
      values[i] = t(2. * M_PI * i / N);
    }
  }

  constexpr double value(double freq) const
  {
    const auto res = int(std::fmod(freq, 2. * M_PI) * (N - 1));
    assert(res >= 0);
    assert(res < (int)N);
    return values[res];
  }
  double values[N];
};

struct sine final : public ossia::nonowning_graph_node
{
  ossia::value_inlet freq_in;
  ossia::audio_outlet audio_out;

#if BOOST_COMP_GNUC
  static constexpr sin_table<1024> sines{[](auto f) { return sin(f); }};
#endif
public:
  double m_cos = 1.;
  double m_sin = 0;
  double freq = 440.;
  sine()
  {
    m_inlets.push_back(&freq_in);
    m_outlets.push_back(&audio_out);
  }
  void
  run(const ossia::token_request& t,
      ossia::exec_state_facade st) noexcept override
  {
    auto& vals = freq_in.target<ossia::value_port>()->get_data();
    if (!vals.empty())
      freq = ossia::clamp(
          ossia::convert<float>(vals.back().value), 0.f, 20000.f);

    auto& audio = audio_out->samples;
    auto N = t.physical_write_duration(st.modelToSamples());
    auto tick_start = t.physical_start(st.modelToSamples());

    if (N > 0)
    {
      audio.resize(1);
      audio[0].resize(tick_start + N);

#if BOOST_COMP_GNUC
      for (int64_t i = tick_start; i < tick_start + N; i++)
      {
        audio[0][i] = sines.value(2. * M_PI * freq / st.sampleRate());
      }
#else
      // Uses the method in
      // https://github.com/mbrucher/AudioTK/blob/master/ATK/Tools/SinusGeneratorFilter.cpp
      const auto fs = st.sampleRate();
      auto frequ_cos = std::cos(ossia::two_pi * freq / fs);
      auto frequ_sin = std::sin(ossia::two_pi * freq / fs);
      for (int64_t i =tick_start; i < tick_start + N; i++)
      {
        auto new_cos = m_cos * frequ_cos - m_sin * frequ_sin;
        auto new_sin = m_cos * frequ_sin + m_sin * frequ_cos;
        auto norm = (new_cos * new_cos + new_sin * new_sin);

        m_cos = new_cos / norm;
        m_sin = new_sin / norm;

        audio[0][i] = m_sin;
      }
#endif
    }
  }
};
}
