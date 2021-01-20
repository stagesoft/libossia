// This is an open source non-commercial project. Dear PVS-Studio, please check
// it. PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "execution_state.hpp"

#include <ossia/audio/audio_parameter.hpp>
#include <ossia/audio/audio_protocol.hpp>
#include <ossia/dataflow/data_copy.hpp>
#include <ossia/dataflow/dataflow.hpp>
#include <ossia/dataflow/exec_state_facade.hpp>
#include <ossia/dataflow/token_request.hpp>
#include <ossia/dataflow/port.hpp>
#include <ossia/detail/apply.hpp>
#include <ossia/editor/state/detail/state_flatten_visitor.hpp>
#include <ossia/editor/state/state_element.hpp>
#include <ossia/network/base/message_queue.hpp>
#include <ossia/network/midi/midi_device.hpp>
#include <ossia/network/midi/midi_protocol.hpp>
#include <ossia/network/midi/detail/midi_impl.hpp>
#include <ossia/dataflow/typed_value.hpp>

namespace ossia
{
struct local_pull_visitor
{
  execution_state& st;
  ossia::net::parameter_base* addr{};
  bool operator()(value_port& val) const
  {
    OSSIA_EXEC_STATE_LOCK_READ(st);
    auto it = st.m_valueState.find(addr);
    if (it != st.m_valueState.end() && !it->second.empty())
    {
      copy_data{}(it->second, val);
      return true;
    }
    return false;
  }

  bool operator()(audio_port& val) const
  {
    OSSIA_EXEC_STATE_LOCK_READ(st);
    auto it = st.m_audioState.find(static_cast<ossia::audio_parameter*>(addr));
    if (it != st.m_audioState.end() && !it->second.samples.empty())
    {
      copy_data{}(it->second, val);
      return true;
    }
    return false;
  }

  bool operator()(midi_port& val) const
  {
    OSSIA_EXEC_STATE_LOCK_READ(st);
    auto it = st.m_midiState.find(addr);
    if (it != st.m_midiState.end() && !it->second.empty())
    {
      copy_data{}(it->second, val);
      return true;
    }
    return false;
  }

  bool operator()() const
  {
    return false;
  }
};

struct global_pull_visitor
{
  ossia::execution_state& state;
  const net::parameter_base& out;
  void operator()(value_port& val) const
  {
    if (!val.is_event)
    {
      copy_data{}(out, val);
    }
    else
    {
      auto it = state.m_receivedValues.find(
          const_cast<net::parameter_base*>(&out));
      if (it != state.m_receivedValues.end())
      {
        copy_data{}(*it->first, it->second, val);
      }
    }
  }

  void operator()(audio_port& val) const
  {
#if !defined(NDEBUG)
    auto aa = dynamic_cast<const audio_parameter*>(&out);
    assert(aa);
#else
    auto aa = static_cast<const audio_parameter*>(&out);
#endif
    aa->clone_value(val.samples);
  }

  void operator()(midi_port& val) const
  {
    auto& node = out.get_node();
    auto& dev = node.get_device();
    auto& proto = dev.get_protocol();

#if !defined(NDEBUG)
    // TODO how to do without that dynamic_cast ?
    // Can we *ensure* that the address of the midi_port is a midi one ?
    auto midi = dynamic_cast<ossia::net::midi::midi_protocol*>(&proto);
    assert(midi);
#else
    auto midi = static_cast<ossia::net::midi::midi_protocol*>(&proto);
#endif

    auto it = state.m_receivedMidi.find(midi);
    if (it != state.m_receivedMidi.end())
    {
      for (const rtmidi::message& v : it->second.second)
      {
        val.messages.push_back(v);
      }
    }
  }

  void operator()() const
  {
  }
};

struct global_pull_node_visitor
{
  ossia::execution_state& state;
  const net::node_base& out;
  void operator()(value_port& val) const
  {
    // TODO Nothing to do ?
  }

  void operator()(audio_port& val) const
  {
    // TODO Nothing to do ?
  }

  void operator()(midi_port& val) const
  {
    auto& node = out;
    auto& dev = node.get_device();
    auto& proto = dev.get_protocol();

#if !defined(NDEBUG)
    // TODO how to do without that dynamic_cast ?
    // Can we *ensure* that the address of the midi_port is a midi one ?
    auto midi = dynamic_cast<ossia::net::midi::midi_protocol*>(&proto);
    assert(midi);
#else
    auto midi = static_cast<ossia::net::midi::midi_protocol*>(&proto);
#endif

    int channel = -1;
    if (node.get_parent() == &dev.get_root_node())
    {
      // the node is a MIDI channel node
      channel = static_cast<const ossia::net::midi::channel_node&>(node).channel;
    }

    auto it = state.m_receivedMidi.find(midi);
    if (it != state.m_receivedMidi.end())
    {
      if(channel == -1)
      {
        for (const rtmidi::message& v : it->second.second)
        {
          val.messages.push_back(v);
        }
      }
      else
      {
        for (const rtmidi::message& v : it->second.second)
        {
          if(v.get_channel() == channel)
            val.messages.push_back(v);
        }
      }
    }
  }

  void operator()() const
  {
  }
};

execution_state::~execution_state()
{
  for(auto dev : m_devices_exec)
    dev->get_protocol().stop_execution();
}

void execution_state::clear_devices()
{
  m_devices_edit.clear();

  for(auto dev : m_devices_exec)
    dev->get_protocol().stop_execution();
  m_devices_exec.clear();
}

execution_state::execution_state()
{
  m_valueState.reserve(100);
  m_audioState.reserve(8);
  m_midiState.reserve(4);
}

void execution_state::register_device(net::device_base* d)
{
  if (d)
  {
    m_devices_edit.push_back(d);
    m_device_change_queue.enqueue({device_operation::REGISTER, d});
  }
}

void execution_state::unregister_device(net::device_base* d)
{
  if (d)
  {
    ossia::remove_erase(m_devices_edit, d);
    m_device_change_queue.enqueue({device_operation::UNREGISTER, d});
  }
}

void execution_state::register_parameter(net::parameter_base& p)
{
  auto device = &p.get_node().get_device();
  for (auto& q : m_valueQueues)
  {
    if (&q.device == device)
    {
      q.reg(p);
      break;
    }
  }
}

void execution_state::unregister_parameter(net::parameter_base& p)
{
  auto device = &p.get_node().get_device();
  for (auto& q : m_valueQueues)
  {
    if (&q.device == device)
    {
      q.unreg(p);
      break;
    }
  }
}

void execution_state::register_midi_parameter(net::midi::midi_protocol& p)
{
  p.enable_registration();
  auto it = m_receivedMidi.find(&p);
  if(it == m_receivedMidi.end())
  {
    m_receivedMidi.insert({&p, {0, {}}});
  }
  else
  {
    it.value().first++;
  }
}

void execution_state::unregister_midi_parameter(net::midi::midi_protocol& p)
{
  auto it = m_receivedMidi.find(&p);
  if(it != m_receivedMidi.end())
  {
    it.value().first--;
    if(it.value().first <= 0)
    {
      m_receivedMidi.erase(it);
      // TODO p.disable_registration();
    }
  }
}

void execution_state::get_new_values()
{
  for (auto it = m_receivedValues.begin(), end = m_receivedValues.end();
       it != end; ++it)
    it.value().clear();

  for (auto& mq : m_valueQueues)
  {
    ossia::received_value recv;
    while (mq.try_dequeue(recv))
      m_receivedValues[recv.address].push_back(recv.value);
  }

  for (auto it = m_receivedMidi.begin(), end = m_receivedMidi.end(); it != end;
       ++it)
  {
    it.value().second.clear();
    it->first->clone_value(it.value().second);
  }
}

void execution_state::register_port(const inlet& port)
{
  if (auto vp = port.target<ossia::value_port>())
  {
    if (vp->is_event)
    {
      if (auto addr = port.address.target<ossia::net::parameter_base*>())
      {
        register_parameter(**addr);
      }
      else if (auto p = port.address.target<ossia::traversal::path>())
      {
        std::vector<ossia::net::node_base*> roots{};

        for (auto n : m_devices_exec)
          roots.push_back(&n->get_root_node());

        ossia::traversal::apply(*p, roots);
        for (auto n : roots)
          if (auto param = n->get_parameter())
            register_parameter(*param);
      }
    }
  }
  else if (port.target<ossia::midi_port>())
  {
    if (auto addr = port.address.target<ossia::net::node_base*>())
    {
      if (auto midi_addr = dynamic_cast<ossia::net::midi::midi_protocol*>(
              &(*addr)->get_device().get_protocol()))
      {
        register_midi_parameter(*midi_addr);
      }
    }
    else if (auto addr = port.address.target<ossia::net::parameter_base*>())
    {
      if (auto midi_addr = dynamic_cast<ossia::net::midi::midi_protocol*>(
              &(*addr)->get_node().get_device().get_protocol()))
      {
        register_midi_parameter(*midi_addr);
      }
    }
  }
}

void execution_state::register_port(const outlet& port)
{
  // nothing to do
}


void execution_state::unregister_port(const inlet& port)
{
  if (auto vp = port.target<ossia::value_port>())
  {
    if (vp->is_event)
    {
      if (auto addr = port.address.target<ossia::net::parameter_base*>())
      {
        unregister_parameter(**addr);
      }
      else if (auto p = port.address.target<ossia::traversal::path>())
      {
        std::vector<ossia::net::node_base*> roots{};

        for (auto n : m_devices_exec)
          roots.push_back(&n->get_root_node());

        ossia::traversal::apply(*p, roots);
        for (auto n : roots)
          if (auto param = n->get_parameter())
            unregister_parameter(*param);
      }
    }
  }
  else if (port.target<ossia::midi_port>())
  {
    if (auto addr = port.address.target<ossia::net::node_base*>())
    {
      if (auto midi_addr = dynamic_cast<ossia::net::midi::midi_protocol*>(
            &(*addr)->get_device().get_protocol()))
      {
        unregister_midi_parameter(*midi_addr);
      }
    }
    else if (auto addr = port.address.target<ossia::net::parameter_base*>())
    {
      if (auto midi_addr = dynamic_cast<ossia::net::midi::midi_protocol*>(
            &(*addr)->get_node().get_device().get_protocol()))
      {
        unregister_midi_parameter(*midi_addr);
      }
    }
  }
}

void execution_state::unregister_port(const outlet& port)
{
  // nothing to do
}

void execution_state::apply_device_changes()
{
  device_operation op;
  while (m_device_change_queue.try_dequeue(op))
  {
    switch (op.operation)
    {
      case device_operation::REGISTER:
        op.device->get_protocol().start_execution();
        m_devices_exec.push_back(op.device);
        m_valueQueues.emplace_back(*op.device);
        break;
      case device_operation::UNREGISTER:
      {
        op.device->get_protocol().stop_execution();
        ossia::remove_erase(m_devices_exec, op.device);
        auto it = ossia::find_if(
            m_valueQueues, [&](auto& mq) { return &mq.device == op.device; });
        if (it != m_valueQueues.end())
          m_valueQueues.erase(it);

        break;
      }
    }
  }
}
void execution_state::begin_tick()
{
  clear_local_state();
  get_new_values();
  apply_device_changes();
}

void execution_state::clear_local_state()
{
  m_msgIndex = 0;
  /*
  for(auto& st : m_valueState)
    st.second.clear();
  for(auto& st : m_audioState)
    for(auto& samples : st.second.samples)
      samples.clear();
  for(auto& st : m_midiState)
    st.second.clear();
    */
}
void execution_state::reset()
{
  // TODO unregister everything ?
  clear_local_state();
  clear_devices();
  m_valueQueues.clear();
  m_receivedValues.clear();
  m_receivedMidi.clear();
}

ossia::message
to_state_element(ossia::net::parameter_base& p, ossia::typed_value&& v)
{
  ossia::message m{p, std::move(v.value)};
  if (auto u = v.type.target<ossia::unit_t>())
    m.dest.unit = std::move(*u);
  m.dest.index = std::move(v.index);
  return m;
}

ossia::message
to_state_element(ossia::net::parameter_base& p, const ossia::typed_value& v)
{
  ossia::message m{p, v.value};
  if (auto u = v.type.target<ossia::unit_t>())
    m.dest.unit = std::move(*u);
  m.dest.index = std::move(v.index);
  return m;
}

void execution_state::commit_common()
{
  for (auto& elt : m_audioState)
  {
    assert(elt.first);
    elt.first->push_value(elt.second);

    for (auto& vec : elt.second.samples)
    {
      vec.clear();
    }
  }

  for (auto& elt : m_midiState)
  {
    if (!elt.second.empty())
    {
      auto proto = dynamic_cast<ossia::net::midi::midi_protocol*>(
          &elt.first->get_node().get_device().get_protocol());
      if (proto)
      {
        for (const auto& v : elt.second)
        {
          proto->push_value(v);
        }
      }
      elt.second.clear();
    }
  }
}

void execution_state::advance_tick(std::size_t t)
{
  /*
        for (auto& elt : st.m_audioState)
        {
          auto addr = dynamic_cast<audio_parameter*>(elt.first);
          if(addr)
          {
            for(auto& chan : addr->audio)
            {
              if(!chan.empty())
              {
                chan = chan.subspan(1);
              }
            }
          }
        }
        */
  for (auto& dev : m_devices_exec)
  {
    auto& proto = dev->get_protocol();
    if (auto ap = dynamic_cast<ossia::audio_protocol*>(&proto))
    {
      ap->advance_tick(t);
    }
  }
}

void execution_state::commit_merged()
{
  // int i = 0;
  for (auto it = m_valueState.begin(), end = m_valueState.end(); it != end;
       ++it)
  {
    switch (it->second.size())
    {
      case 0:
        continue;
      case 1:
      {
        to_state_element(*it->first, it->second[0].first).launch();
        break;
      }
      default:
      {
        m_monoState.e = ossia::state_element{};
        state_flatten_visitor<ossia::mono_state, false, true> vis{m_monoState};
        // i += it->second.size();
        for (auto& val : it->second)
        {
          vis(to_state_element(*it->first, std::move(val.first)));
        }
        ossia::launch(m_monoState.e);
      }
    }
    it->second.clear();
  }
  // std::cout << "NUM MESSAGES: " << i << std::endl;

  commit_common();
}

void execution_state::commit()
{
  state_flatten_visitor<ossia::flat_vec_state, false, true> vis{
      m_commitOrderedState};
  for (auto it = m_valueState.begin(), end = m_valueState.end(); it != end;
       ++it)
  {
    switch (it->second.size())
    {
      case 0:
        continue;
      case 1:
      {
        to_state_element(*it->first, it->second[0].first).launch();
        break;
      }
      default:
      {
        m_commitOrderedState.clear();
        m_commitOrderedState.reserve(it->second.size());
        for (auto& val : it->second)
        {
          // std::cerr << "mergin : " <<  val.first.value << std::endl;
          vis(to_state_element(*it->first, std::move(val.first)));
        }

        m_commitOrderedState.launch();
      }
    }

    it->second.clear();
  }

  commit_common();
}

void execution_state::commit_priorized()
{
  // Here we use the priority of each node
  ossia::flat_map<
      std::tuple<ossia::net::priority, int64_t, int>,
      std::vector<ossia::state_element>>
      m_priorizedMessagesCache;
  for (auto it = m_valueState.begin(), end = m_valueState.end(); it != end;
       ++it)
  {
    m_commitOrderedState.clear();
    m_commitOrderedState.reserve(it->second.size());
    state_flatten_visitor<ossia::flat_vec_state, false, true> vis{
        m_commitOrderedState};

    int64_t cur_ts = 0; // timestamp
    int cur_ms = 0;     // message stamp
    int cur_prio = 0;
    if (const auto& p = ossia::net::get_priority(it->first->get_node()))
      cur_prio = *p;

    for (auto& val : it->second)
    {
      cur_ms = std::max(cur_ms, val.second);
      cur_ts = std::max(cur_ts, val.first.timestamp);
      vis(to_state_element(*it->first, std::move(val.first)));
    }

    auto& idx
        = m_priorizedMessagesCache[std::make_tuple(cur_prio, cur_ts, cur_ms)];
    for (auto& e : m_commitOrderedState)
      idx.push_back(std::move(e));

    it->second.clear();
  }

  for (auto& vec : m_priorizedMessagesCache.container)
  {
    for (auto& mess : vec.second)
      ossia::launch(mess);
    vec.second.clear();
  }

  commit_common();
}

void execution_state::commit_ordered()
{
  // TODO same for midi
  // m_flatMessagesCache.reserve(m_valueState.size());
  for (auto it = m_valueState.begin(), end = m_valueState.end(); it != end;
       ++it)
  {
    m_commitOrderedState.clear();
    m_commitOrderedState.reserve(it->second.size());
    state_flatten_visitor<ossia::flat_vec_state, false, true> vis{
        m_commitOrderedState};

    int64_t cur_ts = 0; // timestamp
    int cur_ms = 0;     // message stamp
    for (auto& val : it->second)
    {
      cur_ms = std::max(cur_ms, val.second);
      cur_ts = std::max(cur_ts, val.first.timestamp);
      vis(to_state_element(*it->first, std::move(val.first)));
    }

    auto& idx = m_flatMessagesCache[std::make_pair(cur_ts, cur_ms)];
    for (auto& e : m_commitOrderedState)
      idx.push_back(std::move(e));

    it->second.clear();
  }

  for (auto& vec : m_flatMessagesCache.container)
  {
    for (auto& mess : vec.second)
      ossia::launch(mess);
    vec.second.clear();
  }

  commit_common();
}

void execution_state::find_and_copy(net::parameter_base& addr, inlet& in)
{
  bool ok = in.visit(local_pull_visitor{*this, &addr});
  if (!ok)
  {
    copy_from_global(addr, in);
  }
}

void execution_state::copy_from_global(net::parameter_base& addr, inlet& in)
{
  if (in.scope & port::scope_t::global)
  {
    in.visit(global_pull_visitor{*this, addr});
  }
}

void execution_state::copy_from_global_node(net::node_base& node, inlet& in)
{
  if (in.scope & port::scope_t::global)
  {
    in.visit(global_pull_node_visitor{*this, node});
  }
}
/*
void execution_state::insert(
    const ossia::destination& param, const audio_port& v)
{
  if(!v.samples.empty())
  {
#if !defined(NDEBUG)
    auto addr = dynamic_cast<ossia::audio_parameter*>(&param.address());
    assert(addr);
#else
    auto addr = static_cast<ossia::audio_parameter*>(&param.address());
#endif
    insert(*addr, v);
  }
}

void execution_state::insert(
    const ossia::destination& param, const midi_port& v)
{
  insert(param.address(), v);
}
*/
void execution_state::insert(
    ossia::net::parameter_base& param, const value_port& val)
{
  OSSIA_EXEC_STATE_LOCK_WRITE(*this);
  int idx = m_msgIndex;
  auto& st = m_valueState[&param];

  // here reserve is a pessimization if we push only a few values...
  // just letting log2 growth do its job is much better.
  switch (val.mix_method)
  {
    case ossia::data_mix_method::mix_replace:
    {
      for (const ossia::timed_value& v : val.get_data())
      {
        auto it = ossia::find_if(
            st, [&](const std::pair<typed_value, int>& val) {
              return val.first.timestamp == v.timestamp;
            });
        if (it != st.end())
          it->first = ossia::typed_value{v, val.index, val.type};
        else
          st.emplace_back(
              ossia::typed_value{v, val.index, val.type}, idx++);
      }
      break;
    }
    case ossia::data_mix_method::mix_append:
    {
      for (const auto& v : val.get_data())
        st.emplace_back(
            ossia::typed_value{v, val.index, val.type}, idx++);
      break;
    }
    case ossia::data_mix_method::mix_merge:
    {
      // TODO;
      break;
    }
  }
  idx = m_msgIndex;
  m_msgIndex += val.get_data().size();
}

void execution_state::insert(ossia::net::parameter_base& param, value_port&& val)
{
  OSSIA_EXEC_STATE_LOCK_WRITE(*this);
  int idx = m_msgIndex;
  auto& st = m_valueState[&param];

  // here reserve is a pessimization if we push only a few values...
  // just letting log2 growth do its job is much better.

  switch (val.mix_method)
  {
    case ossia::data_mix_method::mix_replace:
    {
      for (ossia::timed_value& v : val.get_data())
      {
        auto it = ossia::find_if(
                    st, [&](const std::pair<typed_value, int>& val) {
          return val.first.timestamp == v.timestamp;
        });
        if (it != st.end())
          it->first
              = ossia::typed_value{std::move(v), val.index, val.type};
        else
          st.emplace_back(
                ossia::typed_value{std::move(v), val.index, val.type},
                idx++);
      }
      break;
    }
    case ossia::data_mix_method::mix_append:
    {
      for (auto& v : val.get_data())
        st.emplace_back(
              ossia::typed_value{std::move(v), val.index, val.type},
              idx++);
      break;
    }
    case ossia::data_mix_method::mix_merge:
    {
      // TODO;
      break;
    }
  }
  idx = m_msgIndex;
  m_msgIndex += val.get_data().size();
}

void execution_state::insert(
    ossia::net::parameter_base& param, const typed_value& v)
{
  OSSIA_EXEC_STATE_LOCK_WRITE(*this);
  m_valueState[&param].emplace_back(v, m_msgIndex++);
}
void execution_state::insert(
    ossia::net::parameter_base& param, typed_value&& v)
{
  OSSIA_EXEC_STATE_LOCK_WRITE(*this);
  m_valueState[&param].emplace_back(std::move(v), m_msgIndex++);
}

void execution_state::insert(
    ossia::audio_parameter& param, const audio_port& v)
{
  OSSIA_EXEC_STATE_LOCK_WRITE(*this);
  mix(v.samples, m_audioState[&param].samples);
}

void execution_state::insert(
    ossia::net::parameter_base& param, const midi_port& v)
{
  if (!v.messages.empty())
  {
    OSSIA_EXEC_STATE_LOCK_WRITE(*this);
    auto& vec = m_midiState[&param];
    vec.insert(vec.end(), v.messages.begin(), v.messages.end());
  }
}

struct state_exec_visitor
{
  ossia::execution_state& e;
  void operator()(const ossia::state& st)
  {
    for (auto& msg : st)
      ossia::apply(*this, msg);
  }

  void operator()(const ossia::message& msg)
  {
    OSSIA_EXEC_STATE_LOCK_WRITE(e);
    e.m_valueState[&msg.dest.address()].emplace_back(
        ossia::typed_value{msg.message_value, msg.dest.index, msg.dest.unit},
        e.m_msgIndex++);
  }

  template <std::size_t N>
  void operator()(const ossia::piecewise_vec_message<N>& st)
  {
  }

  void operator()(const ossia::piecewise_message& st)
  {
  }

  void operator()()
  {
  }
};

void execution_state::insert(const ossia::state& v)
{
  OSSIA_EXEC_STATE_LOCK_WRITE(*this);
  for (auto& msg : v)
  {
    ossia::apply(state_exec_visitor{*this}, msg);
  }
}

static bool is_in(
    net::parameter_base& other,
    const ossia::fast_hash_map<
        ossia::net::parameter_base*,
        value_vector<std::pair<typed_value, int>>>& container)
{
  auto it = container.find(&other);
  if (it == container.end())
    return false;
  return !it->second.empty();
}
static bool is_in(
    net::parameter_base& other,
    const ossia::fast_hash_map<
        ossia::net::parameter_base*, value_vector<rtmidi::message>>& container)
{
  auto it = container.find(&other);
  if (it == container.end())
    return false;
  return !it->second.empty();
}
static bool is_in(
    net::parameter_base& other,
    const ossia::fast_hash_map<ossia::audio_parameter*, audio_port>&
        container)
{
  // TODO dangerous
  auto it = container.find(static_cast<ossia::audio_parameter*>(&other));
  if (it == container.end())
    return false;
  return !it->second.samples.empty();
}
bool execution_state::in_local_scope(net::parameter_base& other) const
{
  OSSIA_EXEC_STATE_LOCK_READ(*this);
  return (
      is_in(other, m_valueState) || is_in(other, m_audioState)
      || is_in(other, m_midiState));
}

int exec_state_facade::sampleRate() const noexcept
{
  return impl->sampleRate;
}

int exec_state_facade::bufferSize() const noexcept
{
  return impl->bufferSize;
}

double exec_state_facade::modelToSamples() const noexcept
{
  return impl->modelToSamplesRatio;
}

double exec_state_facade::samplesToModel() const noexcept
{
  return impl->samplesToModelRatio;
}

int64_t exec_state_facade::samplesSinceStart() const noexcept
{
  return impl->samples_since_start;
}

double exec_state_facade::startDate() const noexcept
{
  return impl->start_date;
}

double exec_state_facade::currentDate() const noexcept
{
  return impl->cur_date;
}

ossia::net::node_base*
exec_state_facade::find_node(std::string_view name) const noexcept
{
  return impl->find_node(name);
}

int64_t exec_state_facade::physical_start(const token_request& t) const noexcept
{
  return t.physical_start(impl->modelToSamplesRatio);
}

void exec_state_facade::insert(net::parameter_base& dest, const typed_value& v)
{
  impl->insert(dest, v);
}

void exec_state_facade::insert(net::parameter_base& dest, typed_value&& v)
{
  impl->insert(dest, std::move(v));
}

void exec_state_facade::insert(audio_parameter& dest, const audio_port& v)
{
  impl->insert(dest, v);
}

void exec_state_facade::insert(net::parameter_base& dest, const midi_port& v)
{
  impl->insert(dest, v);
}

void exec_state_facade::insert(const state& v)
{
  impl->insert(v);
}
}
