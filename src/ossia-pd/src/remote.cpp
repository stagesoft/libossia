// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <ossia/network/common/path.hpp>

#include <ossia-pd/src/ossia-pd.hpp>
#include <ossia-pd/src/remote.hpp>
#include <ossia-pd/src/utils.hpp>

namespace ossia::pd
{

#pragma mark t_remote

remote::remote()
    : parameter_base{ossia_pd::remote_class}
{
}

bool remote::register_node(const std::vector<t_matcher>& matchers)
{
  if(m_mute)
    return false;

  if(!m_name)
    return false;

  update_path();

  bool res = do_registration(matchers);
  if(res)
  {
    obj_dequarantining<remote>(this);
    bang(this);
    clock_set(m_poll_clock, 1);
  }
  else if(!m_is_pattern)
    obj_quarantining<remote>(this);

  if(m_is_pattern)
  {
    // TODO support cross device remote,
    // for example *:/foo should match each foo node on all root devices
    std::pair<int, ossia::pd::device*> device{};
    device.second = find_parent_alive<ossia::pd::device>(this, 0, &device.first);

    std::pair<int, ossia::pd::client*> client{};
    client.second = find_parent_alive<ossia::pd::client>(this, 0, &client.first);

    std::vector<std::pair<int, object_base*>> vec{device, client};
    // sort pair by ascending order : closest one first
    std::sort(vec.begin(), vec.end());

    ossia::net::device_base* dev{};

    for(auto& p : vec)
    {
      if(p.second)
      {
        dev = p.second->m_device;
        break;
      }
    }

    if(dev == nullptr)
      dev = ossia_pd::get_default_device();

    if(dev != m_dev)
    {
      if(m_dev)
      {
        m_dev->on_parameter_created.disconnect<&remote::on_parameter_created_callback>(
            this);
        m_dev->get_root_node()
            .about_to_be_deleted.disconnect<&remote::on_device_deleted>(this);
      }
      m_dev = dev;
      m_dev->on_parameter_created.connect<&remote::on_parameter_created_callback>(this);
      m_dev->get_root_node().about_to_be_deleted.connect<&remote::on_device_deleted>(
          this);

      obj_dequarantining<remote>(this);
    }
  }

  return res;
}

bool remote::do_registration(const std::vector<t_matcher>& matchers)
{
  unregister();

  std::string name = m_name->s_name;

  for(auto& m : matchers)
  {
    auto node = m.get_node();

    if(m_addr_scope == net::address_scope::absolute)
    {
      // get root node
      node = &node->get_device().get_root_node();
      // and remove starting '/'
      name = name.substr(1);
    }

    m_parent_node = node;

    std::vector<ossia::net::node_base*> nodes{};

    if(m_addr_scope == net::address_scope::global)
      nodes = ossia::pd::find_global_nodes(name);
    else
      nodes = ossia::net::find_nodes(*node, name);

    m_matchers.reserve(m_matchers.size() + nodes.size());

    for(auto n : nodes)
    {

      bool continue_flag = false;

      // avoid to register the same node twice
      for(auto& m : m_matchers)
      {
        if(m.get_node() == n && m.get_owner() == this)
        {
          continue_flag = true;
          break;
        }
      }

      if(continue_flag)
        continue;

      if(n->get_parameter())
      {

        m_matchers.emplace_back(n, this);
      }
      else
      {

        // if there is a node without parameter it might be a model
        // then look if that node have an eponyme child
        n = ossia::net::find_node(*n, fmt::format("{}/{}", name, name));

        if(n && n->get_parameter())
        {
          m_matchers.emplace_back(node, this);
        }
      }

      if(!n)
        continue;

      if(n->get_parameter()->get_value_type() != ossia::val_type::IMPULSE)
      {
        auto& m = m_matchers.back();

        const auto& map = ossia_pd::instance().m_root_patcher;
        auto it = map.find(m_patcher_hierarchy.back());

        if(it != map.end() && it->second.is_loadbanged)
        {
          m.enqueue_value(n->get_parameter()->value());
          m.output_value();
        }
      }
    }
  }

  fill_selection();

  // do not put it in quarantine if it's a pattern
  // and even if it can't find any matching node
  return (!m_matchers.empty() || m_is_pattern);
}

bool remote::unregister()
{
  clock_unset(m_poll_clock);

  m_matchers.clear();

  obj_quarantining<remote>(this);

  m_parent_node = nullptr;
  if(m_dev)
  {
    m_dev->on_parameter_created.disconnect<&remote::on_parameter_created_callback>(this);
    m_dev->get_root_node().about_to_be_deleted.disconnect<&remote::on_device_deleted>(
        this);
  }
  m_dev = nullptr;
  return true;
}

void remote::on_parameter_created_callback(const ossia::net::parameter_base& param)
{
  auto& node = param.get_node();

  if(m_path && ossia::traversal::match(*m_path, node))
  {
    m_parent_node = node.get_parent();
    m_matchers.emplace_back(&node, this);
    fill_selection();
  }
}

void remote::set_unit()
{
  if(m_unit != gensym(""))
  {
    ossia::unit_t unit = ossia::parse_pretty_unit(m_unit->s_name);
    if(unit)
      m_ounit = unit;
    else
    {
      pd_error(this, "wrong unit: %s", m_unit->s_name);
      m_ounit = std::nullopt;
      m_unit = gensym("");
      return;
    }

    for(auto m : m_node_selection)
    {
      if(m->get_node()->get_parameter()->get_value_type() != ossia::val_type::IMPULSE)
      {
        auto dst_unit = m->get_node()->get_parameter()->get_unit();
        if(!ossia::check_units_convertible(*m_ounit, dst_unit))
        {
          auto src = ossia::get_pretty_unit_text(*m_ounit);
          auto dst = ossia::get_pretty_unit_text(dst_unit);
          pd_error(
              this, "sorry I don't know how to convert '%s' into '%s'", src.data(),
              dst.data());
          m_ounit = std::nullopt;
          m_unit = gensym("");
          break;
        }
        else
        {
          m->enqueue_value(m->get_node()->get_parameter()->value());
          m->output_value();
        }
      }
    }
  }
  else
  {
    m_ounit = std::nullopt;
  }
}

void remote::set_rate()
{
  m_rate = m_rate < m_rate_min ? m_rate_min : m_rate;
}

void remote::get_unit(remote* x)
{
  t_atom a;
  if(x->m_unit)
  {
    SETSYMBOL(&a, x->m_unit);
    outlet_anything(x->m_dumpout, gensym("unit"), 1, &a);
  }
  else
    outlet_anything(x->m_dumpout, gensym("unit"), 0, NULL);
}

void remote::get_mute(remote* x)
{
  t_atom a;
  SETFLOAT(&a, x->m_mute);
  outlet_anything(x->m_dumpout, gensym("mute"), 1, &a);
}

void remote::get_rate(remote* x)
{
  t_atom a;
  SETFLOAT(&a, x->m_rate);
  outlet_anything(x->m_dumpout, gensym("rate"), 1, &a);
}

void remote::on_device_deleted(const net::node_base&)
{
  m_dev = nullptr;
}

t_pd_err remote::notify(remote* x, t_symbol* s, t_symbol* msg, void* sender, void* data)
{
  if(msg == gensym("attr_modified"))
  {
    if(s == gensym("unit"))
      x->set_unit();
    else if(s == gensym("mute"))
    {
      if(x->m_mute)
        x->unregister();
      else
        ossia_register(x);
    }
    else
      parameter_base::notify((parameter_base*)x, s, msg, sender, data);
  }
  return {};
}

void remote::click(
    remote* x, t_floatarg xpos, t_floatarg ypos, t_floatarg shift, t_floatarg ctrl,
    t_floatarg alt)
{

  using namespace std::chrono;
  milliseconds ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
  milliseconds diff = (ms - x->m_last_click);
  if(diff.count() < 200)
  {
    x->m_last_click = milliseconds(0);

    if(!object_base::find_and_display_friend(x))
      pd_error(x, "sorry I can't find a connected friend :-(");
  }
  else
  {
    x->m_last_click = ms;
  }
}

void* remote::create(t_symbol* name, int argc, t_atom* argv)
{
  auto& ossia_pd = ossia_pd::instance();
  remote* x = new remote();

  t_binbuf* d = binbuf_via_atoms(argc, argv);

  if(x && d)
  {
    x->m_otype = object_class::remote;
    x->m_setout = outlet_new((t_object*)x, nullptr);
    x->m_dataout = outlet_new((t_object*)x, nullptr);
    x->m_dumpout = outlet_new((t_object*)x, gensym("dumpout"));

    if(argc != 0 && argv[0].a_type == A_SYMBOL)
    {
      t_symbol* address = atom_getsymbol(argv);
      std::string _name = replace_brackets(address->s_name);
      x->m_name = gensym(_name.c_str());
      x->m_addr_scope = ossia::net::get_address_scope(x->m_name->s_name);
    }

    x->m_poll_clock = clock_new(x, (t_method)parameter_base::output_value);

    ebox_attrprocess_viabinbuf(x, d);

    if(x->m_name)
    {

#ifdef OSSIA_PD_BENCHMARK
      std::cout << measure<>::execution(obj_register<remote>, x) / 1000. << " ms "
                << " " << x << " remote " << x->m_name->s_name << " " << x->m_reg_count
                << std::endl;
#else
      ossia_check_and_register(x);
#endif
    }

    ossia_pd.remotes.push_back(x);
  }

  return (x);
}

void remote::destroy(remote* x)
{
  x->m_dead = true;
  x->unregister();
  obj_dequarantining<remote>(x);
  ossia_pd::instance().remotes.remove_all(x);

  if(x->m_is_pattern && x->m_dev)
  {
    x->m_dev->on_parameter_created.disconnect<&remote::on_parameter_created_callback>(x);
    x->m_dev->get_root_node().about_to_be_deleted.disconnect<&remote::on_device_deleted>(
        x);
  }

  clock_free(x->m_poll_clock);

  outlet_free(x->m_setout);
  outlet_free(x->m_dataout);
  outlet_free(x->m_dumpout);

  x->~remote();
}

void remote::update_attribute(
    remote* x, ossia::string_view attribute, const ossia::net::node_base* node)
{
  // @mute and @unit attributes are specific to each remote
  // it makes no sens to sens to change when an attribute changes
  if(attribute == ossia::net::text_refresh_rate())
  {
    for(auto m : x->m_node_selection)
    {
      outlet_anything(x->m_dumpout, gensym("address"), 1, m->get_atom_addr_ptr());

      auto rate = ossia::net::get_refresh_rate(*m->get_node());
      if(rate)
      {
        x->m_rate_min = *rate;
        x->m_rate = x->m_rate < x->m_rate_min ? x->m_rate_min : x->m_rate;
      }

      t_atom a;
      SETFLOAT(&a, x->m_rate);
      outlet_anything(x->m_dumpout, gensym("rate"), 1, &a);
    }
  }
  else if(attribute == ossia::net::text_unit())
  {
    for(auto m : x->m_node_selection)
    {
      outlet_anything(x->m_dumpout, gensym("address"), 1, m->get_atom_addr_ptr());
      ossia::net::parameter_base* param = m->get_node()->get_parameter();

      if(x->m_ounit && !ossia::check_units_convertible(param->get_unit(), *x->m_ounit))
      {
        x->m_ounit = param->get_unit();
        auto unit = ossia::get_pretty_unit_text(param->get_unit());
        x->m_unit = gensym(unit.data());
      }
    }
  }
  else
  {
    parameter_base::update_attribute(x, attribute, node);
  }
}

void remote::get_mess_cb(remote* x, t_symbol* s)
{
  if(s == gensym("unit"))
    remote::get_unit(x);
  if(s == gensym("mute"))
    remote::get_mute(x);
  if(s == gensym("rate"))
    remote::get_rate(x);
  else
    parameter_base::get_mess_cb(x, s);
}

extern "C" void setup_ossia0x2eremote(void)
{
  t_eclass* c = eclass_new(
      "ossia.remote", (method)ossia::pd::remote::create,
      (method)ossia::pd::remote::destroy, (short)sizeof(remote), CLASS_DEFAULT, A_GIMME,
      0);

  if(c)
  {
    class_addcreator((t_newmethod)remote::create, gensym("ø.remote"), A_GIMME, 0);

    parameter_base::class_setup(c);

    eclass_addmethod(c, (method)remote::click, "click", A_NULL, 0);
    eclass_addmethod(c, (method)remote::notify, "notify", A_NULL, 0);
    eclass_addmethod(c, (method)address_mess_cb<remote>, "address", A_SYMBOL, 0);

    CLASS_ATTR_DEFAULT(c, "unit", 0, "");

    // remote special attributes
    eclass_addmethod(c, (method)remote::get_mess_cb, "get", A_SYMBOL, 0);

#ifndef PURR_DATA
    eclass_register(CLASS_OBJ, c);
#endif
  }

  ossia_pd::remote_class = c;
}

ossia::safe_set<remote*>& remote::quarantine()
{
  return ossia_pd::instance().remote_quarantine;
}

} // ossia namespace
