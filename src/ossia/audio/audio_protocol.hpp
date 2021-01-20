#pragma once
#include <ossia/audio/audio_parameter.hpp>
#include <ossia/network/base/protocol.hpp>
#include <ossia/network/generic/generic_device.hpp>

#include <readerwriterqueue.h>
#include <smallfun.hpp>

#include <ossia-config.hpp>

namespace ossia
{
class audio_protocol;
class OSSIA_EXPORT audio_engine
{
public:
  audio_engine();
  virtual ~audio_engine();

  virtual bool running() const = 0;
  virtual void stop() = 0;
  virtual void reload(audio_protocol* cur) = 0;



  using fun_type = smallfun::function<void(unsigned long, double), 256>;
  void set_tick(fun_type&& t);
  void load_audio_tick();

  moodycamel::ReaderWriterQueue<fun_type> tick_funlist;
  fun_type audio_tick;

  std::atomic<audio_protocol*> protocol{};
  std::atomic_bool stop_processing{};
  std::atomic_bool processing{};

  int effective_sample_rate{};
  int effective_buffer_size{};
};

class OSSIA_EXPORT audio_protocol final : public ossia::net::protocol_base
{
public:
  static void process_generic(
      audio_protocol& self, float* const* inputs, float** outputs, int n_in,
      int n_out, uint64_t nsamples);

  audio_protocol();
  ~audio_protocol() override;
  void stop() override;

  void setup_tree(int inputs, int outputs);
  void advance_tick(std::size_t count);

  bool pull(ossia::net::parameter_base&) override;
  bool push(const ossia::net::parameter_base&, const ossia::value& v) override;
  bool
  push_bundle(const std::vector<const ossia::net::parameter_base*>&) override;
  bool push_raw(const ossia::net::full_parameter_data&) override;
  bool push_raw_bundle(
      const std::vector<ossia::net::full_parameter_data>&) override;
  bool observe(ossia::net::parameter_base&, bool) override;
  bool update(ossia::net::node_base& node_base) override;
  void set_device(ossia::net::device_base& dev) override;

  void register_parameter(mapped_audio_parameter& p);
  void unregister_parameter(mapped_audio_parameter& p);
  void register_parameter(virtual_audio_parameter& p);
  void unregister_parameter(virtual_audio_parameter& p);

  ossia::net::device_base& get_device() const
  {
    return *m_dev;
  }
  ossia::audio_parameter* main_audio_in{};
  ossia::audio_parameter* main_audio_out{};
  std::vector<ossia::audio_parameter*> audio_ins;
  std::vector<ossia::audio_parameter*> audio_outs;

  std::vector<ossia::mapped_audio_parameter*> in_mappings;
  std::vector<ossia::mapped_audio_parameter*> out_mappings;
  std::vector<ossia::virtual_audio_parameter*> virtaudio;
  audio_engine* engine{};

protected:
  ossia::net::device_base* m_dev{};

  moodycamel::ReaderWriterQueue<smallfun::function<void()>> funlist;
};

class OSSIA_EXPORT audio_device
{
public:
  audio_device(std::string name = "audio");
  audio_device(std::unique_ptr<audio_protocol>, std::string name = "audio");
  ~audio_device();

  ossia::audio_parameter& get_main_in();
  ossia::audio_parameter& get_main_out();

  int get_buffer_size() const;
  int get_sample_rate() const;

  std::unique_ptr<ossia::audio_engine> engine;
  ossia::net::generic_device device;
  ossia::audio_protocol& protocol;

private:
  int m_bs{}, m_sr{};
};

OSSIA_EXPORT
ossia::audio_engine* make_audio_engine(
    std::string proto, std::string name, std::string req_in,
    std::string req_out, int& inputs, int& outputs, int& rate, int& bs);
}
