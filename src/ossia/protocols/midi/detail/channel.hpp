#pragma once
#include <array>
#include <cinttypes>
#include <utility>
namespace ossia::net::midi
{
using midi_size_t = uint8_t;
class midi_parameter;
struct midi_channel
{
  // [ note, vel ]
  std::pair<midi_size_t, midi_size_t> note_on{};
  std::pair<midi_size_t, midi_size_t> note_off{};

  // [ CC, value ]
  std::pair<midi_size_t, midi_size_t> cc{};

  // PC
  midi_size_t pc{};

  // PB
  int32_t pb{};

  // velocity or value
  std::array<midi_size_t, 128> note_on_N = {{64}};
  std::array<midi_size_t, 128> note_off_N = {{64}};
  std::array<midi_size_t, 128> cc_N = {{64}};
  // No need to store PC since they are only impulses

  // Callbacks
  midi_parameter* param_note_on{};
  midi_parameter* param_note_off{};
  midi_parameter* param_cc{};
  midi_parameter* param_pc{};
  midi_parameter* param_pb{};
  std::array<midi_parameter*, 128> param_note_on_N = {{}};
  std::array<midi_parameter*, 128> param_note_off_N = {{}};
  std::array<midi_parameter*, 128> param_cc_N = {{}};
  std::array<midi_parameter*, 128> param_pc_N = {{}};

  bool callback_note_on{};
  bool callback_note_off{};
  bool callback_cc{};
  bool callback_pc{};
  bool callback_pb{};
  std::array<bool, 128> callback_note_on_N = {{}};
  std::array<bool, 128> callback_note_off_N = {{}};
  std::array<bool, 128> callback_cc_N = {{}};
  std::array<bool, 128> callback_pc_N = {{}};
};
}
