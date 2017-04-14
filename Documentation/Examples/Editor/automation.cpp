#include <ossia/ossia.hpp>

int main()
{
  using namespace ossia;

  // Create a device with a single address
  ossia::net::generic_device device{std::make_unique<ossia::net::local_protocol>(), "app"};
  auto address = ossia::net::create_node(device, "/the_float").createAddress(ossia::val_type::FLOAT);

  // Log a message when something is pushed on the address
  address->add_callback([] (const auto& value) {
    ossia::logger().info("Received value: {}", value);
  });

  // Create the temporal structure
  auto start_node = std::make_shared<time_node>();
  auto end_node = std::make_shared<time_node>();

  auto start_event = *(start_node->emplace(start_node->timeEvents().begin(), {}));
  auto end_event = *(end_node->emplace(end_node->timeEvents().begin(), {}));

  // Our process will play for five seconds
  auto constraint =
      std::make_shared<time_constraint>(
        [] (auto t, auto t2, const auto& state) { state.launch(); },
        *start_event, *end_event, 5000._tv, 5000._tv, 5000._tv);

  // The curve that we want to play. Do one curve per address.
  auto behaviour = std::make_shared<curve<double, float>>();

  behaviour->setInitialPointAbscissa(0.);
  behaviour->setInitialPointOrdinate(0.);
  behaviour->addPoint(curve_segment_linear<float>{}, 0.5, 1.);
  behaviour->addPoint(curve_segment_ease<float, easing::circularOut>{}, 1., 0.);

  constraint->addTimeProcess(std::make_unique<automation>(*address, behaviour));

  constraint->setSpeed(1._tv);
  constraint->setGranularity(50._tv); // In milliseconds.

  // Start the execution. It runs in its own separate thread.
  constraint->start();
  while (constraint->getRunning())
      ;
  constraint->stop();

  // The execution resets to zero:
  constraint->start();
  while (constraint->getRunning())
      ;
  constraint->stop();

  // We can have the execution perform manually, too,
  // for instance for use with an external clock source
  constraint->setDriveMode(clock::DriveMode::EXTERNAL);
  constraint->start();
  for(int i = 0; i < 1000; i++)
  {
    // Tick every 100 microseconds
    constraint->tick(100._tv);
  }
  constraint->stop();

  std::cerr << std::flush;
  return 0;
}
