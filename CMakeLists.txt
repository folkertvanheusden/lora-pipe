project(lora-pipe)
cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(
  lora-pipe
  lp.cpp
  libLoRaPi/src/lora.cpp
  libLoRaPi/src/packet.cpp
)

#set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(lora-pipe Threads::Threads wiringPi)
target_include_directories(lora-pipe PUBLIC libLoRaPi/src/include/)
