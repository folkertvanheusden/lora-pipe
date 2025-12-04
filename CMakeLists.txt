project(lora-pipe)
cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(
  meshcore STATIC
  meshcore-c/meshcore/payload/request.c
  meshcore-c/meshcore/payload/grp_txt.c
  meshcore-c/meshcore/payload/ack.c
  meshcore-c/meshcore/payload/advert.c
  meshcore-c/meshcore/chat/grp_payload.c
  meshcore-c/meshcore/packet.c
  meshcore-c/crypto/sha256.c
  meshcore-c/crypto/hmac_sha256.c
  meshcore-c/crypto/aes.c
)

target_include_directories(meshcore PUBLIC meshcore-c/meshcore/)

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
target_link_libraries(lora-pipe Threads::Threads wiringPi meshcore)
target_include_directories(lora-pipe PUBLIC libLoRaPi/src/include/)

include(FindPkgConfig)

pkg_check_modules(MQTT REQUIRED libmosquitto)
target_link_libraries(lora-pipe ${MQTT_LIBRARIES})
target_include_directories(lora-pipe PUBLIC ${MQTT_INCLUDE_DIRS})
target_compile_options(lora-pipe PUBLIC ${MQTT_CFLAGS_OTHER})

pkg_check_modules(NCURSES REQUIRED ncursesw)
target_link_libraries(lora-pipe ${NCURSES_LIBRARIES})
target_include_directories(lora-pipe PUBLIC ${NCURSES_INCLUDE_DIRS})
target_compile_options(lora-pipe PUBLIC ${NCURSES_CFLAGS_OTHER})
