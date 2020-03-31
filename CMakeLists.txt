cmake_minimum_required(VERSION 3.10)

project(IPA VERSION 0.0)

configure_file(IPAConfig.h.in IPAConfig.h)

set(LIBS)

# add the library siffex
add_library(sniffex src/sniffex.c)
target_include_directories(sniffex 
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
list(APPEND LIBS sniffex)

# set executable
add_executable(IPA src/main.c)

target_include_directories(IPA 
    PUBLIC ${PROJECT_BINARY_DIR}
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(IPA
    PUBLIC pcap
    PRIVATE ${LIBS}
)
