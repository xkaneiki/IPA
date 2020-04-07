cmake_minimum_required(VERSION 3.10)

project(IPA VERSION 0.0)

configure_file(IPAConfig.h.in IPAConfig.h)

set(LIBS)

# add the library sniffex
add_library(sniffex src/sniffex.c)
target_include_directories(sniffex 
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
list(APPEND LIBS sniffex)

# add the library hash
add_library(hash src/hash.c)
target_include_directories(hash 
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
list(APPEND LIBS hash)

# add the library correlation
add_library(correlation src/correlation.c)
target_include_directories(correlation 
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
list(APPEND LIBS correlation)

# add the library myrbtree
add_library(myrbtree src/myrbtree.c)
target_include_directories(myrbtree 
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
list(APPEND LIBS myrbtree)

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
