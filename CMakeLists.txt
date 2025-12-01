cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

project(TMTLogger C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_DIR   ${CMAKE_SOURCE_DIR}/src)
set(BPF_DIR   ${SRC_DIR}/bpf)
set(USER_DIR  ${SRC_DIR}/user)
set(BIN_DIR   ${CMAKE_BINARY_DIR}/bin)
set(OUT_DIR   ${CMAKE_SOURCE_DIR}/out)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

# vmlinux.h generation
find_program(BPFTOOL_EXECUTABLE NAMES bpftool)
if(NOT BPFTOOL_EXECUTABLE)
    message(FATAL_ERROR "bpftool not found. Please install bpftool to generate vmlinux.h")
endif()

set(BUILD_BPF_INCLUDE_DIR ${CMAKE_BINARY_DIR}/include/bpf)
file(MAKE_DIRECTORY ${BUILD_BPF_INCLUDE_DIR})

set(VMLINUX_H ${BUILD_BPF_INCLUDE_DIR}/vmlinux.h)

message(STATUS "Generating vmlinux.h at: ${VMLINUX_H}")

execute_process(
    COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c
    OUTPUT_FILE ${VMLINUX_H}
    RESULT_VARIABLE VMLINUX_RES
)

if(NOT VMLINUX_RES EQUAL 0)
    message(FATAL_ERROR "Failed to generate vmlinux.h with bpftool (exit code ${VMLINUX_RES})")
endif()

set(SRC_BPF_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include/bpf)
file(MAKE_DIRECTORY ${SRC_BPF_INCLUDE_DIR})
file(COPY ${VMLINUX_H} DESTINATION ${SRC_BPF_INCLUDE_DIR})
message(STATUS "Copied vmlinux.h to: ${SRC_BPF_INCLUDE_DIR}")

# args library via FetchContent
include(FetchContent)

FetchContent_Declare(
    args
    GIT_REPOSITORY https://github.com/Taywee/args.git
    GIT_TAG 6.4.7
)

set(ARGS_BUILD_EXAMPLE OFF CACHE INTERNAL "")
set(ARGS_BUILD_UNITTESTS OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(args)

# BPF compilation
set(BPF_SOURCES
    ${BPF_DIR}/execve.bpf.c
    ${BPF_DIR}/fork.bpf.c
    ${BPF_DIR}/exit.bpf.c
    ${BPF_DIR}/clone.bpf.c
    ${BPF_DIR}/clone3.bpf.c
    ${BPF_DIR}/exit_group.bpf.c
    ${BPF_DIR}/sched_switch.bpf.c
)

set(BPF_OBJECTS)

foreach(bpf_src ${BPF_SOURCES})
    get_filename_component(bpf_we ${bpf_src} NAME_WE)
    string(REPLACE ".bpf" "" bpf_short ${bpf_we})

    set(bpf_obj ${BIN_DIR}/${bpf_short}.bpf.o)

    add_custom_command(
        OUTPUT ${bpf_obj}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${BIN_DIR}
        COMMAND clang -O2 -g -target bpf -D__TARGET_ARCH_x86
            -I${CMAKE_SOURCE_DIR}/include/bpf
            -I${BUILD_BPF_INCLUDE_DIR}
            -I/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
            -c ${bpf_src}
            -o ${bpf_obj}
        DEPENDS ${bpf_src} ${VMLINUX_H}
        COMMENT "Building BPF object ${bpf_short}.bpf.o"
        VERBATIM
    )

    list(APPEND BPF_OBJECTS ${bpf_obj})
endforeach()

add_custom_target(bpf_objects ALL DEPENDS ${BPF_OBJECTS})

# Userland sources
set(USER_SOURCES
    ${CMAKE_SOURCE_DIR}/main.cpp
    ${USER_DIR}/logger/SyscallLogger.cpp
    ${USER_DIR}/processors/EventProcessor.cpp
    ${USER_DIR}/processors/SwitchProcessor.cpp
    ${USER_DIR}/handlers/BaseHandler.cpp
    ${USER_DIR}/handlers/ExecveHandler.cpp
    ${USER_DIR}/handlers/ForkHandler.cpp
    ${USER_DIR}/handlers/ExitHandler.cpp
    ${USER_DIR}/handlers/CloneHandler.cpp
    ${USER_DIR}/handlers/Clone3Handler.cpp
    ${USER_DIR}/handlers/ExitGroupHandler.cpp
    ${USER_DIR}/handlers/SwitchHandler.cpp
)

add_executable(tmt_logger ${USER_SOURCES})
add_dependencies(tmt_logger bpf_objects)

target_include_directories(tmt_logger PRIVATE
    ${USER_DIR}
    ${CMAKE_SOURCE_DIR}/include/user/common
    ${CMAKE_SOURCE_DIR}/include/user/handlers
    ${CMAKE_SOURCE_DIR}/include/user/logger
    ${CMAKE_SOURCE_DIR}/include/user/processors
    ${args_SOURCE_DIR}
)

# libbpf + pthread
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBBPF libbpf)
endif()

find_package(Threads REQUIRED)

if(LIBBPF_FOUND)
    target_include_directories(tmt_logger PRIVATE ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(tmt_logger PRIVATE ${LIBBPF_LIBRARIES} Threads::Threads)
else()
    target_link_libraries(tmt_logger PRIVATE bpf elf z Threads::Threads)
endif()

target_link_directories(tmt_logger PRIVATE /usr/lib64)

set_target_properties(tmt_logger PROPERTIES
    BUILD_RPATH "/usr/lib64;/usr/local/lib"
)

file(MAKE_DIRECTORY ${OUT_DIR})


# gnuplot
find_program(GNUPLOT_EXECUTABLE NAMES gnuplot)

option(TMT_ENABLE_PLOTS "Enable gnuplot plot targets" ON)

if(TMT_ENABLE_PLOTS)
    if(GNUPLOT_EXECUTABLE)
        message(STATUS "Found gnuplot: ${GNUPLOT_EXECUTABLE}")
        set(PLOTS_DIR ${CMAKE_SOURCE_DIR}/plots)

        add_custom_target(plot_threads_over_time
            COMMAND ${GNUPLOT_EXECUTABLE}
                -c ${PLOTS_DIR}/threads_over_time.gp
                "${OUT_DIR}/oncpu_slices.csv"
                "${OUT_DIR}/alive_series.csv"
                "${OUT_DIR}/threads_over_time.png"
            DEPENDS tmt_logger
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating threads_over_time plot with gnuplot"
        )

        add_custom_target(plots_all
            DEPENDS plot_threads_over_time
        )
    else()
        message(STATUS "Gnuplot not found: plot targets will be stubs")

        add_custom_target(plots_all
            COMMAND ${CMAKE_COMMAND} -E echo "Gnuplot not available. Install it and reconfigure to enable plotting."
        )
    endif()
endif()


add_custom_target(run
    COMMAND sudo -E $<TARGET_FILE:tmt_logger> --cmd "sleep 1" --print-raw
    DEPENDS tmt_logger
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
