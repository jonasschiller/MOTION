add_executable(benchmark_multiplication benchmark_multiplication_main.cpp common/benchmark_multiplication.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_multiplication
        MOTION::motion
        Boost::program_options
        )
