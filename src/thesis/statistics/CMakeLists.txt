add_executable(statistics statistics_main.cpp common/statistics.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(statistics
        MOTION::motion
        Boost::program_options
        )
