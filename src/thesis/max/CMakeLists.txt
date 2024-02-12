add_executable(max max_main.cpp common/max.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(max
        MOTION::motion
        Boost::program_options
        )
