add_executable(min min_main.cpp common/min.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(min
        MOTION::motion
        Boost::program_options
        )
