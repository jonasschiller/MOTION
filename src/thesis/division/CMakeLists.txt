add_executable(division division_main.cpp common/division.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(division
        MOTION::motion
        Boost::program_options
        )
