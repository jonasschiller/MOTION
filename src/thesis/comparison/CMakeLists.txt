add_executable(comparison comparison_main.cpp common/comparison.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(comparison
        MOTION::motion
        Boost::program_options
        )
