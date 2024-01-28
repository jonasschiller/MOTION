add_executable(reveal reveal_main.cpp common/reveal.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(reveal
        MOTION::motion
        Boost::program_options
        )
