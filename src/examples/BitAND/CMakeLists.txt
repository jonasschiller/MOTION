add_executable(BitAnd BitAnd_main.cpp common/BitAnd.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(BitAnd
        MOTION::motion
        Boost::program_options
        )
