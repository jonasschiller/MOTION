add_executable(addition addition_main.cpp common/addition.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(addition
        MOTION::motion
        Boost::program_options
        )
