add_executable(LeNet LeNet_main.cpp common/LeNet.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(LeNet
        MOTION::motion
        Boost::program_options
        )
