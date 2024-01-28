add_executable(share share_main.cpp common/share.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(share
        MOTION::motion
        Boost::program_options
        )
