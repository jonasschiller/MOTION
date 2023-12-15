add_executable(share_conversion share_conversion_main.cpp common/share_conversion.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(share_conversion
        MOTION::motion
        Boost::program_options
        )
