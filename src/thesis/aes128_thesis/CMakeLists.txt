add_executable(aes128_thesis aes128_main.cpp common/aes128.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(aes128_thesis
        MOTION::motion
        Boost::program_options
        )
