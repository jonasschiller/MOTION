add_executable(fixedpt_div fixedpt_div_main.cpp common/fixedpt_div.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(fixedpt_div
        MOTION::motion
        Boost::program_options
        )
