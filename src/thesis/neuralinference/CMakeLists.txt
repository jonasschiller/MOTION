add_executable(neuralinference neuralinference_main.cpp common/neuralinference.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(neuralinference
        MOTION::motion
        Boost::program_options
        )
