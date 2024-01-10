add_executable(psi psi.cpp common/psi.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(psi
        MOTION::motion
        Boost::program_options
        )
