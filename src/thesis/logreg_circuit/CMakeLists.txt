add_executable(logreg logreg_main.cpp common/logreg.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(logreg
        MOTION::motion
        Boost::program_options
        )
