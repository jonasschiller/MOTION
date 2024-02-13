add_executable(auction_hycc auction_h_main.cpp common/auction_h.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(auction_hycc
        MOTION::motion
        Boost::program_options
        )
