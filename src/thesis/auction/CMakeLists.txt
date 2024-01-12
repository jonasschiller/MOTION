add_executable(auction auction_main.cpp  common/auction.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(auction
        MOTION::motion
        Boost::program_options
        )
