
file( GLOB SOURCES "*.cpp")

add_executable(test ${SOURCES})

target_link_libraries(test
    Keystore.SDK
)
