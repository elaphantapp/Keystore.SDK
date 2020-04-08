cmake_minimum_required(VERSION 3.12)

include(config/cmake/CMakeLists.txt)

project(Keystore.SDK)
add_subdirectory(thirdparty)
add_subdirectory(crypto)

if(DEFINED CFG_WITH_TEST)
    add_subdirectory(test)
endif()

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/Keystore.SDK.pc.in
	${CMAKE_CURRENT_BINARY_DIR}/Keystore.SDK.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Keystore.SDK.pc DESTINATION lib/pkgconfig)
