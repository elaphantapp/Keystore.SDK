pkg_search_module(pkg-openssl REQUIRED openssl)
message(STATUS "openssl include path: ${pkg-openssl_INCLUDE_DIRS}")
message(STATUS "openssl library path: ${pkg-openssl_STATIC_LDFLAGS}")

file( GLOB Keystore.SDK-SOURCES "*.cpp" "*.c")
file( GLOB Keystore.SDK-HEADERS "bip39.h" )

add_library(Keystore.SDK)
target_sources(Keystore.SDK PRIVATE
	${Keystore.SDK-SOURCES})
target_sources(Keystore.SDK PRIVATE
	$<TARGET_OBJECTS:thirdparty>)
target_include_directories(Keystore.SDK PRIVATE
	"${pkg-openssl_INCLUDE_DIRS}"
	"${CMAKE_CURRENT_SOURCE_DIR}/secp256k1"
	"${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include")
target_link_libraries(Keystore.SDK PUBLIC
	${pkg-openssl_STATIC_LDFLAGS})
target_link_libraries(Keystore.SDK PRIVATE
    thirdparty)
if("${CFG_TARGET_PLATFORM}" STREQUAL "Android")
    target_link_libraries(Keystore.SDK PRIVATE log)
endif()

set_target_properties(Keystore.SDK PROPERTIES PUBLIC_HEADER "${Keystore.SDK-HEADERS}")
install(TARGETS Keystore.SDK
		RUNTIME DESTINATION bin
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		PUBLIC_HEADER DESTINATION include/Keystore.SDK)
