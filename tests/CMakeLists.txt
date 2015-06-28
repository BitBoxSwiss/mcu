include_directories(../src)

#-----------------------------------------------------------------------------
# Build tests_unit
add_executable(tests_unit tests_unit.c)
target_link_libraries(tests_unit bitbox)


#-----------------------------------------------------------------------------
# Build tests_openssl
include_directories(${OPENSSL_INCLUDE_DIR})
add_executable(tests_openssl tests_openssl.c)
target_link_libraries(tests_openssl bitbox ${OPENSSL_LIBRARIES})


#-----------------------------------------------------------------------------
# Build tests_cmdline
add_executable(tests_cmdline tests_cmdline.c)
target_link_libraries(tests_cmdline bitbox)


#-----------------------------------------------------------------------------
# Build tests_api
if(NOT CONTINUOUS_INTEGRATION)
  include_directories(${HIDAPI_INCLUDE_DIR})
endif()

add_executable(tests_api tests_api.c)

if(NOT CONTINUOUS_INTEGRATION)
  target_link_libraries(tests_api bitbox ${HIDAPI_LIBRARY})
else()
  target_link_libraries(tests_api bitbox)
endif()
