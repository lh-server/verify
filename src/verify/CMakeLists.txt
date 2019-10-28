set(APP_NAME verifier)
set(APP_SRC  verifier.cpp)

add_executable(${APP_NAME} ${APP_SRC})
target_link_libraries(${APP_NAME} ${BOTAN_LIBRARY})
INSTALL(TARGETS ${APP_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX})