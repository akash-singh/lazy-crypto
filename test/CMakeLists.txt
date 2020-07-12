include_directories (${PROJECT_SOURCE_DIR}/src/include)

add_executable(aes_test ${CMAKE_CURRENT_LIST_DIR}/aes_test.cpp)
add_executable(arith_test ${CMAKE_CURRENT_LIST_DIR}/arith_test.cpp)

target_link_libraries (aes_test yaml-cpp lazy-crypto)
target_link_libraries (arith_test yaml-cpp lazy-crypto)

add_custom_target(run_aes_smoke_test
    COMMAND aes_test ${PROJECT_SOURCE_DIR}/test/aes_test_vectors.yml
    DEPENDS aes_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_custom_target(run_arith_smoke_test
    COMMAND arith_test ${PROJECT_SOURCE_DIR}/test/bigInt_test_vectors.yml
    DEPENDS arith_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)