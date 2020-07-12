
include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

add_library (lazy-crypto
    ${CMAKE_CURRENT_LIST_DIR}/aes_block_cipher.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arith.cpp
)
