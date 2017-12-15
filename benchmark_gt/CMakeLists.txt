cmake_minimum_required(VERSION 3.2)
project(BENCHMARK_GT)
set(CMAKE_CXX_STANDARD 11)
add_subdirectory(libgm)
add_subdirectory(libpaillier)
set(MCL_INCLUDE ../mcl/)
include_directories(${MCL_INCLUDE}/include)
link_directories(${MCL_INCLUDE}/build/lib)
set(mcl ../mcl/build/lib/libmcl.a)
add_executable(bench_paillier_gt bench_paillier_gt.cpp)
target_link_libraries(bench_paillier_gt boost_system paillier gmp pthread)

set(ECC_LIB mcl gmp gmpxx crypto)

add_executable(bench_ecc_gt bench_ecc_gt.cpp)
target_link_libraries(bench_ecc_gt boost_system pthread ${ECC_LIB})

add_executable(bench_gm_gt bench_gm_gt.cpp)
target_link_libraries(bench_gm_gt gm gmp)
