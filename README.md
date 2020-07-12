# lazy-crypto
Fetch yaml-cpp
git submodule init
git submodule update

# Build and Run
mkdir build
cd build
cmake ..
make 

# Running AES test
make run_aes_smoke_test

# Running ExpModM test
make run_arith_smoke_test
