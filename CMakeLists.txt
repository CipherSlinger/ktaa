cmake_minimum_required (VERSION 3.5.1)
  
project(KTAA
        VERSION 0.1
        LANGUAGES CXX)

# add_subdirectory(src)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
include_directories( ${PROJECT_SOURCE_DIR}/include )
include_directories(  /usr/local/include/pbc/ )

link_directories( /usr/local/lib/ )
link_libraries( gmp pbc )

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_executable( pairing_test test.cpp 
        ./src/Group.cpp 
        ./src/Pairing.cpp 
        ./src/SHA256.cpp 
        ./src/Zr.cpp 
        ./src/Timer.cpp)

add_executable( emura emura.cpp 
        ./src/Group.cpp 
        ./src/Pairing.cpp 
        ./src/SHA256.cpp 
        ./src/Zr.cpp 
        ./src/Timer.cpp)

add_executable( hwg hwg.cpp 
        ./src/Group.cpp 
        ./src/Pairing.cpp 
        ./src/SHA256.cpp 
        ./src/Zr.cpp 
        ./src/Timer.cpp)

add_executable( ours ours.cpp 
        ./src/Group.cpp 
        ./src/Pairing.cpp 
        ./src/SHA256.cpp 
        ./src/Zr.cpp 
        ./src/Timer.cpp)