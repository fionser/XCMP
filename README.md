# XCMP
non-interactive and output eXpressive private CoMParison Protocol

## Requirements
* c++ compiler
* cmake
* boost
* [NTL](http://www.shoup.net/ntl/)

## BUILD
* Pull all the submodules `git submodule update --init --recursive`
* Build XCMP main in `PrivateDecisionTree` directory
    * mkdir build & cp build
    * cmake .. -DCMAKE_BUILD_TYPE=Release & make
* The benchmark of other comparison protocols require MCL
    * cd mcl
    * mkdir build & cp build
    * cmake .. -DCMAKE_BUILD_TYPE=Release & make
* Build the benchmark for other comparision protocols
    * cd benchmark_gt
    * mkdir build & cp build
    * cmake .. -DCMAKE_BUILD_TYPE=Release & make
