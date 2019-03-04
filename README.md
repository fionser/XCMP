# XCMP
non-interactive and output eXpressive private CoMParison Protocol

Implementation of our [paper](https://dl.acm.org/citation.cfm?doid=3196494.3196503).

Also, provide the SEAL version for XCMP, see [here](SEAL/main.cpp).


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
