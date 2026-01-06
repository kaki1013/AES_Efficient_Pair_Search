# AES_Efficient_Pair_Search

This repository contains the source code used in the paper **"Efficient Pair Search Techniques for Zero Difference-Based AES Cryptanalysis"**. It provides implementations of various experimental methods for efficient pair searching in AES differential cryptanalysis.

## Overview

Several differential cryptanalysis techniques on AES require the search for ciphertext or plaintext pairs that exhibit **zero difference** in certain byte positions. Existing approaches include hash table-based methods and sorting-based methods.

However, when the number of candidate byte values to be checked exceeds the number of available plaintexts, traditional hash-based techniques become impractical. This work addresses this limitation and makes the following contributions:

- **Experimental validation** that hash-based and sort-based methods have similar performance when applicable.
- **A novel hash-based technique** that remains effective even when the number of candidate values exceeds the number of plaintexts.
- Utilizes custom hash function design, chaining, and memory pool techniques to improve performance.

### Key Findings

- Achieves comparable performance to merge sort.
- Approximately **1.3× slower** than quicksort.
- Approximately **5.3× faster** than implementations using C++ STL's `unordered_map`.

## Directory Structure

```

AES_Efficient_Pair_Search/
├── cpp/         # C++ implementation with custom hash table approach
│   ├── aes_tdc.c / .h
│   ├── ciphertools.h
│   ├── testsource.cpp
│   └── Makefile
├── diag1/       # Experiment 1 (C-based)
│   ├── aes_tdc.c
│   ├── ciphertools.h
│   ├── testsource.c
│   └── Makefile
└── diag2/       # Experiment 2 (C-based)
    ├── aes_tdc.c
    ├── ciphertools.h
    ├── testsource.c
    └── Makefile

````

## How to Build and Run

Navigate into any of the subdirectories (`cpp/`, `diag1/`, or `diag2/`) and execute:

```bash
make
./test
````

The entry point is typically `testsource.c` or `testsource.cpp`.

## Requirements

* GCC
* `make` utility

## Citation

This code was developed as part of the experiments in the following paper:

> Lee, M., Shin, H., Kim, I., Kim, S., Kwon, D., Hong, D., Sung, J., & Hong, S. (2025).
> Hash Table Method for Data Search in Differential Cryptanalysis.
> *Journal of The Korea Institute of Information Security and Cryptology*, 35(6), 1297–1308.

## License

This project is intended for academic and research use only. If no explicit license is provided, it is made available under a non-commercial, research-only usage policy.
