# Selectable k-TimesAnonymous Authentication, k-TAA

This repository is for the paper "Efficient Anonymous Counting Authentication for Secure Cloud-Fog Computing".

## Requirements
To compile the code, you need to install the following libraries:
- PBC library (version 0.5.14): https://crypto.stanford.edu/pbc/
- GMP library (version 6.3.0): https://gmplib.org/

## Compile the code
```bash
cd build 
make clean
cmake .. && make
```
## Run the code
```bash
../bin/emura
../bin/hwg
../bin/ours
../bin/pairing_test
```

## Contact
For questions or issues, please contact:
- Jianye Huang (huangjianye@ioccs.cn)
- Hequn Xian (xianhequn@ioccs.cn) 
- Yang Zhang (zhangyang@ioccs.cn)
