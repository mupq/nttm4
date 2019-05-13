# nttm4
This code package contains the software accompanying the paper "Memory-Efficient High-Speed Implementation of Kyber on Cortex-M4". The paper is available at XXX

# Setup 

The setup is mostly similar to https://github.com/mupq/pqm4.
After having installed all the dependences run
```
git clone --recurse-submodules  https://github.com/mupq/nttm4
cd nttm4
cd libopencm3 && make &  cd ..
make 
```

# Testing and Benchmarking 
Running `make` will produce the binaries `bin/{test, speed, stack}_kyber{512,768,1024}_m4round{1,2}.bin`, where: 

**Type**
- `test` provides basic funcionality testing (i.e., checks that both parties derive the same shared secret)
- `speed` benchmarkes the schemes and outputs cycles counts (Table 2 in the paper)
- `stack` measures the stack usage (Table 3 in the paper)

**Parameter Set**
- `kyber512`, `kyber768`, and `kyber1024` refer to the different parameter sets of Kyber aiming for NIST security level 1, 3, and 5 respectively. 

**Version**
- `round1` implements Kyber compatible with the [first round NIST submission](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/CRYSTALS_Kyber.zip)
- `round2` implements Kyber compatibl with the [second round NIST submission](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-2/submissions/CRYSTALS-Kyber-Round2.zip) (i.e., no public key compression, ciphertext in NTT domain, `q=3329`, `eta=2`, different NTT)
