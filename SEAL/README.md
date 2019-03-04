## Implementation XCMP on [SEAL](https://github.com/Microsoft/SEAL)

* Also implement the domain extension tech from Ishimaki et al. 's paper _Non-Interactive and Fully Output Expressive Private Comparison_.
  * Basically, take advantage automorphism to erase terms of encrypted polynomial, and keepping only the constant term.
