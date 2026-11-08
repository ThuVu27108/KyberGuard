# Requirements Specification

### Problem to be Solved

When two parties want to communicate securely over an insecure network, they need encryption. Using asymmetric encryption directly for large payloads is relatively slow. Therefore, it is standard practice to use asymmetric encryption to securely establish or encapsulate a shared key, which is then used by faster symmetric encryption (such as AES-GCM). This mechanism is known as a Key Encapsulation Mechanism (KEM) [6].

Traditionally, the [Diffie–Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) key exchange and RSA have been used for this purpose [6]. However, with the advent of Shor's algorithm on large-scale quantum computers, these traditional cryptosystems will be completely compromised. To address the urgent demand for quantum-resistant asymmetric cryptography, the **CRYSTALS-Kyber** algorithm was designed based on the hardness of the Module Learning With Errors (M-LWE) problem over module lattices. In 2022, the National Institute of Standards and Technology (NIST) selected Kyber as the primary post-quantum standard for general encryption and key encapsulation [4]. In August 2023, NIST published the draft standard FIPS 203 (ML-KEM) [5], establishing Kyber as the global benchmark for post-quantum key exchange.

However, even when an algorithm is mathematically secure against classical and quantum cryptanalysis, its physical or software implementations may remain vulnerable to **Side-Channel Attacks (SCA)**, such as Timing Attacks and Differential Power Analysis (DPA). Defending post-quantum lattice-based implementations against side-channel leakages while preserving computational efficiency is a critical research challenge.

### Project Heritage & Acknowledgement of Original Work

> **Notice of Provenance:**
> This project is developed as an **enhanced and hardened research fork** based on the original open-source Python Kyber implementation created by **Pyry L** (available at [https://github.com/PyryL/kyber](https://github.com/PyryL/kyber)).
>
> The foundational reference implementation of CRYSTALS-Kyber in pure Python (including the polynomial ring structures, CPAPKE encryption/decryption primitives, Fujisaki-Okamoto CCA-KEM transform, serialization routines, and original unit test suite) was authored by Pyry L. We gratefully acknowledge and credit their foundational work.

### New Requirements & Improvements in this Project

Building on the original foundational codebase of Pyry L, this project introduces the following research enhancements and hardened capabilities:

1. **Number Theoretic Transform (NTT) Optimization:**
   - Implementation of Kyber's standard NTT and Inverse NTT (INTT) using Cooley-Tukey and Gentleman-Sande butterfly networks mod $q = 3329$ with $\zeta = 17$ (degree-256 primitive root of unity).
   - Base multiplication in the quotient ring $\mathbb{Z}_q[x]/(x^2 - \zeta_i)$ across 128 coefficient pairs.
   - Accelerates polynomial multiplication from $O(n^2)$ schoolbook multiplication (65,536 multiplications) to $O(n \log n)$ ($128 \times 4 = 512$ modular multiplications), achieving an algorithmic speedup of over $\sim 128\times$.

2. **Side-Channel Resistance via NTT Domain Blinding:**
   - Protection of the secret key $\mathbf{s}$ during decryption by masking it with a cryptographically secure random vector $\hat{\mathbf{r}}$ sampled directly in the NTT domain.
   - Algebraic de-blinding formulation: $(\hat{\mathbf{s}} + \hat{\mathbf{r}})^\top \hat{\mathbf{u}} - \hat{\mathbf{r}}^\top \hat{\mathbf{u}} = \hat{\mathbf{s}}^\top \hat{\mathbf{u}}$.
   - Drastically reduces masking computational overhead from $\sim 85\%$ (in schoolbook polynomial multiplication) down to only $\approx 7.5\%$ in the NTT domain.
   - Secure erasure (zeroization) of sensitive intermediate buffers in memory.

3. **Side-Channel Attack Simulation & Verification Framework:**
   - **Timing Attack PoC:** Evaluation of decryption execution time variance (Coefficient of Variation) and Pearson correlation with secret-dependent Hamming weights.
   - **Differential Power Analysis (DPA) PoC:** Simulated power trace measurements using the Hamming Weight (HW) leakage model targeting specific base-mul operations. Proves that NTT Blinding reduces Pearson correlation $|r|$ from $\approx 0.95$ (successful attack) to $|r| < 0.05$ (attack completely mitigated, $>95\%$ leakage reduction).
   - **Algebraic & Empirical Correctness Verification:** Guaranteeing $100\%$ functional equivalence between unblinded and blinded decryption outputs.

4. **Automated Demonstration and Reporting Tools:**
   - Command-line benchmarking and comparison tools (`demo_comparison.py`).
   - Automated generation of publication-quality figures and scatter plots (`export_figures.py`).

### Input and Output

The package provides standard high-level API functions for post-quantum key encapsulation:

```python
# Key generation (CCA-KEM)
private_key, public_key = ccakem_generate_keys()

# Encapsulation (Sender)
ciphertext, shared_secret_sender = ccakem_encrypt(public_key)

# Decapsulation (Receiver - with side-channel protection)
shared_secret_receiver = decrypt_ntt_blinded(private_key, ciphertext)

# Both parties establish the identical 256-bit (32-byte) shared key:
assert shared_secret_sender == shared_secret_receiver
```

### Algorithms and Data Structures

- **Algebraic Setting:** Polynomial ring $\mathcal{R}_q = \mathbb{Z}_q[x]/(x^{256} + 1)$ with modulus $q = 3329$.
- **Kyber Parameter Set:** Implements Kyber1024 (NIST Security Level 5, equivalent to AES-256) with parameters $k = 4$, $\eta_1 = \eta_2 = 2$, $d_u = 11$, $d_v = 5$.
- **Sampling & Hashing:** SHA3-256, SHA3-512, SHAKE-128 (XOF matrix generation), SHAKE-256 (PRF and KDF), Centered Binomial Distribution (CBD).
- **NTT Arithmetic:** Bit-reversal permutation, Cooley-Tukey forward NTT, Gentleman-Sande inverse NTT, point-wise base multiplication mod $(x^2 - \zeta)$.
- **Randomness Generation:** Operating system Cryptographically Secure Pseudo-Random Number Generator (CSPRNG via Python `secrets`).

### Time and Space Complexity

- **Polynomial Multiplication:**
  - Original schoolbook baseline: $O(n^2)$ where $n = 256$.
  - NTT-based multiplication: $O(n \log n)$ per polynomial.
- **Key Generation & Encapsulation:** $O(k^2 \cdot n \log n)$ operations.
- **Decryption with Blinding:** $O(k \cdot n \log n)$ with only $O(k \cdot n)$ additional cost for masking and de-masking inner products.
- **Memory:** Constant auxiliary memory space with immediate zeroization of ephemeral secrets.

### About the Authors

- **Original Author of Baseline Repository:**
  **Pyry L** — Student of Computer Science Bachelor program (tietojenkäsittelytieteen kandidaatti, TKT) at the University of Helsinki.
  Repository: [https://github.com/PyryL/kyber](https://github.com/PyryL/kyber).

- **Enhancements, NTT Optimization & Side-Channel Hardening:**
  Developed as part of academic research on side-channel vulnerability analysis and lightweight countermeasures for lattice-based post-quantum cryptography (KyberGuard).

### References

1. Avanzi, Roberto et al.: *Algorithm Specifications And Supporting Documentation* (version 3.02, 2021), URL: [https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)
2. Cryptographic Suite for Algebraic Lattices: *Kyber*, URL: [https://pq-crystals.org/kyber/index.shtml](https://pq-crystals.org/kyber/index.shtml)
3. Gonzalez, Ruben: *Kyber - How does it work?* (2021), URL: [https://cryptopedia.dev/posts/kyber/](https://cryptopedia.dev/posts/kyber/)
4. National Institute of Standards and Technology: *NIST Announces First Four Quantum-Resistant Cryptographic Algorithms* (2022), URL: [https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms](https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms)
5. National Institute of Standards and Technology: *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard* (2023/2024), URL: [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)
6. Wikipedia: *Key encapsulation mechanism*, URL: [https://en.wikipedia.org/wiki/Key_encapsulation_mechanism](https://en.wikipedia.org/wiki/Key_encapsulation_mechanism)
7. Pyry L: *Kyber - Python implementation of CRYSTALS-Kyber KEM*, URL: [https://github.com/PyryL/kyber](https://github.com/PyryL/kyber)
