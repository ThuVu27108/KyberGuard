# Tests and Verification

> **Provenance Notice:**
> The original unit test suite (covering byte conversions, CBD sampling, polynomial arithmetic, compression, encoding, and basic KEM operations) was authored by **Pyry L** ([https://github.com/PyryL/kyber](https://github.com/PyryL/kyber)).
> In this enhanced repository, we preserve all original tests and expand testing with **NTT correctness verification, side-channel attack evaluations (Timing & DPA), and benchmark comparisons**.

---

## 1. Unit Tests

Unit tests rigorously examine each function and module individually using both fixed deterministic test vectors and random inputs. In addition to testing correct flows, functions are tested to ensure they raise proper exceptions (`ValueError`, assertions) when provided with malformed or tampered inputs.

### Test Suite Execution

Run all unit tests using `pytest` or `invoke`:

```bash
pytest -v
# or
poetry run invoke test
```

### Test Suite Coverage

```text
tests/test_byte_conversion.py ........          [ 11%]
tests/test_cbd.py .....                         [ 18%]
tests/test_ccakem.py .....                      [ 25%]
tests/test_compression.py ......                [ 34%]
tests/test_decrypt.py ...                       [ 38%]
tests/test_encoding.py .......                  [ 48%]
tests/test_encrypt.py ...                       [ 52%]
tests/test_encryption.py .                      [ 54%]
tests/test_key_generation.py ..                 [ 57%]
tests/test_parse.py ...                         [ 61%]
tests/test_polring.py .........                 [ 74%]
tests/test_pseudo_random.py .................   [ 98%]
tests/test_round.py .                           [100%]

================= 70 passed in 3.00s =================
```

### Code Coverage

Coverage can be analyzed and generated via:

```bash
poetry run invoke coverage-report
```

This generates an HTML report in `htmlcov/index.html`. All core arithmetic and cryptographic modules maintain complete statement and branch coverage.

---

## 2. Correctness Verification of NTT Blinding

Because side-channel masking introduces randomized vectors $\hat{\mathbf{r}}$ into the critical decryption path, rigorous verification is required to guarantee that plaintext recovery is never corrupted.

The verification routine (`verify_correctness` in `side_channel_poc.py` and Step 1 of `demo_comparison.py`) executes end-to-end decapsulation trials across randomly generated keypairs:

$$\forall (\text{sk}, c): \quad \texttt{decrypt\_ntt}(\text{sk}, c) \equiv \texttt{decrypt\_ntt\_blinded}(\text{sk}, c)$$

### Algebraic Invariant
$$\left(v + \hat{\mathbf{r}}^\top \mathbf{u}\right) - (\mathbf{s} + \hat{\mathbf{r}})^\top \mathbf{u} = v - \mathbf{s}^\top \mathbf{u} \pmod q$$

### Execution
```bash
python -X utf8 demo_comparison.py --quick
```

**Result:**
```text
BUOC 1 - VERIFY: Ket qua hai phien ban phai giong het nhau
Trial  1: [PASS]  m = ec0dbecdb264e936fe364cdb...
Trial  2: [PASS]  m = 6febd165be0f620f2e849d08...
...
Trial  8: [PASS]  m = 2d57a01b2a5b9d80aaac2d92...
Ket qua: TAT CA PASS
```

---

## 3. Side-Channel Security Evaluation Tests

### Differential Power Analysis (DPA) Quick Test
A standalone test script `test_dpa_quick.py` evaluates the correlation between the attacker's Hamming Weight oracle and simulated power traces:

```bash
python -X utf8 test_dpa_quick.py
```

* **Pass Criteria:**
  - Unprotected NTT correlation: $|r| > 0.5$ (vulnerability confirmed).
  - NTT Blinding correlation: $|r| < 0.3$ (target: $|r| < 0.1$, attack blocked).
  - Correlation reduction: $> 80\%$.

### Full Side-Channel Evaluation (Timing + DPA)
```bash
python -X utf8 demo_comparison.py --samples 60
```

Evaluates both:
1. **Timing Attack:** Decryption time Coefficient of Variation ($CV$) and Pearson correlation $r(\text{timing}, \text{oracle})$.
2. **DPA Simulation:** Target base-mul Hamming Weight correlation over $N=60$ trials. Blinding reduces $|r|$ from $0.9534$ to $0.0167$ ($98.2\%$ reduction).

---

## 4. Performance & Integration Benchmarks

1. **Kyber CCA-KEM Benchmark (`perf_tests/test_ccakem.py`):**
   Iterates end-to-end keygen, encrypt, and decrypt across hundreds of cycles.
   ```bash
   poetry run invoke performance
   ```

2. **Bulk CPAPKE Encryption (`perf_tests/test_encryption.py`):**
   Tests splitting variable-length payloads ($\sim 10$ KiB) into 32-byte chunks, encrypting, and reassembling.

3. **AES-GCM Hybrid Integration (`perf_tests/test_aes_integration.py`):**
   Demonstrates practical integration where Kyber encapsulates a 256-bit symmetric key, followed by AES-256-GCM data encryption.

4. **Blinding Overhead Benchmark (`demo_comparison.py`):**
   Compares execution timing between `decrypt_ntt()` and `decrypt_ntt_blinded()`. Empirically confirms an overhead of only $+7.5\%$, satisfying the research requirement of $< 20\%$.
