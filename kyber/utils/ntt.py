"""
ntt.py
======
Number Theoretic Transform (NTT) chuan Kyber cho vong da thuc R_q.

Tham so Kyber:
    q    = 3329  -- modulus
    n    = 256   -- so he so da thuc
    zeta = 17    -- can nguyen thuy bac-256 mod q
                    (17^128 = -1 mod q, 17^256 = 1 mod q)

Ly thuyet:
    x^256 + 1 phan tich thanh 128 nhan tu bac-2 trong Z_q[x]:
        x^256 + 1 = prod_{i=0}^{127} (x^2 - zeta^(2*bitrev7(i)+1))  mod q

    NTT anh xa da thuc f(x) in R_q sang 128 cap he so
    (f_hat[2i], f_hat[2i+1]) la phan du trong Z_q[x]/(x^2 - zeta_i).

Hieu nang:
    - ntt / intt:   O(n log n) = 256 * 7 ~ 1792 phep tinh
    - mul_ntt:      O(n)       = 128 base-mul  (nhanh hon schoolbook O(n^2)=65536x ~128 lan)
    - Blinding chi them 1 dot_product_ntt (~O(k*n)) thay vi 1 matmul polynomial

Tham chieu:
    CRYSTALS-Kyber specification v3.02, Algorithm 1-4.
    https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
"""

from kyber.constants import q, n

# ==============================================================================
# Hang so NTT (tinh truoc de tranh tinh lai moi lan)
# ==============================================================================

_ZETA = 17       # can nguyen thuy bac-256 mod q  (17^128=-1, 17^256=1)
_INV128 = 3303   # pow(128, -1, 3329) -- dung de chuan hoa INTT


def _bitrev7(i: int) -> int:
    """Dao bit 7-bit (bit-reversal permutation cho n=128 stages)."""
    return int(f"{i:07b}"[::-1], 2)


# ZETAS[k] = zeta^bitrev7(k) mod q, k = 0..127
# Dung trong butterfly NTT / INTT
ZETAS: list[int] = [pow(_ZETA, _bitrev7(k), q) for k in range(128)]

# ZETA_BASEMUL[i] = zeta^(2*bitrev7(i)+1) mod q, i = 0..127
# Dung trong base multiplication tai cap thu i
ZETA_BASEMUL: list[int] = [pow(_ZETA, 2 * _bitrev7(i) + 1, q) for i in range(128)]


# ==============================================================================
# Forward NTT -- Algorithm 1 theo Kyber spec
# ==============================================================================

def ntt(f: list[int]) -> list[int]:
    """
    Forward NTT: chuyen [f_0, ..., f_255] in R_q sang bieu dien NTT.

    Thuat toan: Cooley-Tukey in-place butterfly, 7 tang, bit-reversed order.
    Input/Output: list 256 so nguyen mod q.
    Do phuc tap: O(n log n).

    Khong sua doi input (tao ban sao).
    """
    assert len(f) == n, f"NTT: len={len(f)} != n={n}"
    f = list(f)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < n:
            z = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = z * f[j + length] % q
                f[j + length] = (f[j] - t) % q
                f[j]          = (f[j] + t) % q
            start += 2 * length
        length >>= 1
    return f


# ==============================================================================
# Inverse NTT -- Algorithm 2 theo Kyber spec
# ==============================================================================

def intt(f_hat: list[int]) -> list[int]:
    """
    Inverse NTT: chuyen bieu dien NTT ve da thuc f(x) in R_q.

    Thuat toan: Gentleman-Sande in-place butterfly, 7 tang, normal order.
    Input/Output: list 256 so nguyen mod q.
    Do phuc tap: O(n log n).

    Khong sua doi input (tao ban sao).
    """
    assert len(f_hat) == n, f"INTT: len={len(f_hat)} != n={n}"
    f = list(f_hat)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < n:
            z = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j]          = (t + f[j + length]) % q
                f[j + length] = (z * (f[j + length] - t)) % q
            start += 2 * length
        length <<= 1
    return [c * _INV128 % q for c in f]


# ==============================================================================
# Base multiplication: nhan trong Z_q[x]/(x^2 - zeta)
# ==============================================================================

def _basemul(a0: int, a1: int, b0: int, b1: int, zeta: int) -> tuple[int, int]:
    """
    Nhan (a0 + a1*x)*(b0 + b1*x) mod (x^2 - zeta) trong Z_q.

    Ket qua: c0 = a0*b0 + a1*b1*zeta, c1 = a0*b1 + a1*b0  (mod q)
    Chi 4 phep nhan + 2 phep cong -- rat nhanh!
    """
    c0 = (a0 * b0 + a1 * b1 * zeta) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1


# ==============================================================================
# Phep tinh NTT domain
# ==============================================================================

def mul_ntt(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """
    Nhan hai NTT-domain: h_hat = f_hat (*) g_hat.

    KHONG can NTT hay INTT them.
    Thuc hien 128 base-mul (moi 4 phep nhan) => tong 512 phep nhan mod q.
    So voi schoolbook: 256*256 = 65536 phep nhan (nhanh hon ~128 lan!).

    Input:  f_hat, g_hat -- list[256 int] (NTT domain)
    Output: h_hat        -- list[256 int] (NTT domain)
    """
    assert len(f_hat) == len(g_hat) == n
    h = [0] * n
    for i in range(128):
        zeta = ZETA_BASEMUL[i]
        h[2*i], h[2*i+1] = _basemul(
            f_hat[2*i], f_hat[2*i+1],
            g_hat[2*i], g_hat[2*i+1],
            zeta,
        )
    return h


def add_ntt(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """Cong hai NTT domain (he so-wise mod q). O(n)."""
    return [(a + b) % q for a, b in zip(f_hat, g_hat)]


def sub_ntt(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """Tru hai NTT domain (he so-wise mod q). O(n)."""
    return [(a - b) % q for a, b in zip(f_hat, g_hat)]


def zero_ntt() -> list[int]:
    """Tra ve phan tu 0 trong NTT domain (phong bao cho tich vo huong)."""
    return [0] * n


# ==============================================================================
# Tich vo huong NTT (inner product)
# ==============================================================================

def dot_product_ntt(
    vec_a: list[list[int]],
    vec_b: list[list[int]],
) -> list[int]:
    """
    Tich vo huong cua hai vector NTT:
        result_hat = sum_i(mul_ntt(vec_a[i], vec_b[i]))

    Tat ca phep tinh trong NTT domain => O(k * n).
    (Khong ton them chi phi NTT/INTT -- cac input da o NTT domain.)

    Input:  vec_a, vec_b  --  list cua k  list[256 int]
    Output: list[256 int] (NTT domain, chua INTT)
    """
    assert len(vec_a) == len(vec_b) > 0
    result = zero_ntt()
    for a_hat, b_hat in zip(vec_a, vec_b):
        result = add_ntt(result, mul_ntt(a_hat, b_hat))
    return result


# ==============================================================================
# Helper: chuyen PolynomialRing <-> list[int]
# ==============================================================================

def polring_to_list(pol, length: int = n) -> list[int]:
    """
    Chuyen PolynomialRing sang list he so do dai `length` (pad 0 neu can).
    Ap dung mod q de dam bao he so trong [0, q-1].
    """
    coefs = list(pol.coefs)
    if len(coefs) < length:
        coefs += [0] * (length - len(coefs))
    return [int(c) % q for c in coefs[:length]]
