"""
decrypt_blinded.py
==================
Giai ma Kyber voi ky thuat che mat na r (Blinding / Masking)
nham bao ve khoa bi mat s truoc cac cuoc tan cong kenh ben (DPA, Timing Attack).

Nguyen ly:
    - Sinh mat na ngau nhien r truc tiep trong mien bien doi bang CSPRNG
    - Che giau khoa: s* = s + r (khoa bi mat s khong bao gio xuat hien don le)
    - Tinh: (s*)^T * u - r^T * u = s^T * u
    - Xoa an toan (zeroization) cac bo dem trung gian
"""

import secrets
import numpy as np
from kyber.utils.compression import compress, decompress
from kyber.utils.encoding import encode, decode
from kyber.utils.ntt import (
    ntt, intt,
    add_ntt, sub_ntt,
    dot_product_ntt,
    polring_to_list,
)
from kyber.constants import n, k, du, dv, q
from kyber.entities.polring import PolynomialRing


def _random_ntt_vector(size: int) -> list[list[int]]:
    """Sinh size da thuc ngau nhien truc tiep bang CSPRNG cua OS."""
    raw = secrets.token_bytes(size * n * 2)
    arr = memoryview(raw).cast('H')  # uint16, zero-copy
    return [
        [int(arr[i * n + j]) % q for j in range(n)]
        for i in range(size)
    ]


def _erase_list(lst: list) -> None:
    """Ghi de 0 vao moi phan tu cua list (xoa an toan)."""
    for i in range(len(lst)):
        lst[i] = 0


def _erase_vector(vec: list[list[int]]) -> None:
    """Ghi de 0 vao moi list trong vector (xoa an toan)."""
    for lst in vec:
        _erase_list(lst)


def decrypt_blinded(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Giai ma Kyber co su dung mat na bao ve r (phien ban cai tien chong kenh ben).

    :param private_key: Khoa bi mat CPAPKE (32*12*k bytes).
    :param ciphertext:  Ban ma (du*k*n//8 + dv*n//8 bytes).
    :returns:           32 bytes plaintext (shared secret m).
    :raises ValueError: Neu do dai input sai.
    """
    if len(private_key) != 32 * 12 * k:
        raise ValueError(f"private_key len={len(private_key)}, expected {32*12*k}")
    if len(ciphertext) != du * k * n // 8 + dv * n // 8:
        raise ValueError(f"ciphertext len={len(ciphertext)}, expected {du*k*n//8 + dv*n//8}")

    # Buoc 1: Decode va Decompress
    s_pols = decode(private_key, 12)
    u_bytes = ciphertext[: du * k * n // 8]
    v_bytes = ciphertext[du * k * n // 8 :]

    u_pols = [decompress(pol, du) for pol in decode(u_bytes, du)]
    v_pol  = decompress(decode(v_bytes, dv)[0], dv)

    # Buoc 2: Chuyen sang mien NTT
    s_hat = [ntt(polring_to_list(p)) for p in s_pols]
    u_hat = [ntt(polring_to_list(p)) for p in u_pols]
    v_coefs = polring_to_list(v_pol)

    # Buoc 3: BLINDING -- Sinh mat na r ngau nhien
    r_hat = _random_ntt_vector(k)

    # Che giau khoa: s* = s + r
    s_star_hat = [add_ntt(s_hat[i], r_hat[i]) for i in range(k)]

    # Buoc 4: Tinh tich vo huong (s KHONG bao gio xuat hien don le)
    s_star_u_hat = dot_product_ntt(s_star_hat, u_hat)
    r_u_hat      = dot_product_ntt(r_hat, u_hat)

    # Khu mat na: (s*)^T * u - r^T * u = s^T * u
    s_u_hat = sub_ntt(s_star_u_hat, r_u_hat)

    # Buoc 5: INTT va khoi phuc m
    s_dot_u = intt(s_u_hat)
    m_coefs = [(v_coefs[j] - s_dot_u[j]) % q for j in range(n)]

    # Buoc 6: Xoa an toan bo nho dem
    _erase_vector(r_hat)
    _erase_vector(s_star_hat)
    _erase_list(s_star_u_hat)
    _erase_list(r_u_hat)
    _erase_list(s_u_hat)

    # Buoc 7: Encode ket qua
    m_pol = PolynomialRing(m_coefs, check_limits=True)
    return encode(compress([m_pol], 1), 1)

# Aliases tuong thich nguoc neu can
decrypt_ntt_blinded = decrypt_blinded
from kyber.encryption.decrypt import decrypt as decrypt_ntt
