import numpy as np
from kyber.utils.compression import compress, decompress
from kyber.utils.encoding import encode, decode
from kyber.utils.ntt import (
    ntt, intt,
    dot_product_ntt,
    polring_to_list,
)
from kyber.constants import n, k, du, dv, q
from kyber.entities.polring import PolynomialRing

def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Giai ma Kyber ban goc (chuan NTT theo FIPS 203, chua them mat na bao ve).

    :param private_key: Khoa bi mat CPAPKE (32*12*k bytes).
    :param ciphertext:  Ban ma (du*k*n//8 + dv*n//8 bytes).
    :returns:           32 bytes plaintext (shared secret m).
    :raises ValueError: Neu do dai input sai.
    """
    if len(private_key) != 32 * 12 * k:
        raise ValueError(f"private_key len={len(private_key)}, expected {32*12*k}")
    if len(ciphertext) != du * k * n // 8 + dv * n // 8:
        raise ValueError(f"ciphertext len={len(ciphertext)}, expected {du*k*n//8 + dv*n//8}")

    s_pols = decode(private_key, 12)
    u_bytes = ciphertext[: du * k * n // 8]
    v_bytes = ciphertext[du * k * n // 8 :]
    u_pols = [decompress(pol, du) for pol in decode(u_bytes, du)]
    v_pol  = decompress(decode(v_bytes, dv)[0], dv)

    # Chuyen doi sang mien NTT
    s_hat = [ntt(polring_to_list(p)) for p in s_pols]
    u_hat = [ntt(polring_to_list(p)) for p in u_pols]
    v_coefs = polring_to_list(v_pol)

    # Tich vo huong trong mien NTT
    s_u_hat = dot_product_ntt(s_hat, u_hat)
    s_dot_u = intt(s_u_hat)

    # m = v - s^T * u
    m_coefs = [(v_coefs[j] - s_dot_u[j]) % q for j in range(n)]
    m_pol   = PolynomialRing(m_coefs, check_limits=True)
    return encode(compress([m_pol], 1), 1)

# Alias tuong thich nguoc neu can
decrypt_ntt = decrypt
