"""
Wrapper giu tuong thich cho cac module cu neu co import tu decrypt_ntt_blinded.
Khuyen nghi su dung truc tiep:
    from kyber.encryption.decrypt import decrypt
    from kyber.encryption.decrypt_blinded import decrypt_blinded
"""

from kyber.encryption.decrypt import decrypt, decrypt_ntt
from kyber.encryption.decrypt_blinded import decrypt_blinded, decrypt_ntt_blinded
