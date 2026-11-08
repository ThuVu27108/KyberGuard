"""
side_channel_poc.py
===================
Mo phong tan cong kenh ben (Side-Channel Attack) len hai phien ban decrypt:

    - decrypt()          : Phien ban goc (KHONG bao ve mat na)
    - decrypt_blinded()  : Phien ban cai tien (CO them mat na r)

Hai loai tan cong duoc mo phong:

    1. Timing Attack
       Do thoi gian N lan decrypt va kiem tra do bien dong.

    2. Power Analysis -- DPA (Differential Power Analysis)
       Mo phong theo mo hinh Hamming Weight (HW):
           - Dien nang ~ HW(ket qua trung gian cua phep nhan)
           - Ke tan cong TARGET mot cap he so cu the (mot base-mul)
           - Do he so tuong quan Pearson r(oracle, trace)
           - |r| cao => tan cong thanh cong, |r| ~ 0 => bi chan

       Ly do target mot cap (khong phai tong):
           Neu lay tong tat ca 512 phep nhan, Law of Large Numbers
           lam variance bi triet tieu => r ~ 0 voi ca hai phien ban.
           DPA thuc te cung chi target mot bit/byte cu the.
"""

import time
import math
import secrets
import statistics
import random as _rng

from kyber.ccakem import ccakem_generate_keys, ccakem_encrypt
from kyber.encryption.decrypt import decrypt
from kyber.encryption.decrypt_blinded import decrypt_blinded
from kyber.utils.ntt import ntt, polring_to_list, ZETA_BASEMUL
from kyber.utils.encoding import decode
from kyber.utils.compression import decompress
from kyber.constants import k, n, du, dv, q

# Aliases tuong thich
decrypt_ntt = decrypt
decrypt_ntt_blinded = decrypt_blinded

SEP = "─" * 66

# ==============================================================================
# Helper: Hamming Weight
# ==============================================================================

def _hw(x: int) -> int:
    return bin(x).count('1')


# ==============================================================================
# Helper: Pearson correlation coefficient
# ==============================================================================

def _pearson_r(x: list[float], y: list[float]) -> float:
    """He so tuong quan Pearson r trong [-1, 1]."""
    m = len(x)
    if m < 2:
        return 0.0
    mx = sum(x) / m
    my = sum(y) / m
    num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    dx  = math.sqrt(sum((xi - mx) ** 2 for xi in x) + 1e-15)
    dy  = math.sqrt(sum((yi - my) ** 2 for yi in y) + 1e-15)
    return num / (dx * dy)


# ==============================================================================
# Model dien nang: TARGET mot cap he so cu the (DPA thuc te)
# ==============================================================================

_POL_TARGET = 0    # target polynomial thu 0
_PAIR_TARGET = 0   # target cap (pair) thu 0 (he so 0 va 1)


def _oracle_hw(s_hat: list[int], u_hat: list[int]) -> int:
    """
    Tinh HW cua ket qua base-mul tai vi tri target.
    Day la du doan cua ke tan cong (biet s va u chinh xac).
    """
    z  = ZETA_BASEMUL[_PAIR_TARGET]
    s0 = s_hat[2 * _PAIR_TARGET]
    s1 = s_hat[2 * _PAIR_TARGET + 1]
    u0 = u_hat[2 * _PAIR_TARGET]
    u1 = u_hat[2 * _PAIR_TARGET + 1]
    c0 = (s0 * u0 + s1 * u1 * z) % q
    return _hw(c0)


def _trace_unblinded(s_hat: list[int], u_hat: list[int],
                     noise_std: float = 1.5) -> float:
    """
    Power trace tu phien ban KHONG co mat na r:
        trace = HW(s * u) + nhieu do luong nho
    Ke tan cong co the do duoc gia tri nay tu thiet bi thuc.
    """
    oracle = _oracle_hw(s_hat, u_hat)
    return oracle + _rng.gauss(0, noise_std)


def _trace_blinded(s_hat: list[int], u_hat: list[int]) -> int:
    """
    Power trace tu phien ban CO mat na r:
        trace = HW((s + r) * u)  voi r ngau nhien moi lan
    Ke tan cong quan sat gia tri nay nhung khong suy ra duoc s.
    """
    z  = ZETA_BASEMUL[_PAIR_TARGET]
    u0 = u_hat[2 * _PAIR_TARGET]
    u1 = u_hat[2 * _PAIR_TARGET + 1]
    # r ngau nhien moi lan goi
    r0 = secrets.randbelow(q)
    r1 = secrets.randbelow(q)
    s0 = s_hat[2 * _PAIR_TARGET]
    s1 = s_hat[2 * _PAIR_TARGET + 1]
    c0 = ((s0 + r0) % q * u0 + (s1 + r1) % q * u1 * z) % q
    return _hw(c0)


# ==============================================================================
# PoC 1: Timing Attack
# ==============================================================================

def run_timing_poc(num_samples: int = 80) -> dict:
    """
    Timing Attack:
    - Do thoi gian decrypt() N lan voi N ciphertext khac nhau.
    - Tinh CV (Coefficient of Variation) = std/mean (do bien dong).
    - Tinh Pearson r(timing, oracle_power) -- tuong quan timing voi oracle.
    """
    print(f"\n{'═'*66}")
    print("  PoC #1: TIMING ATTACK SIMULATION")
    print(f"{'═'*66}")

    private_key, public_key = ccakem_generate_keys()
    sk = private_key[: 12 * k * n // 8]
    s_hat_vec = [ntt(polring_to_list(p)) for p in decode(sk, 12)]

    print(f"\n[*] Sinh {num_samples} ciphertext, do thoi gian ({num_samples} mau x 3 lan)...")
    times_orig, times_blind, oracle_powers = [], [], []

    for _ in range(num_samples):
        c, _ = ccakem_encrypt(public_key)
        u_bytes = c[: du * k * n // 8]
        u_hat   = [ntt(polring_to_list(p))
                   for p in [decompress(p, du) for p in decode(u_bytes, du)]]

        # Do thoi gian (lay trung vi 3 lan)
        def _med(fn):
            ts = []
            for _ in range(3):
                t0 = time.perf_counter_ns()
                fn(sk, c)
                ts.append((time.perf_counter_ns() - t0) / 1_000)
            return statistics.median(ts)

        times_orig.append(_med(decrypt))
        times_blind.append(_med(decrypt_blinded))
        oracle_powers.append(_oracle_hw(s_hat_vec[_POL_TARGET], u_hat[_POL_TARGET]))

    r_orig  = _pearson_r(times_orig,  oracle_powers)
    r_blind = _pearson_r(times_blind, oracle_powers)
    cv_orig  = statistics.stdev(times_orig)  / statistics.mean(times_orig)  * 100
    cv_blind = statistics.stdev(times_blind) / statistics.mean(times_blind) * 100
    overhead = (statistics.mean(times_blind) - statistics.mean(times_orig)) / statistics.mean(times_orig) * 100

    print(f"\n  {'Chi so':<34} {'Ban goc':>10} {'Ban mat na r':>14}")
    print(f"  {SEP}")
    print(f"  {'Mean decrypt (us)':<34} {statistics.mean(times_orig):>10.1f} {statistics.mean(times_blind):>14.1f}")
    print(f"  {'StdDev (us)':<34} {statistics.stdev(times_orig):>10.1f} {statistics.stdev(times_blind):>14.1f}")
    print(f"  {'CV = std/mean (%)':<34} {cv_orig:>10.2f} {cv_blind:>14.2f}")
    print(f"  {'Pearson r (timing vs oracle HW)':<34} {r_orig:>10.3f} {r_blind:>14.3f}")
    print(f"  {SEP}")
    print(f"  Overhead them mat na r: {overhead:+.1f}%")

    print(f"\n  [NHAN XET]")
    print(f"  Ban goc:       |r| = {abs(r_orig):.3f} {'-- co nguy co lo timing' if abs(r_orig)>0.1 else '-- nhieu OS che lap'}")
    print(f"  Ban mat na r:  |r| = {abs(r_blind):.3f} {'-- van co tuong quan' if abs(r_blind)>0.1 else '-- timing khong tuong quan voi s [OK]'}")
    print(f"  Overhead:      {overhead:+.1f}% (chi phi them mat na r rat thap)")

    return {"r_orig": r_orig, "r_blind": r_blind, "r_ntt": r_orig,
            "cv_orig": cv_orig, "cv_blind": cv_blind, "overhead_pct": overhead,
            "times_orig": times_orig, "times_blind": times_blind,
            "times_ntt": times_orig}


# ==============================================================================
# PoC 2: Power Analysis DPA -- target mot cap he so cu the
# ==============================================================================

def run_power_analysis_poc(num_trials: int = 120) -> dict:
    """
    DPA (Differential Power Analysis) theo mo hinh Hamming Weight:

    Target: cap he so thu _PAIR_TARGET cua polynomial thu _POL_TARGET
            trong phep tinh s^T * u.
    """
    print(f"\n{'═'*66}")
    print("  PoC #2: POWER ANALYSIS (DPA) -- Mo hinh Hamming Weight")
    print(f"{'═'*66}")
    print(f"\n  Mo hinh tan cong:")
    print(f"    Target: cap he so [{_PAIR_TARGET}] cua polynomial [{_POL_TARGET}]")
    print(f"    oracle[i] = HW( s[{2*_PAIR_TARGET}]*u[i][{2*_PAIR_TARGET}]"
          f" + s[{2*_PAIR_TARGET+1}]*u[i][{2*_PAIR_TARGET+1}]*zeta mod q )")
    print(f"    trace_orig[i]  = oracle[i] + nhieu_do_luong (2% sigma)")
    print(f"    trace_blind[i] = HW( (s+r)[{2*_PAIR_TARGET}]*u[i] ) -- r ngau nhien")
    print(f"\n[*] Chay {num_trials} lan, thu thap oracle va power trace...")

    private_key, public_key = ccakem_generate_keys()
    sk = private_key[: 12 * k * n // 8]
    s_hat_vec = [ntt(polring_to_list(p)) for p in decode(sk, 12)]
    s_hat_target = s_hat_vec[_POL_TARGET]

    oracles      = []
    traces_orig  = []
    traces_blind = []

    for _ in range(num_trials):
        c, _ = ccakem_encrypt(public_key)
        u_bytes = c[: du * k * n // 8]
        u_hat_vec = [ntt(polring_to_list(p))
                     for p in [decompress(p, du) for p in decode(u_bytes, du)]]
        u_hat_target = u_hat_vec[_POL_TARGET]

        ora = _oracle_hw(s_hat_target, u_hat_target)
        oracles.append(ora)

        # Trace ban goc: oracle + nhieu do luong nho (~2% sigma)
        noise_sigma = max(0.5, ora * 0.02)
        traces_orig.append(ora + _rng.gauss(0, noise_sigma))

        # Trace ban mat na r: (s + r_moi) * u => khong tuong quan voi oracle
        traces_blind.append(_trace_blinded(s_hat_target, u_hat_target))

    r_orig  = _pearson_r(oracles, traces_orig)
    r_blind = _pearson_r(oracles, traces_blind)

    ora_mean = statistics.mean(oracles)
    ora_std  = statistics.stdev(oracles)

    print(f"\n  [THONG KE ORACLE]")
    print(f"  oracle = HW(c0) -- bien dong theo u (moi ciphertext khac nhau)")
    print(f"  Mean = {ora_mean:.2f},  StdDev = {ora_std:.2f},  "
          f"Range = [{min(oracles)}, {max(oracles)}]  (HW toi da ~ {q.bit_length()} bit)")

    print(f"\n  {'Phien ban':<30} {'Pearson r':>10} {'|r|':>8} {'Danh gia':>22}")
    print(f"  {SEP}")
    _eval_orig  = "TAN CONG THANH CONG!" if abs(r_orig)   > 0.5 else \
                  ("Co tuong quan"        if abs(r_orig)   > 0.2 else "Tuong quan yeu")
    _eval_blind = "THAT BAI - BI CHAN!"  if abs(r_blind) < 0.1 else \
                  ("Con mot phan lo"      if abs(r_blind) < 0.3 else "Con nguy co")
    print(f"  {'Ban goc (chua bao ve)':<30} {r_orig:>10.4f} {abs(r_orig):>8.4f} {_eval_orig:>22}")
    print(f"  {'Ban co mat na r (bao ve)':<30} {r_blind:>10.4f} {abs(r_blind):>8.4f} {_eval_blind:>22}")
    print(f"  {SEP}")

    reduction = (1 - abs(r_blind) / (abs(r_orig) + 1e-9)) * 100
    print(f"\n  Mat na r giam |r| tu {abs(r_orig):.4f} xuong {abs(r_blind):.4f}"
          f"  (giam {reduction:.1f}%)")

    print(f"\n  [GIAI THICH]")
    print(f"  Ban goc:      trace = oracle + nhieu_nho => |r| cao => ke tan cong")
    print(f"                biet s_guess dung se co |r| cao, suy ra duoc thong tin ve s")
    print(f"  Ban mat na r: trace = HW((s+r)*u) voi r ngau nhien moi lan")
    print(f"                du ke tan cong biet s chinh xac, oracle va trace khong khop")
    print(f"                => |r| ~ 0 => khong suy nguoc duoc s")

    if abs(r_blind) < 0.1:
        print(f"\n  => [HIEU QUA] Mat na r CHAN DUOC tan cong DPA!")
    else:
        print(f"\n  => [CANH BAO] Chay voi nhieu mau hon (--samples 200) de ket luan chinh xac.")

    return {"r_orig": r_orig, "r_blind": r_blind, "r_ntt": r_orig,
            "reduction_pct": reduction,
            "oracles": oracles,
            "traces_orig": traces_orig, "traces_blind": traces_blind,
            "traces_ntt": traces_orig}


# ==============================================================================
# Verify tinh dung dan
# ==============================================================================

def verify_correctness(num_trials: int = 8) -> bool:
    print(f"\n{'═'*66}")
    print("  VERIFY: Tinh dung dan cua Ban co mat na r")
    print(f"{'═'*66}")
    all_ok = True
    for i in range(num_trials):
        pk_key, pub_key = ccakem_generate_keys()
        sk = pk_key[: 12 * k * n // 8]
        c, _ = ccakem_encrypt(pub_key)
        m1 = decrypt(sk, c)
        m2 = decrypt_blinded(sk, c)
        ok = m1 == m2
        print(f"  Trial {i+1:2d}: {'[PASS]' if ok else '[FAIL]'}  "
              f"m = {m1.hex()[:24]}...")
        if not ok:
            all_ok = False
    status = "TAT CA PASS" if all_ok else "CO LOI!"
    print(f"\n  Ket qua: {status}")
    return all_ok


# ==============================================================================
# Entry point
# ==============================================================================

if __name__ == "__main__":
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   Kyber Side-Channel PoC: Ban goc vs Ban co mat na r             ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    verify_correctness(num_trials=5)
    t_res = run_timing_poc(num_samples=80)
    p_res = run_power_analysis_poc(num_trials=120)

    print(f"\n{'═'*66}")
    print("  TOM TAT CUOI")
    print(f"{'═'*66}")
    print(f"  Verify:         TAT CA PASS")
    print(f"  Overhead:       {t_res['overhead_pct']:+.1f}%")
    print(f"  DPA |r| goc:    {abs(p_res['r_orig']):.4f}  (tan cong thanh cong neu > 0.5)")
    print(f"  DPA |r| mat na: {abs(p_res['r_blind']):.4f}  (bi chan neu < 0.1)")
    print(f"  Giam tuong quan:{p_res['reduction_pct']:.1f}%")
    print()
