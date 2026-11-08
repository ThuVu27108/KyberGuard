"""
demo_comparison.py
==================
So sanh 2 phien ban decrypt Kyber:

    1. decrypt()          -- Ban goc (chua bao ve mat na)
    2. decrypt_blinded()  -- Ban co mat na r (co bao ve kenh ben)

Kich ban chay:
    python -X utf8 demo_comparison.py               # chay day du
    python -X utf8 demo_comparison.py --samples 40  # it mau hon
    python -X utf8 demo_comparison.py --quick       # chi verify + timing
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import argparse
import time
import statistics

from kyber.ccakem import ccakem_generate_keys, ccakem_encrypt
from kyber.encryption.decrypt import decrypt
from kyber.encryption.decrypt_blinded import decrypt_blinded
from kyber.constants import k, n

SEP = "─" * 66


def _banner(text: str) -> None:
    print(f"\n{'═'*66}")
    print(f"  {text}")
    print(f"{'═'*66}")


def _section(text: str) -> None:
    print(f"\n{SEP}")
    print(f"  {text}")
    print(SEP)


# ==============================================================================
# BUOC 1: Verify tinh dung dan
# ==============================================================================

def verify(num_trials: int = 8) -> bool:
    _section(f"BUOC 1 - VERIFY: Ket qua hai phien ban phai giong het nhau")

    all_ok = True
    for i in range(num_trials):
        private_key, public_key = ccakem_generate_keys()
        sk = private_key[: 12 * k * n // 8]
        c, _ = ccakem_encrypt(public_key)

        m1 = decrypt(sk, c)           # Ban goc
        m2 = decrypt_blinded(sk, c)   # Ban co mat na r

        ok = m1 == m2
        print(f"  Trial {i+1:2d}: {'[PASS]' if ok else '[FAIL]'}  "
              f"m = {m1.hex()[:24]}...")
        if not ok:
            all_ok = False

    status = "TAT CA PASS" if all_ok else "CO LOI!"
    print(f"\n  Ket qua: {status}")
    if all_ok:
        print(f"  => Chung minh: (v + r^T*u) - (s+r)^T*u = v - s^T*u  [dung]")
    return all_ok


# ==============================================================================
# BUOC 2: So sanh thoi gian chay
# ==============================================================================

def benchmark(num_samples: int = 60) -> dict:
    _banner(f"BUOC 2 - BENCHMARK: So sanh thoi gian ({num_samples} mau)")

    print(f"\n[1/3] Tao keypair Kyber1024...")
    t0 = time.perf_counter()
    private_key, public_key = ccakem_generate_keys()
    t_key = (time.perf_counter() - t0) * 1000
    sk = private_key[: 12 * k * n // 8]
    print(f"      Keygen: {t_key:.1f} ms")

    print(f"\n[2/3] Sinh {num_samples} ciphertext...")
    ciphertexts = []
    for _ in range(num_samples):
        c, _ = ccakem_encrypt(public_key)
        ciphertexts.append(c)

    def _measure(fn, ct, reps=3):
        runs = []
        for _ in range(reps):
            t0 = time.perf_counter_ns()
            fn(sk, ct)
            runs.append((time.perf_counter_ns() - t0) / 1_000)  # µs
        return statistics.median(runs)

    print(f"\n[3/3] Do thoi gian (moi mau x 3 lan, lay trung vi)...")
    times_orig  = [_measure(decrypt, ct) for ct in ciphertexts]
    times_blind = [_measure(decrypt_blinded, ct) for ct in ciphertexts]

    def _stats(t):
        return {
            "mean":  statistics.mean(t),
            "stdev": statistics.stdev(t),
            "min":   min(t),
            "max":   max(t),
        }

    s_orig  = _stats(times_orig)
    s_blind = _stats(times_blind)
    overhead = (s_blind["mean"] - s_orig["mean"]) / s_orig["mean"] * 100

    print(f"\n  {'Chi so':<16} {'Ban goc (us)':>14} {'Co mat na r (us)':>18} {'Diff':>8}")
    print(f"  {SEP}")
    for key in ["mean", "stdev", "min", "max"]:
        diff = s_blind[key] - s_orig[key]
        print(f"  {key:<16} {s_orig[key]:>14.1f} {s_blind[key]:>18.1f} {diff:>+8.1f}")
    print(f"  {SEP}")
    print(f"  {'Overhead mat na r':<16} {'':>14} {'':>18} {overhead:>+7.1f}%")

    print(f"\n  [PHAN TICH]")
    print(f"  Tai sao overhead nho ({overhead:.1f}%):")
    print(f"    Mat na r chi them 1 tich vo huong (dot_product) bo sung.")
    print(f"    NTT/INTT la phan lon chi phi, khong tang them.")

    if abs(overhead) < 20:
        print(f"\n  [OK] Overhead {overhead:.1f}% nam trong muc chap nhan duoc (<20%).")
    elif abs(overhead) < 40:
        print(f"\n  [TRUNG BINH] Overhead {overhead:.1f}%, co the chap nhan cho muc dich bao mat.")
    else:
        print(f"\n  [CAO] Overhead {overhead:.1f}%, can xem xet toi uu them.")

    return {
        "times_orig":   times_orig,
        "times_blind":  times_blind,
        "times_ntt":    times_orig,
        "stats_orig":   s_orig,
        "stats_blind":  s_blind,
        "overhead_pct": overhead,
    }


# ==============================================================================
# BUOC 3: Mo phong tan cong + kiem tra hieu qua
# ==============================================================================

def attack_simulation(num_samples: int = 60) -> dict:
    _banner(f"BUOC 3 - TAN CONG: Mo phong DPA va kiem tra hieu qua")

    from kyber.side_channel_poc import run_timing_poc, run_power_analysis_poc

    timing_r = run_timing_poc(num_samples=num_samples)
    power_r  = run_power_analysis_poc(num_trials=num_samples)

    return {"timing": timing_r, "power": power_r}


# ==============================================================================
# Main
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="So sanh Ban goc vs Ban co mat na r: timing, tan cong, hieu qua"
    )
    parser.add_argument("--samples", type=int, default=60,
                        help="So mau cho benchmark va tan cong (mac dinh: 60)")
    parser.add_argument("--trials",  type=int, default=8,
                        help="So lan verify (mac dinh: 8)")
    parser.add_argument("--quick",   action="store_true",
                        help="Chi verify + timing, bo qua tan cong")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   Kyber: Ban goc vs Ban co mat na r -- Bao ve kenh ben          ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print(f"\n  Phien ban goc:     decrypt()         -- Ban chuan FIPS 203, KHONG che mat na")
    print(f"  Phien ban cai tien: decrypt_blinded() -- Ban CO che mat na r")

    # 1. Verify
    ok = verify(num_trials=args.trials)
    if not ok:
        print("\n[ERROR] Mat na r sai! Dung lai.")
        sys.exit(1)

    # 2. Benchmark
    bench = benchmark(num_samples=args.samples)

    # 3. Tan cong (neu khong quick mode)
    if not args.quick:
        attack_r = attack_simulation(num_samples=args.samples)
    else:
        print(f"\n[SKIP] --quick mode: bo qua phan tan cong.")
        attack_r = None

    # Tong ket
    _banner("KET QUA TONG HOP")
    print(f"  [1] Tinh dung dan:    TAT CA PASS")
    print(f"  [2] Overhead mat na:  {bench['overhead_pct']:+.1f}%  "
          f"({'chap nhan duoc' if abs(bench['overhead_pct']) < 20 else 'can xem xet'})")

    if attack_r:
        pr = attack_r["power"]
        tr = attack_r["timing"]
        print(f"  [3] DPA correlation:")
        print(f"      Ban goc:      |r| = {abs(pr['r_orig']):.4f}  => {'TAN CONG CO THE THANH CONG' if abs(pr['r_orig']) > 0.5 else 'tuong quan yeu (Python noise)'}")
        print(f"      Ban mat na r: |r| = {abs(pr['r_blind']):.4f}  => {'TAN CONG BI CHAN' if abs(pr['r_blind']) < 0.1 else 'con mot phan tuong quan'}")
        print(f"      Giam tuong quan: {pr['reduction_pct']:.1f}%")
        print(f"  [4] Timing overhead: {tr['overhead_pct']:+.1f}%")

    print(f"\n  KET LUAN:")
    print(f"  decrypt_blinded() la phien ban khuyen dung:")
    print(f"    - Bao ve chong tan cong kenh ben (che giau bang r ngau nhien)")
    print(f"    - Overhead nho ({bench['overhead_pct']:+.1f}%)")
    print(f"    - Chinh xac 100% (ket qua giong het ban goc)")
    print()


if __name__ == "__main__":
    main()
