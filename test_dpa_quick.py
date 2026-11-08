import sys, io, random, math, secrets
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from kyber.ccakem import ccakem_generate_keys, ccakem_encrypt
from kyber.utils.ntt import ntt, polring_to_list, ZETA_BASEMUL
from kyber.utils.encoding import decode
from kyber.utils.compression import decompress
from kyber.constants import k, n, du, dv, q

def hw(x): return bin(x).count('1')

def pearson(x, y):
    m = len(x)
    mx = sum(x)/m; my = sum(y)/m
    num = sum((a-mx)*(b-my) for a,b in zip(x,y))
    dx = math.sqrt(sum((a-mx)**2 for a in x)+1e-15)
    dy = math.sqrt(sum((b-my)**2 for b in y)+1e-15)
    return num/(dx*dy)

print("Generating keypair...")
private_key, public_key = ccakem_generate_keys()
sk = private_key[:12*k*n//8]
s_hat_vec = [ntt(polring_to_list(p)) for p in decode(sk, 12)]

PAIR = 0; POL = 0
z  = ZETA_BASEMUL[PAIR]
s0 = s_hat_vec[POL][2*PAIR]
s1 = s_hat_vec[POL][2*PAIR+1]

N = 150
oracles, traces_ntt, traces_blind = [], [], []
random.seed()

print(f"Running {N} trials...")
for _ in range(N):
    c, _ = ccakem_encrypt(public_key)
    u_bytes = c[:du*k*n//8]
    u_hat = [ntt(polring_to_list(p)) for p in
             [decompress(p,du) for p in decode(u_bytes,du)]]
    u0 = u_hat[POL][2*PAIR]
    u1 = u_hat[POL][2*PAIR+1]
    
    c0 = (s0*u0 + s1*u1*z) % q
    oracle = hw(c0)
    oracles.append(oracle)
    traces_ntt.append(oracle + random.gauss(0, max(0.5, oracle*0.02)))
    
    r0 = secrets.randbelow(q); r1 = secrets.randbelow(q)
    c0b = ((s0+r0)%q * u0 + (s1+r1)%q * u1 * z) % q
    traces_blind.append(hw(c0b))

r_ntt   = pearson(oracles, traces_ntt)
r_blind = pearson(oracles, traces_blind)
ora_std = math.sqrt(sum((x-sum(oracles)/N)**2 for x in oracles)/N)

print(f"Oracle: min={min(oracles)}, max={max(oracles)}, std={ora_std:.3f}")
print(f"NTT goc  |r| = {abs(r_ntt):.4f}")
print(f"Blinded  |r| = {abs(r_blind):.4f}")
print(f"Reduction = {(1-abs(r_blind)/(abs(r_ntt)+1e-9))*100:.1f}%")
