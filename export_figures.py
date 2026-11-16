"""
export_figures.py
=================
Tu dong xuat cac bieu do va hinh anh danh cho bao cao LaTeX:
- images/scatter_ntt_original.png  (Bieu do Ban goc)
- images/scatter_ntt_blinded.png   (Bieu do Ban co mat na r)
"""

import os
import sys
import io

# Xu ly ma hoa utf-8 tren Windows console
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import numpy as np
import matplotlib.pyplot as plt

# Dam bao import duoc kyber
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from kyber.side_channel_poc import run_power_analysis_poc

def export_scatter_plots(num_trials=60, output_dir="images"):
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Dang chay mo phong DPA voi {num_trials} mau de xuat scatter plot...")
    
    res = run_power_analysis_poc(num_trials=num_trials)
    oracles = np.array(res["oracles"])
    traces_orig = np.array(res["traces_orig"])
    traces_blind = np.array(res["traces_blind"])
    r_orig = res["r_orig"]
    r_blind = res["r_blind"]

    # Style bieu do khoa hoc
    plt.rcParams.update({
        'font.size': 12,
        'axes.labelsize': 13,
        'axes.titlesize': 14,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'figure.titlesize': 15
    })

    # 1. Scatter Plot - Ban goc (Khong co mat na r)
    fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
    ax.scatter(oracles, traces_orig, color='#d9534f', alpha=0.75, edgecolors='k', s=50, label='Mau do luong')
    
    # Duong hoi quy tuyen tinh
    m_orig, b_orig = np.polyfit(oracles, traces_orig, 1)
    x_line = np.linspace(min(oracles), max(oracles), 100)
    ax.plot(x_line, m_orig * x_line + b_orig, color='#b52b27', linestyle='--', linewidth=2, 
            label=f'Hoi quy (r = {r_orig:.4f})')
    
    ax.set_title(f'Ban goc (Khong che mat na)\nPearson |r| = {abs(r_orig):.4f} (Tuong quan cao)', fontweight='bold')
    ax.set_xlabel('Hamming Weight du doan (Oracle HW)')
    ax.set_ylabel('Dien nang tieu thu mo phong (Trace)')
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.legend(loc='upper left', frameon=True)
    plt.tight_layout()
    path_orig = os.path.join(output_dir, "scatter_ntt_original.png")
    plt.savefig(path_orig)
    plt.close()
    print(f"[+] Da luu: {path_orig}")

    # 2. Scatter Plot - Ban co mat na r
    fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
    ax.scatter(oracles, traces_blind, color='#2e6da4', alpha=0.75, edgecolors='k', s=50, label='Mau do luong')
    
    m_blind, b_blind = np.polyfit(oracles, traces_blind, 1)
    ax.plot(x_line, m_blind * x_line + b_blind, color='#1b4970', linestyle='--', linewidth=2, 
            label=f'Hoi quy (r = {r_blind:.4f})')
    
    ax.set_title(f'Ban co mat na r (Co bao ve)\nPearson |r| = {abs(r_blind):.4f} (Bi chan)', fontweight='bold')
    ax.set_xlabel('Hamming Weight du doan (Oracle HW)')
    ax.set_ylabel('Dien nang tieu thu mo phong (Trace)')
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.legend(loc='upper left', frameon=True)
    plt.tight_layout()
    path_blind = os.path.join(output_dir, "scatter_ntt_blinded.png")
    plt.savefig(path_blind)
    plt.close()
    print(f"[+] Da luu: {path_blind}")

if __name__ == "__main__":
    export_scatter_plots(num_trials=80)
    print("\n[OK] Hoan tat xuat toan bo bieu do scatter plot vao thu muc images/!")
