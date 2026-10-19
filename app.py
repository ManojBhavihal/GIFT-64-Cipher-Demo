"""
GIFT-64 Block Cipher — Interactive Web Demonstration
=====================================================

A polished Streamlit web application for demonstrating the GIFT-64
lightweight block cipher. Built as an academic mini-project.

Run with:
    streamlit run app.py
"""

import streamlit as st
import matplotlib.pyplot as plt
import matplotlib
import time

from gift64 import encrypt, decrypt, encrypt_verbose, NUM_ROUNDS, SBOX, PERM
from cryptanalysis import (
    avalanche_plaintext,
    avalanche_key,
    avalanche_stats,
    avalanche_round_by_round,
    hamming_distance,
)

# Use a non-interactive backend for matplotlib (avoids Tkinter issues)
matplotlib.use('Agg')

# ──────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="GIFT-64 Cipher Demo",
    page_icon="🎁",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────
# CUSTOM STYLING
# ──────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    /* Main title styling */
    .main-title {
        text-align: center;
        padding: 1rem 0;
    }
    /* Result boxes */
    .result-box {
        background-color: #0e1117;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        font-family: 'Courier New', monospace;
        font-size: 1.1rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 20px;
        font-size: 1rem;
    }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────────

def text_to_blocks(text: str) -> list[int]:
    """Convert a text string to a list of 64-bit (8-byte) blocks.

    Pads the last block with null bytes if needed.
    """
    data = text.encode('utf-8')
    # Pad to multiple of 8 bytes
    while len(data) % 8 != 0:
        data += b'\x00'
    blocks = []
    for i in range(0, len(data), 8):
        block = int.from_bytes(data[i:i+8], byteorder='big')
        blocks.append(block)
    return blocks


def blocks_to_text(blocks: list[int]) -> str:
    """Convert a list of 64-bit blocks back to a text string."""
    data = b''
    for block in blocks:
        data += block.to_bytes(8, byteorder='big')
    # Strip null padding
    return data.rstrip(b'\x00').decode('utf-8', errors='replace')


def hex_to_int(hex_str: str, expected_bits: int) -> int:
    """Parse a hex string to an integer, validating the bit length."""
    hex_str = hex_str.strip().replace(' ', '').replace('0x', '').replace('0X', '')
    if not hex_str:
        raise ValueError("Empty hex string")
    if not all(c in '0123456789abcdefABCDEF' for c in hex_str):
        raise ValueError("Invalid hex characters")
    value = int(hex_str, 16)
    if value >= (1 << expected_bits):
        raise ValueError(f"Value too large for {expected_bits} bits")
    return value


def format_hex_spaced(value: int, nibbles: int) -> str:
    """Format an integer as spaced hex bytes (like the official test vectors)."""
    hex_str = format(value, f'0{nibbles}x')
    # Group into pairs (bytes) separated by spaces
    return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))


# ──────────────────────────────────────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🎁 GIFT-64 Cipher")
    st.markdown("**Lightweight Block Cipher**")
    st.markdown("---")
    st.markdown("""
    | Parameter | Value |
    |-----------|-------|
    | Block size | 64 bits |
    | Key size | 128 bits |
    | Rounds | 28 |
    | S-box | 4-bit |
    | Structure | SPN |
    """)
    st.markdown("---")
    st.markdown("**Reference:**")
    st.markdown('Banik et al., *"GIFT: A Small Present"*, CHES 2017')
st.sidebar.markdown("### Project Team")
st.sidebar.markdown("""
- Ashwini
- Bhagyashree
- Manoj
""")
st.sidebar.markdown("---")
st.sidebar.caption("ACC Mini Project | MIT Manipal")


# ──────────────────────────────────────────────────────────────────────
# MAIN HEADER
# ──────────────────────────────────────────────────────────────────────

st.markdown("""
# 🎁 GIFT-64 Block Cipher
### Interactive Demonstration & Cryptanalysis
""")

# ──────────────────────────────────────────────────────────────────────
# TABS
# ──────────────────────────────────────────────────────────────────────

tab_encrypt, tab_decrypt, tab_analysis, tab_learn = st.tabs([
    "🔐 Encrypt",
    "🔓 Decrypt",
    "📊 Avalanche Analysis",
    "📚 Learn",
])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 1: ENCRYPT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_encrypt:
    st.header("🔐 Encryption")
    st.markdown("Enter your plaintext and secret key to encrypt using GIFT-64.")

    # Input mode selector
    input_mode = st.radio(
        "Input format:",
        ["Text (UTF-8)", "Hex (advanced)"],
        horizontal=True,
        key="enc_input_mode",
    )

    col1, col2 = st.columns(2)

    with col1:
        if input_mode == "Text (UTF-8)":
            plain_input = st.text_input(
                "Plaintext (up to 8 characters):",
                value="Hello!",
                max_chars=8,
                key="enc_plain_text",
                help="Enter up to 8 characters. Shorter text will be padded with null bytes."
            )
        else:
            plain_input = st.text_input(
                "Plaintext (hex, 16 hex digits = 64 bits):",
                value="0000000000000000",
                max_chars=20,
                key="enc_plain_hex",
                help="Enter exactly 16 hex digits (e.g., fedcba9876543210)"
            )

    with col2:
        key_input = st.text_input(
            "Secret Key (hex, 32 hex digits = 128 bits):",
            value="00000000000000000000000000000000",
            max_chars=40,
            key="enc_key",
            help="Enter exactly 32 hex digits for the 128-bit key."
        )

    show_rounds = st.checkbox("Show round-by-round details", key="enc_show_rounds")

    if st.button("🔐 Encrypt", type="primary", key="enc_btn"):
        try:
            # Parse key
            key_val = hex_to_int(key_input, 128)

            # Parse plaintext
            if input_mode == "Text (UTF-8)":
                blocks = text_to_blocks(plain_input)
                pt_val = blocks[0]
                st.info(f"Text `\"{plain_input}\"` → Hex: `{format(pt_val, '016x')}`")
            else:
                pt_val = hex_to_int(plain_input, 64)

            # Encrypt
            start_time = time.time()
            ct_val = encrypt(pt_val, key_val)
            elapsed = (time.time() - start_time) * 1000

            # Display results
            st.success("✅ Encryption successful!")

            res_col1, res_col2, res_col3 = st.columns(3)
            with res_col1:
                st.metric("Plaintext", format_hex_spaced(pt_val, 16))
            with res_col2:
                st.metric("Key", format_hex_spaced(key_val, 32)[:23] + "...")
            with res_col3:
                st.metric("Ciphertext", format_hex_spaced(ct_val, 16))

            st.caption(f"⏱️ Encrypted in {elapsed:.1f} ms")

            # Copyable hex output
            st.code(f"Ciphertext (hex): {format(ct_val, '016x')}", language=None)

            # Round-by-round details
            if show_rounds:
                verbose = encrypt_verbose(pt_val, key_val)
                st.markdown("#### Round-by-Round State")
                round_data = []
                for r_info in verbose['rounds']:
                    round_data.append({
                        'Round': r_info['round'],
                        'After SubCells': r_info['after_subcells'],
                        'After PermBits': r_info['after_permbits'],
                        'After AddRoundKey': r_info['after_addroundkey'],
                    })
                st.dataframe(round_data, use_container_width=True, hide_index=True)

        except ValueError as e:
            st.error(f"❌ Input error: {e}")
        except Exception as e:
            st.error(f"❌ Unexpected error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 2: DECRYPT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_decrypt:
    st.header("🔓 Decryption")
    st.markdown("Enter a ciphertext and the same secret key to recover the original plaintext.")

    col1, col2 = st.columns(2)

    with col1:
        ct_input = st.text_input(
            "Ciphertext (hex, 16 hex digits):",
            value="f62bc3ef34f775ac",
            max_chars=20,
            key="dec_ct",
            help="Paste the hex ciphertext from the Encrypt tab."
        )

    with col2:
        dec_key_input = st.text_input(
            "Secret Key (hex, 32 hex digits):",
            value="00000000000000000000000000000000",
            max_chars=40,
            key="dec_key",
            help="Must be the SAME key used for encryption."
        )

    output_mode = st.radio(
        "Output format:",
        ["Hex", "Text (UTF-8)"],
        horizontal=True,
        key="dec_output_mode",
    )

    if st.button("🔓 Decrypt", type="primary", key="dec_btn"):
        try:
            ct_val = hex_to_int(ct_input, 64)
            key_val = hex_to_int(dec_key_input, 128)

            start_time = time.time()
            pt_val = decrypt(ct_val, key_val)
            elapsed = (time.time() - start_time) * 1000

            st.success("✅ Decryption successful!")

            res_col1, res_col2, res_col3 = st.columns(3)
            with res_col1:
                st.metric("Ciphertext", format_hex_spaced(ct_val, 16))
            with res_col2:
                st.metric("Key", format_hex_spaced(key_val, 32)[:23] + "...")
            with res_col3:
                st.metric("Plaintext (hex)", format_hex_spaced(pt_val, 16))

            st.caption(f"⏱️ Decrypted in {elapsed:.1f} ms")

            st.code(f"Plaintext (hex): {format(pt_val, '016x')}", language=None)

            if output_mode == "Text (UTF-8)":
                try:
                    text_result = blocks_to_text([pt_val])
                    st.info(f'📝 As text: **"{text_result}"**')
                except Exception:
                    st.warning("⚠️ Could not decode as valid UTF-8 text.")

        except ValueError as e:
            st.error(f"❌ Input error: {e}")
        except Exception as e:
            st.error(f"❌ Unexpected error: {e}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 3: AVALANCHE ANALYSIS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_analysis:
    st.header("📊 Avalanche Effect Analysis")
    st.markdown("""
    > **What is this?** This is an *educational experiment*, not a real attack.
    > It demonstrates a desirable property of any good cipher: the **avalanche effect**.

    **The idea:** Flip a *single bit* in the plaintext and see how many ciphertext bits
    change. For an ideal cipher, about **50%** of the output bits (32 out of 64)
    should change — even though only 1 input bit was different.
    """)

    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        av_pt = st.text_input(
            "Plaintext (hex):",
            value="0000000000000000",
            key="av_pt",
        )
    with col2:
        av_key = st.text_input(
            "Key (hex):",
            value="00000000000000000000000000000000",
            key="av_key",
        )

    analysis_type = st.radio(
        "What to analyze:",
        ["Flip plaintext bits", "Flip key bits", "Round-by-round diffusion"],
        horizontal=True,
        key="av_type",
    )

    if st.button("📊 Run Analysis", type="primary", key="av_btn"):
        try:
            pt_val = hex_to_int(av_pt, 64)
            key_val = hex_to_int(av_key, 128)

            if analysis_type == "Flip plaintext bits":
                with st.spinner("Analyzing plaintext sensitivity (64 encryptions)..."):
                    distances = avalanche_plaintext(pt_val, key_val)
                    stats = avalanche_stats(distances)

                # Statistics
                st.markdown("### Results")
                mc1, mc2, mc3, mc4 = st.columns(4)
                mc1.metric("Average bits changed", f"{stats['mean']:.1f} / 64")
                mc2.metric("Ideal value", "32.0 / 64")
                mc3.metric("Min / Max", f"{stats['min']} / {stats['max']}")
                mc4.metric("Std deviation", f"{stats['std_dev']:.2f}")

                # Bar chart
                fig, ax = plt.subplots(figsize=(12, 4))
                bars = ax.bar(range(64), distances, color='#4CAF50', alpha=0.8, width=0.8)
                ax.axhline(y=32, color='red', linestyle='--', linewidth=1.5, label='Ideal (32 bits)')
                ax.axhline(y=stats['mean'], color='orange', linestyle='-', linewidth=1.5,
                           label=f'Mean ({stats["mean"]:.1f} bits)')
                ax.set_xlabel('Bit position flipped in plaintext', fontsize=11)
                ax.set_ylabel('Ciphertext bits changed', fontsize=11)
                ax.set_title('Avalanche Effect: Plaintext Bit Sensitivity', fontsize=13)
                ax.legend(fontsize=10)
                ax.set_ylim(0, 64)
                ax.set_xlim(-1, 64)
                plt.tight_layout()
                st.pyplot(fig)
                plt.close()

                # Histogram
                fig2, ax2 = plt.subplots(figsize=(8, 4))
                ax2.hist(distances, bins=range(0, 65), color='#2196F3', alpha=0.8,
                         edgecolor='white', linewidth=0.5)
                ax2.axvline(x=32, color='red', linestyle='--', linewidth=1.5, label='Ideal (32)')
                ax2.axvline(x=stats['mean'], color='orange', linestyle='-', linewidth=1.5,
                            label=f'Mean ({stats["mean"]:.1f})')
                ax2.set_xlabel('Number of bits changed', fontsize=11)
                ax2.set_ylabel('Frequency', fontsize=11)
                ax2.set_title('Distribution of Bit Changes', fontsize=13)
                ax2.legend(fontsize=10)
                plt.tight_layout()
                st.pyplot(fig2)
                plt.close()

                # Interpretation
                if abs(stats['mean'] - 32) < 5:
                    st.success(
                        f"✅ **Strong avalanche effect!** Mean = {stats['mean']:.1f} bits "
                        f"(close to the ideal 32). GIFT-64 has good diffusion."
                    )
                else:
                    st.warning(
                        f"⚠️ Mean = {stats['mean']:.1f} bits — somewhat far from the ideal 32. "
                        f"This may warrant further investigation."
                    )

            elif analysis_type == "Flip key bits":
                with st.spinner("Analyzing key sensitivity (128 encryptions)..."):
                    distances = avalanche_key(pt_val, key_val)
                    stats = avalanche_stats(distances)

                st.markdown("### Results")
                mc1, mc2, mc3, mc4 = st.columns(4)
                mc1.metric("Average bits changed", f"{stats['mean']:.1f} / 64")
                mc2.metric("Ideal value", "32.0 / 64")
                mc3.metric("Min / Max", f"{stats['min']} / {stats['max']}")
                mc4.metric("Std deviation", f"{stats['std_dev']:.2f}")

                fig, ax = plt.subplots(figsize=(14, 4))
                ax.bar(range(128), distances, color='#FF9800', alpha=0.8, width=0.8)
                ax.axhline(y=32, color='red', linestyle='--', linewidth=1.5, label='Ideal (32 bits)')
                ax.axhline(y=stats['mean'], color='blue', linestyle='-', linewidth=1.5,
                           label=f'Mean ({stats["mean"]:.1f} bits)')
                ax.set_xlabel('Bit position flipped in key', fontsize=11)
                ax.set_ylabel('Ciphertext bits changed', fontsize=11)
                ax.set_title('Avalanche Effect: Key Bit Sensitivity', fontsize=13)
                ax.legend(fontsize=10)
                ax.set_ylim(0, 64)
                ax.set_xlim(-1, 128)
                plt.tight_layout()
                st.pyplot(fig)
                plt.close()

                if abs(stats['mean'] - 32) < 5:
                    st.success(
                        f"✅ **Strong key sensitivity!** Changing any single key bit "
                        f"changes ~{stats['mean']:.1f} ciphertext bits on average."
                    )

            else:  # Round-by-round
                with st.spinner("Analyzing round-by-round diffusion..."):
                    bit_to_flip = st.session_state.get('rr_bit', 0)
                    fractions = avalanche_round_by_round(pt_val, key_val, bit_pos=0)

                st.markdown("### Round-by-Round Diffusion")
                st.markdown(
                    "This shows how the avalanche builds up: after round 1, only a few bits "
                    "differ. By round 5–6, the effect has 'avalanched' to ~50%."
                )

                fig, ax = plt.subplots(figsize=(10, 5))
                rounds_x = list(range(1, NUM_ROUNDS + 1))
                percentages = [f * 100 for f in fractions]
                ax.plot(rounds_x, percentages, 'o-', color='#E91E63', markersize=6,
                        linewidth=2, label='Actual diffusion')
                ax.axhline(y=50, color='green', linestyle='--', linewidth=1.5,
                           label='Ideal (50%)')
                ax.set_xlabel('Round number', fontsize=12)
                ax.set_ylabel('Bits changed (%)', fontsize=12)
                ax.set_title('How the Avalanche Effect Builds Up', fontsize=14)
                ax.set_ylim(-5, 105)
                ax.set_xlim(0, NUM_ROUNDS + 1)
                ax.legend(fontsize=11)
                ax.grid(True, alpha=0.3)
                plt.tight_layout()
                st.pyplot(fig)
                plt.close()

                # Show the data in a table too
                round_data = []
                for i, frac in enumerate(fractions):
                    round_data.append({
                        'Round': i + 1,
                        'Bits Changed': int(frac * 64),
                        'Percentage': f"{frac * 100:.1f}%",
                    })
                st.dataframe(round_data, use_container_width=True, hide_index=True)

        except ValueError as e:
            st.error(f"❌ Input error: {e}")
        except Exception as e:
            st.error(f"❌ Error: {e}")

    st.markdown("---")
    st.info(
        "⚠️ **Disclaimer:** This avalanche analysis is a *statistical property test*, "
        "not a cryptographic attack. It demonstrates that GIFT-64 has good diffusion, "
        "which is a necessary (but not sufficient) condition for security."
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 4: LEARN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_learn:
    st.header("📚 Understanding GIFT-64")

    st.markdown("""
    ## What is GIFT-64?

    GIFT-64 is a **lightweight block cipher** — a cipher designed to be very small
    and efficient, suitable for devices with extremely limited resources like
    smart cards, RFID tags, and IoT sensors.

    It was created by a team of cryptographers and published at **CHES 2017**
    (Cryptographic Hardware and Embedded Systems), one of the top venues for
    hardware-oriented cryptography research.

    ---

    ## The Big Picture

    GIFT-64 takes two inputs:
    - A **64-bit plaintext** (the message to encrypt — 8 bytes)
    - A **128-bit key** (the secret — 16 bytes)

    And produces:
    - A **64-bit ciphertext** (the encrypted message)

    It does this by running **28 rounds** of the same three operations.
    """)

    # Visual diagram of one round
    st.markdown("""
    ## One Round of GIFT-64

    ```
    ┌─────────────────────────────────┐
    │         64-bit State            │
    └─────────────┬───────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────┐
    │  ① SubCells (S-box substitution)│  ← Confusion
    │    Apply 4-bit S-box to each    │
    │    of the 16 nibbles            │
    └─────────────┬───────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────┐
    │  ② PermBits (Bit permutation)   │  ← Diffusion
    │    Rearrange all 64 bits        │
    │    according to a fixed table   │
    └─────────────┬───────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────┐
    │  ③ AddRoundKey                  │  ← Key Mixing
    │    XOR round key + constant     │
    │    into the state               │
    └─────────────┬───────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────┐
    │     Key schedule update         │
    │     (rotate key register)       │
    └─────────────────────────────────┘
    ```
    """)

    st.markdown("---")

    # S-box explanation
    st.markdown("## ① SubCells — The S-box")
    st.markdown("""
    The **S-box** (Substitution box) is a lookup table that replaces each 4-bit
    nibble with a different 4-bit nibble. It's the ONLY non-linear operation
    in the cipher, which means it's essential for security.

    **Why is non-linearity important?** Without it, the entire cipher would be
    a linear function, and an attacker could solve a simple system of equations
    to find the key. The S-box breaks this linearity.

    **GIFT-64's S-box:**
    """)

    sbox_data = []
    for i in range(16):
        sbox_data.append({
            'Input (hex)': f'{i:X}',
            'Input (binary)': f'{i:04b}',
            'Output (hex)': f'{SBOX[i]:X}',
            'Output (binary)': f'{SBOX[i]:04b}',
        })
    st.dataframe(sbox_data, use_container_width=True, hide_index=True)

    st.markdown("---")

    # PermBits explanation
    st.markdown("## ② PermBits — Bit Permutation")
    st.markdown("""
    After substitution, the 64 bits are **rearranged** according to a fixed
    permutation table. Bit 0 might go to position 0, bit 1 goes to position 17,
    bit 2 goes to position 34, and so on.

    **Why?** The S-box works on individual 4-bit nibbles. Without the permutation,
    each nibble would be processed independently and the cipher would be trivially
    breakable. The permutation SPREADS the bits across different nibbles so that
    in the next round, the S-box mixes bits from different original positions.

    This is how **diffusion** is achieved: one changed bit propagates to affect
    many positions over several rounds.
    """)

    st.markdown("---")

    # AddRoundKey explanation
    st.markdown("## ③ AddRoundKey")
    st.markdown("""
    In this step, 32 bits of the key register are XORed into specific positions
    of the 64-bit state. A 6-bit **round constant** (different for each round)
    is also XORed in.

    **Why XOR?** XOR is its own inverse (a ⊕ b ⊕ b = a), which makes decryption
    straightforward. It also mixes the key material into the state without
    requiring complex arithmetic.

    **Why round constants?** Without them, all rounds would be identical if the
    key happened to be all zeros. Round constants ensure that every round is
    different, even with a zero key. They prevent certain classes of attacks
    called *slide attacks*.
    """)

    st.markdown("---")

    # Key schedule
    st.markdown("## Key Schedule")
    st.markdown("""
    The 128-bit key is stored in a register. After each round, the key register
    is updated by:
    1. **Rotating** the entire 128 bits right by 32 positions
    2. **Rotating** the top 16-bit word by 12 positions
    3. **Rotating** the next 16-bit word by 2 positions

    This ensures that different key bits are used in each round, increasing
    the complexity of the relationship between the key and the ciphertext.
    """)

    st.markdown("---")

    # Decryption
    st.markdown("## How Decryption Works")
    st.markdown("""
    To decrypt, we run the **same three operations in reverse order**, for
    28 rounds starting from the last round:

    1. **Inverse AddRoundKey**: XOR is its own inverse, so we XOR the same
       round key and constant again. We pre-compute all 28 round keys.
    2. **Inverse PermBits**: Apply the inverse permutation table.
    3. **Inverse SubCells**: Use the inverse S-box.

    The key insight: we need all 28 round keys. We generate them by running
    the key schedule forward 28 times and storing each state.
    """)

    st.markdown("---")

    st.markdown("## Why 'Lightweight'?")
    st.markdown("""
    GIFT-64 is designed for **constrained environments**:

    | Feature | GIFT-64 | AES-128 |
    |---------|---------|---------|
    | Block size | 64 bits | 128 bits |
    | Key size | 128 bits | 128 bits |
    | S-box size | 4-bit | 8-bit |
    | Gate count | ~800 GE | ~3,400 GE |
    | Rounds | 28 | 10 |

    GE = Gate Equivalents (a measure of hardware cost)

    GIFT achieves good security with a much smaller circuit by using a simpler
    4-bit S-box and more rounds. The trade-off: it's slower in software but
    much smaller in hardware.
    """)
