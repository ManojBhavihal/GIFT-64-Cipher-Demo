"""
Cryptanalysis Module — Avalanche Effect Analysis for GIFT-64
=============================================================

This module implements an EDUCATIONAL cryptanalysis experiment:
the *avalanche effect* test. It is NOT a real attack on the cipher.

What is the Avalanche Effect?
-----------------------------
A good cipher should have the property that flipping a single bit in
the plaintext (or key) causes roughly HALF the bits in the ciphertext
to change. This property is called the "avalanche effect" and was
first formalized by Horst Feistel.

For a 64-bit block cipher like GIFT-64, flipping one input bit should
change approximately 32 of the 64 output bits (50%).

What this module does:
- Encrypts a plaintext P with key K → ciphertext C₀
- Flips one bit of P to get P' → encrypts P' with same K → C₁
- Counts how many bits differ between C₀ and C₁ (Hamming distance)
- Repeats for each of the 64 bit positions
- Reports statistics (mean, min, max, std deviation)

This demonstrates the DIFFUSION property of GIFT-64.
"""

from gift64 import encrypt, NUM_ROUNDS


def hamming_distance(a: int, b: int) -> int:
    """Count the number of bits that differ between two integers.

    Example:
        hamming_distance(0b1010, 0b1001) → 2  (bits 0 and 1 differ)

    This is also called the "Hamming weight of a XOR b".
    """
    return bin(a ^ b).count('1')


def avalanche_plaintext(plaintext: int, key: int) -> list[int]:
    """Test the avalanche effect by flipping each plaintext bit.

    For each of the 64 bit positions:
      1. Flip that one bit in the plaintext
      2. Encrypt the modified plaintext with the same key
      3. Count how many ciphertext bits changed

    Args:
        plaintext: The original 64-bit plaintext.
        key:       The 128-bit key.

    Returns:
        A list of 64 integers, where result[i] is the number of
        ciphertext bits that changed when bit i was flipped.
    """
    # Encrypt the original plaintext
    original_ct = encrypt(plaintext, key)

    distances = []
    for bit_pos in range(64):
        # Flip exactly one bit
        flipped_pt = plaintext ^ (1 << bit_pos)
        # Encrypt the modified plaintext
        flipped_ct = encrypt(flipped_pt, key)
        # Count how many output bits changed
        dist = hamming_distance(original_ct, flipped_ct)
        distances.append(dist)

    return distances


def avalanche_key(plaintext: int, key: int) -> list[int]:
    """Test the avalanche effect by flipping each key bit.

    Same as avalanche_plaintext, but flips key bits instead.
    For each of the 128 key bit positions:
      1. Flip that one bit in the key
      2. Encrypt the SAME plaintext with the modified key
      3. Count how many ciphertext bits changed

    Args:
        plaintext: The 64-bit plaintext (unchanged).
        key:       The original 128-bit key.

    Returns:
        A list of 128 integers, where result[i] is the number of
        ciphertext bits that changed when key bit i was flipped.
    """
    original_ct = encrypt(plaintext, key)

    distances = []
    for bit_pos in range(128):
        flipped_key = key ^ (1 << bit_pos)
        flipped_ct = encrypt(plaintext, flipped_key)
        dist = hamming_distance(original_ct, flipped_ct)
        distances.append(dist)

    return distances


def avalanche_stats(distances: list[int]) -> dict:
    """Compute statistics from an avalanche analysis.

    Args:
        distances: List of Hamming distances (from avalanche_plaintext or avalanche_key).

    Returns:
        Dictionary with keys:
            'mean':     Average number of bits flipped
            'min':      Minimum bits flipped
            'max':      Maximum bits flipped
            'std_dev':  Standard deviation
            'ideal':    The ideal value (32 for 64-bit block)
            'count':    Number of measurements
    """
    n = len(distances)
    mean = sum(distances) / n
    variance = sum((d - mean) ** 2 for d in distances) / n
    std_dev = variance ** 0.5

    return {
        'mean': round(mean, 2),
        'min': min(distances),
        'max': max(distances),
        'std_dev': round(std_dev, 2),
        'ideal': 32,   # Half of 64-bit block
        'count': n,
    }


def avalanche_round_by_round(plaintext: int, key: int, bit_pos: int = 0) -> list[float]:
    """Show how the avalanche effect builds up round by round.

    This is a more detailed educational analysis: for a single bit flip,
    how many bits change after 1 round, 2 rounds, ..., up to 28 rounds?

    This demonstrates that early rounds produce little change, but after
    several rounds the effect "avalanches" to roughly 50%.

    Args:
        plaintext: The 64-bit plaintext.
        key:       The 128-bit key.
        bit_pos:   Which bit to flip (0–63).

    Returns:
        A list of 28 floats, where result[r] is the fraction of bits
        that changed after (r+1) rounds.
    """
    from gift64 import (
        _int_to_nibbles, _nibbles_to_int,
        sub_cells, perm_bits, add_round_key, key_update
    )

    flipped_pt = plaintext ^ (1 << bit_pos)

    # Run both plaintexts through the cipher round by round
    state_orig = _int_to_nibbles(plaintext, 16)
    state_flip = _int_to_nibbles(flipped_pt, 16)
    k_orig = _int_to_nibbles(key, 32)
    k_flip = list(k_orig)  # Same key for both

    fractions = []
    for r in range(NUM_ROUNDS):
        state_orig = sub_cells(state_orig)
        state_flip = sub_cells(state_flip)

        state_orig = perm_bits(state_orig)
        state_flip = perm_bits(state_flip)

        state_orig = add_round_key(state_orig, k_orig, r)
        state_flip = add_round_key(state_flip, k_flip, r)

        k_orig = key_update(k_orig)
        k_flip = key_update(k_flip)

        # Measure difference after this round
        val_orig = _nibbles_to_int(state_orig)
        val_flip = _nibbles_to_int(state_flip)
        bits_diff = hamming_distance(val_orig, val_flip)
        fractions.append(bits_diff / 64.0)

    return fractions


def generate_full_report(plaintext: int, key: int) -> dict:
    """Generate a complete avalanche analysis report.

    Returns a dictionary containing:
        - 'plaintext_analysis': stats and distances for plaintext bit flips
        - 'key_analysis': stats and distances for key bit flips
        - 'round_by_round': how the avalanche builds up per round
        - 'plaintext_hex': the plaintext in hex
        - 'key_hex': the key in hex
        - 'ciphertext_hex': the ciphertext in hex
    """
    pt_distances = avalanche_plaintext(plaintext, key)
    key_distances = avalanche_key(plaintext, key)
    round_fractions = avalanche_round_by_round(plaintext, key, bit_pos=0)

    return {
        'plaintext_hex': format(plaintext, '016x'),
        'key_hex': format(key, '032x'),
        'ciphertext_hex': format(encrypt(plaintext, key), '016x'),
        'plaintext_analysis': {
            'distances': pt_distances,
            'stats': avalanche_stats(pt_distances),
        },
        'key_analysis': {
            'distances': key_distances,
            'stats': avalanche_stats(key_distances),
        },
        'round_by_round': round_fractions,
    }
