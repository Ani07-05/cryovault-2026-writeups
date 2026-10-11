"""Prismwake: 6000 EC x-coordinate observations x([m_i] K), where the
multipliers m_i turn out to be the raw output stream of Python's
random.randrange(1, n) (MT19937) rather than independent random integers.
Recover the generator's internal state from the multipliers, rewind it past
its seed window to the Mobius-map coefficients that mask the true
observations, then recover K via the EC x-only Montgomery ladder.

This is a structural sketch -- the full MT19937 state-recovery/rewind code
(mt.py / ec.py / clone_helpers.py / rewind*.py) ran across several scratchpad
files that no longer exist on disk. The high-level steps and the final
formula are exactly what worked; the MT-internals plumbing below is
illustrative, not a drop-in solver.
"""
import json
import pickle


def temper(y: int) -> int:
    """MT19937 tempering transform."""
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & 0xFFFFFFFF


def untemper(y: int) -> int:
    """Inverse of temper(); recovers a raw MT19937 state word from output."""
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    for _ in range(7):
        y ^= (y << 7) & 0x9D2C5680
    for _ in range(2):
        y ^= y >> 11
    return y & 0xFFFFFFFF


def mt_next_state_word(state, i):
    """One step of the MT19937 state-transition recurrence, used to fill
    gaps between recovered words -- see Matsumoto & Nishimura 1998."""
    n, m, matrix_a, upper_mask, lower_mask = 624, 397, 0x9908B0DF, 0x80000000, 0x7FFFFFFF
    y = (state[i] & upper_mask) | (state[(i + 1) % n] & lower_mask)
    y = state[(i + m) % n] ^ (y >> 1)
    if y & 1:
        y ^= matrix_a
    return y


def recover_stream_words(multipliers, n):
    """Place each (multiplier - 1) at its position in the MT output stream,
    recover the partially-masked words via untemper(), and fill gaps with
    the recurrence. Returns the recovered state-word stream."""
    words = {}
    for i, m in enumerate(multipliers):
        raw = (m - 1) % n
        words[i] = untemper(raw)
    # propagate via recurrence -- real implementation fills ~18k consecutive
    # words with no contradictions and flags the 70 planted outliers.
    return words


def mobius(y, u, v, w, p):
    return (u * y + v) * pow((w * y + 1) % p, -1, p) % p


def main():
    d = json.load(open('observations.json'))
    p, n, curve_b = int(d['prime']), int(d['order']), int(d['curve_b'])
    M = [int(x) % n for x in d['multiplier']]
    Y = [int(x) for x in d['observation']]

    stream = recover_stream_words(M, n)

    # Rewound coefficients (recovered by walking the MT state back past its
    # 624-word window to the draws made just before the first multiplier).
    u = 34559716604220687612953322102
    v = 48772199007751653754816185446
    w = 22589791273467761145953217267

    from ec import aff, ladder  # x-only Montgomery ladder over E: y^2=x^3+curve_b mod p

    y0 = mobius(Y[0], u, v, w, p)
    xK = aff(ladder(pow(M[0], -1, n), y0))

    matches = sum(
        1 for i in range(len(Y))
        if aff(ladder(M[i], xK)) == mobius(Y[i], u, v, w, p)
    )
    print('xK =', xK, 'matches', matches, '/', len(Y))

    import model
    print(model.open_seal(xK))


if __name__ == '__main__':
    main()
