"""igd_aes.py - AES-128 / AES-256 in CFB-128, for SNMPv3's privacy (1.7.2), as otp's.

otp carries its own AES in Python (otp.py: _aes_tables, _xt, _AesAny, snmp_cfb) for the
SNMPv3 agent, so that the standard library is enough: taken whole from otp 1.0.288. The
`cryptography` module is used where the system has it (faster, constant-time), else the
lines below do the same (FIPS-197; CFB as RFC 3826 wants it: 128-bit segments).

Encryption of the block only - CFB needs no more, both ways.
"""

_AES_SBOX = None


def _aes_tables():
    global _AES_SBOX
    if _AES_SBOX is None:
        sbox = [0] * 256
        p = q = 1
        while True:
            p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
            q ^= q << 1
            q ^= q << 2
            q ^= q << 4
            q &= 0xFF
            if q & 0x80:
                q ^= 0x09
            x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ \
                ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
            sbox[p] = (x ^ 0x63) & 0xFF
            if p == 1:
                break
        sbox[0] = 0x63
        _AES_SBOX = sbox
    return _AES_SBOX


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


class AesAny(object):
    """AES-128 or -256 (a key of 16 or 32 bytes; 24 works too), encryption only."""

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("an AES key is 16, 24 or 32 bytes")
        sb = _aes_tables()
        nk = len(key) // 4
        rounds = nk + 6
        w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
        rcon = 1
        for i in range(nk, 4 * (rounds + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = [sb[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _xt(rcon)
            elif nk > 6 and i % nk == 4:
                t = [sb[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - nk], t)])
        self.rk = [sum(w[r * 4:r * 4 + 4], []) for r in range(rounds + 1)]
        self.rounds = rounds
        self.sb = sb

    def block(self, data):
        sb, rk = self.sb, self.rk
        s = [a ^ b for a, b in zip(data, rk[0])]
        for r in range(1, self.rounds + 1):
            s = [sb[x] for x in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]       # ShiftRows
            if r != self.rounds:
                m = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    t = a0 ^ a1 ^ a2 ^ a3
                    m += [a0 ^ t ^ _xt(a0 ^ a1), a1 ^ t ^ _xt(a1 ^ a2),
                          a2 ^ t ^ _xt(a2 ^ a3), a3 ^ t ^ _xt(a3 ^ a0)]
                s = m
            s = [a ^ b for a, b in zip(s, rk[r])]
        return bytes(s)


def cfb_pure(key, iv, data, decrypt):
    """CFB-128 with the AES above alone (no `cryptography`)."""
    aes, prev, out = AesAny(key), iv, bytearray()
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        ks = aes.block(prev)
        got = bytes(a ^ b for a, b in zip(chunk, ks))
        out += got
        prev = (chunk if decrypt else got) + ks[len(chunk):]
    return bytes(out)


def cfb(key, iv, data, decrypt):
    """AES in CFB-128: `cryptography`'s where it is there, else cfb_pure()."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:                                # CFB moved there in cryptography 47
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB
        c = Cipher(algorithms.AES(key), CFB(iv))
        x = c.decryptor() if decrypt else c.encryptor()
        return x.update(data) + x.finalize()
    except ImportError:
        pass
    return cfb_pure(key, iv, data, decrypt)
