import unittest
import os
from random import randint
from fastecdsa.curve import secp256k1,Curve
from sympy import integer_nthroot
from math import log2, floor
from itertools import combinations
from hashlib import sha256
from abc import ABC, abstractmethod
from hashlib import sha256, md5
from typing import List,Optional
from fastecdsa.curve import secp256k1
import base64
from fastecdsa.point import Point
from fastecdsa.curve import secp256k1
from fastecdsa.util import mod_sqrt

CURVE = secp256k1
BYTE_LENGTH = CURVE.q.bit_length() // 8
SUPERCURVE: Curve = secp256k1
p = CURVE.q


def elliptic_hash(msg: bytes, CURVE: Curve):
    p = CURVE.p
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16)
        if x >= p:
            continue

        y_sq = (x ** 3 + CURVE.a * x + CURVE.b) % p
        y = mod_sqrt(y_sq, p)[0]

        if CURVE.is_point_on_curve((x, y)):
            b = int(md5(prefixed_msg).hexdigest(), 16) % 2
            return Point(x, y, CURVE) if b else Point(x, p - y, CURVE)


class RangeProof(unittest.TestCase):
    def Setup(self,V,N):
        seeds = [os.urandom(10) for _ in range(7)]
        v, n = ModP(randint(0, V), p), N
        gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
        hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
        g = elliptic_hash(seeds[2], CURVE)
        h = elliptic_hash(seeds[3], CURVE)
        u = elliptic_hash(seeds[4], CURVE)
        gamma = mod_hash(seeds[5], p)
        V = commitment(g, h, v, gamma)
        return (v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V)
    def RanProve(self, v, n, g, h, gs, hs, gamma, u, CURVE, seed):  
        Prov = NIRangeProver(v, n, g, h, gs, hs, gamma, u, CURVE, seed)
        proof = Prov.prove()
        return proof
    def RanVerify(self, V, g, h, gs, hs, u, proof,seeds):
        Verif = RangeVerifier(V, g, h, gs, hs, u, proof)
        return Verif.verify()

class ModP:

    num_of_mult=0
    @classmethod
    def reset(cls):
        cls.num_of_mult = 0

    def __init__(self, x, p):
        self.x = x
        self.p = p

    def __add__(self, y):
        if isinstance(y, int):
            return ModP(self.x+y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __mul__(self, y):
        type(self).num_of_mult += 1
        if isinstance(y, int):
            return ModP(self.x*y, self.p)
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP(self.x-y, self.p)
        assert self.p == y.p
        return ModP((self.x - y.x) % self.p, self.p)
    
    def __pow__(self, n):
        # return ModP(pow(self.x, n, self.p), self.p)
        exp = bin(n)
        value = ModP(self.x, self.p)
    
        for i in range(3, len(exp)):
            value = value * value
            if(exp[i:i+1]=='1'):
                value = value*self
        return value
    
    
    def __neg__(self):
        return ModP(self.p - self.x, self.p)
    
    def __eq__(self, y):
        return (self.x == y.x) and (self.p == y.p)

    
    def __str__(self):
        return str(self.x)
    def __repr__(self):
        return str(self.x)
    
def mod_hash(msg: bytes, p: int, non_zero: bool = True) -> ModP:
    """Takes a message and a prime and returns a hash in ModP"""
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16) % 2 ** p.bit_length()
        if x >= p:
            continue
        elif non_zero and x == 0:
            continue
        else:
            return ModP(x, p)


def egcd(a, b):
    """Extended euclid algorithm"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


class ModP:
    """Class representing an integer mod p"""

    def __init__(self, x, p):
        self.x = x
        self.p = p

    def __add__(self, y):
        if isinstance(y, int):
            return ModP(self.x + y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __radd__(self, y):
        return self + y

    def __mul__(self, y):
        if isinstance(y, int):
            return ModP(self.x * y, self.p)
        if isinstance(y, Point):
            return self.x * y
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP((self.x - y) % self.p, self.p)
        assert self.p == y.p
        return ModP((self.x - y.x) % self.p, self.p)

    def __rsub__(self, y):
        return -(self - y)

    def __pow__(self, n):
        return ModP(pow(self.x, n, self.p), self.p)

    def __mod__(self, other):
        return self.x % other

    def __neg__(self):
        return ModP(self.p - self.x, self.p)

    def inv(self):
        """Returns the modular inverse"""
        g, a, _ = egcd(self.x, self.p)
        if g != 1:
            raise Exception("modular inverse does not exist")
        else:
            return ModP(a % self.p, self.p)

    def __eq__(self, y):
        return (self.p == y.p) and (self.x % self.p == y.x % self.p)

    def __str__(self):
        return str(self.x)

    def __repr__(self):
        return str(self.x)


def mod_hash(msg: bytes, p: int, non_zero: bool = True) -> ModP:
    """Takes a message and a prime and returns a hash in ModP"""
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16) % 2 ** p.bit_length()
        if x >= p:
            continue
        elif non_zero and x == 0:
            continue
        else:
            return ModP(x, p)


def point_to_bytes(g: Point) -> bytes:
    """Takes an EC point and returns the compressed bytes representation"""
    if g == Point.IDENTITY_ELEMENT:
        return b"\x00"
    x_enc = g.x.to_bytes(BYTE_LENGTH, "big")
    prefix = b"\x03" if g.y % 2 else b"\x02"
    return prefix + x_enc


def point_to_b64(g: Point) -> bytes:
    """Takes an EC point and returns the base64 compressed bytes representation"""
    return base64.b64encode(point_to_bytes(g))


def b64_to_point(s: bytes) -> Point:
    """Takes a base64 compressed bytes representation and returns the corresponding point"""
    return bytes_to_point(base64.b64decode(s))


def bytes_to_point(b: bytes) -> Point:
    """Takes a compressed bytes representation and returns the corresponding point"""
    if b == 0:
        return Point.IDENTITY_ELEMENT
    p = CURVE.p
    yp, x_enc = b[0], b[1:]
    yp = 0 if yp == 2 else 1
    x = int.from_bytes(x_enc, "big")
    y = mod_sqrt((x ** 3 + CURVE.a * x + CURVE.b) % p, p)[0]
    if y % 2 == yp:
        return Point(x, y, CURVE)
    else:
        return Point(x, p - y, CURVE)


def inner_product(a: List[ModP], b: List[ModP]) -> ModP:
    """Inner-product of vectors in Z_p"""
    assert len(a) == len(b)
    return sum([ai * bi for ai, bi in zip(a, b)], ModP(0, a[0].p))


class NIRangeProver:
    def __init__(
        self,
        v: ModP,
        n: int,
        g: Point,
        h: Point,
        gs: List[Point],
        hs: List[Point],
        gamma: ModP,
        u: Point,
        group,
        seed: bytes = b"",
    ):
        self.v = v
        self.n = n
        self.g = g
        self.h = h
        self.gs = gs
        self.hs = hs
        self.gamma = gamma
        self.u = u
        self.group = group
        self.transcript = Transcript(seed)

    def prove(self):
        v = self.v
        n = self.n
        gs = self.gs
        hs = self.hs
        h = self.h

        aL = list(map(int, reversed(bin(v.x)[2:].zfill(n))))[:n]
        aR = [
            (x - 1) % self.group.q for x in aL
        ]  # TODO implement inverse of elliptic curve point  to compute -1 * g instead of multiplying by p-1
        alpha = mod_hash(b"alpha" + self.transcript.digest, self.group.q)
        A = vector_commitment(gs, hs, aL, aR) + alpha * h
        sL = [
            mod_hash(str(i).encode() + self.transcript.digest, self.group.q)
            for i in range(n)
        ]
        sR = [
            mod_hash(str(i).encode() + self.transcript.digest, self.group.q)
            for i in range(n, 2 * n)
        ]
        rho = mod_hash(str(2 * n).encode() + self.transcript.digest, self.group.q)
        S = vector_commitment(gs, hs, sL, sR) + rho * h
        self.transcript.add_list_points([A, S])
        y = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(y)
        z = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(z)

        t1, t2 = self._get_polynomial_coeffs(aL, aR, sL, sR, y, z)
        tau1 = mod_hash(b"tau1" + self.transcript.digest, self.group.q)
        tau2 = mod_hash(b"tau2" + self.transcript.digest, self.group.q)
        T1 = commitment(self.g, h, t1, tau1)
        T2 = commitment(self.g, h, t2, tau2)
        self.transcript.add_list_points([T1, T2])
        x = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(x)
        taux, mu, t_hat, ls, rs = self._final_compute(
            aL, aR, sL, sR, y, z, x, tau1, tau2, alpha, rho
        )

        # return Proof(taux, mu, t_hat, ls, rs, T1, T2, A, S), x,y,z
        hsp = [(y.inv() ** i) * hs[i] for i in range(n)]
        P = (
            A
            + x * S
            + PipSECP256k1.multiexp(
                gs + hsp,
                [-z for _ in range(n)]
                + [(z * (y ** i)) + ((z ** 2) * (2 ** i)) for i in range(n)],
            )
        )

        InnerProv = NIProver(gs, hsp, self.u, P + (-mu) * h, t_hat, ls, rs, self.group)
        innerProof = InnerProv.prove()

        return Proof(taux, mu, t_hat, T1, T2, A, S, innerProof, self.transcript.digest)

    def _get_polynomial_coeffs(self, aL, aR, sL, sR, y, z):
        t1 = inner_product(
            sL, [(y ** i) * (aR[i] + z) + (z ** 2) * (2 ** i) for i in range(self.n)]
        ) + inner_product(
            [aL[i] - z for i in range(self.n)],
            [(y ** i) * sR[i] for i in range(self.n)],
        )
        t2 = inner_product(sL, [(y ** i) * sR[i] for i in range(self.n)])
        return t1, t2

    def _final_compute(self, aL, aR, sL, sR, y, z, x, tau1, tau2, alpha, rho):
        ls = [aL[i] - z + sL[i] * x for i in range(self.n)]
        rs = [
            (y ** i) * (aR[i] + z + sR[i] * x) + (z ** 2) * (2 ** i)
            for i in range(self.n)
        ]
        t_hat = inner_product(ls, rs)
        taux = tau2 * (x ** 2) + tau1 * x + (z ** 2) * self.gamma
        mu = alpha + rho * x
        return taux, mu, t_hat, ls, rs

    
class Proof:
    """Proof class for Protocol 1"""

    def __init__(self, taux, mu, t_hat, T1, T2, A, S, innerProof, transcript):
        self.taux = taux
        self.mu = mu
        self.t_hat = t_hat
        self.T1 = T1
        self.T2 = T2
        self.A = A
        self.S = S
        self.innerProof = innerProof
        self.transcript = transcript


class RangeVerifier:
    """Verifier class for Range Proofs"""

    def __init__(self, V, g, h, gs, hs, u, proof: Proof):
        self.V = V
        self.g = g
        self.h = h
        self.gs = gs
        self.hs = hs
        self.u = u
        self.proof = proof

    def assertThat(self, expr: bool):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        proof = self.proof
        p = proof.taux.p
        lTranscript = proof.transcript.split(b"&")
        self.assertThat(lTranscript[1] == point_to_b64(proof.A))
        self.assertThat(lTranscript[2] == point_to_b64(proof.S))
        self.y = ModP(int(lTranscript[3]), p)
        self.z = ModP(int(lTranscript[4]), p)
        self.assertThat(lTranscript[5] == point_to_b64(proof.T1))
        self.assertThat(lTranscript[6] == point_to_b64(proof.T2))
        self.x = ModP(int(lTranscript[7]), p)

    def verify(self):
        """Verifies the proof given by a prover. Raises an execption if it is invalid"""
        self.verify_transcript()

        g = self.g
        h = self.h
        gs = self.gs
        hs = self.hs
        x = self.x
        y = self.y
        z = self.z
        proof = self.proof

        n = len(gs)
        delta_yz = (z - z ** 2) * sum(
            [y ** i for i in range(n)], ModP(0, CURVE.q)
        ) - (z ** 3) * ModP(2 ** n - 1, CURVE.q)
        hsp = [(y.inv() ** i) * hs[i] for i in range(n)]
        self.assertThat(
            proof.t_hat * g + proof.taux * h
            == (z ** 2) * self.V + delta_yz * g + x * proof.T1 + (x ** 2) * proof.T2
        )

        P = self._getP(x, y, z, proof.A, proof.S, gs, hsp, n)
        # self.assertThat(
        #     P == vector_commitment(gs, hsp, proof.ls, proof.rs) + proof.mu * h
        # )
        # self.assertThat(proof.t_hat == inner_product(proof.ls, proof.rs))
        InnerVerif = Verifier1(
            gs, hsp, self.u, P + (-proof.mu) * h, proof.t_hat, proof.innerProof
        )
        return InnerVerif.verify()

    def _getP(self, x, y, z, A, S, gs, hsp, n):
        return (
            A
            + x * S
            + PipSECP256k1.multiexp(
                gs + hsp,
                [-z for _ in range(n)]
                + [(z * (y ** i)) + ((z ** 2) * (2 ** i)) for i in range(n)],
            )
        )


    def _getP(self, x, y, z, A, S, gs, hsp, n):
        return (
            A
            + x * S
            + PipSECP256k1.multiexp(
                gs + hsp,
                [-z for _ in range(n)]
                + [(z * (y ** i)) + ((z ** 2) * (2 ** i)) for i in range(n)],
            )
        )

class Verifier1:
    """Verifier class for Protocol 1"""

    def __init__(self, g, h, u, P, c, proof1):
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.proof1 = proof1

    def assertThat(self, expr: bool):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        lTranscript = self.proof1.transcript.split(b"&")
        self.assertThat(
            lTranscript[1]
            == str(mod_hash(b"&".join(lTranscript[:1]) + b"&", SUPERCURVE.q)).encode()
        )

    def verify(self):
        """Verifies the proof given by a prover. Raises an execption if it is invalid"""
        self.verify_transcript()

        lTranscript = self.proof1.transcript.split(b"&")
        x = lTranscript[1]
        x = ModP(int(x), SUPERCURVE.q)
        self.assertThat(self.proof1.P_new == self.P + (x * self.c) * self.u)
        self.assertThat(self.proof1.u_new == x * self.u)

        Verif2 = Verifier2(
            self.g, self.h, self.proof1.u_new, self.proof1.P_new, self.proof1.proof2
        )

        return Verif2.verify()

    

class Proof2:
    """Proof class for Protocol 2"""

    def __init__(self, a, b, xs, Ls, Rs, transcript, start_transcript: int = 0):
        self.a = a
        self.b = b
        self.xs = xs
        self.Ls = Ls
        self.Rs = Rs
        self.transcript = transcript
        self.start_transcript = (
            start_transcript
        )  # Start of transcript to be used if Protocol 2 is run in Protocol 1


        
class Verifier2:
    """Verifier class for Protocol 2"""

    def __init__(self, g, h, u, P, proof: Proof2):
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.proof = proof

    def assertThat(self, expr):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def get_ss(self, xs):
        """See page 15 in paper"""
        n = len(self.g)
        log_n = n.bit_length() - 1
        ss = []
        for i in range(1, n + 1):
            tmp = ModP(1, SUPERCURVE.q)
            for j in range(0, log_n):
                b = 1 if bin(i - 1)[2:].zfill(log_n)[j] == "1" else -1
                tmp *= xs[j] if b == 1 else xs[j].inv()
            ss.append(tmp)
        return ss

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        init_len = self.proof.start_transcript
        n = len(self.g)
        log_n = n.bit_length() - 1
        Ls = self.proof.Ls
        Rs = self.proof.Rs
        xs = self.proof.xs
        lTranscript = self.proof.transcript.split(b"&")
        for i in range(log_n):
            self.assertThat(lTranscript[init_len + i * 3] == point_to_b64(Ls[i]))
            self.assertThat(lTranscript[init_len + i * 3 + 1] == point_to_b64(Rs[i]))
            self.assertThat(
                str(xs[i]).encode()
                == lTranscript[init_len + i * 3 + 2]
                == str(
                    mod_hash(
                        b"&".join(lTranscript[: init_len + i * 3 + 2]) + b"&",
                        SUPERCURVE.q,
                    )
                ).encode()
            )

    def verify(self):
        """Verifies the proof given by a prover. Raises an execption if it is invalid"""
        self.verify_transcript()

        proof = self.proof
        Pip = PipSECP256k1
        ss = self.get_ss(self.proof.xs)
        LHS = Pip.multiexp(
            self.g + self.h + [self.u],
            [proof.a * ssi for ssi in ss]
            + [proof.b * ssi.inv() for ssi in ss]
            + [proof.a * proof.b],
        )
        RHS = self.P + Pip.multiexp(
            proof.Ls + proof.Rs,
            [xi ** 2 for xi in proof.xs] + [xi.inv() ** 2 for xi in proof.xs],
        )

        self.assertThat(LHS == RHS)
        return True

class Transcript:
    """
    Transcript class.
    Contains all parameters used to generate randomness using Fiat-Shamir
    Separate every entity by a '&'. 
    """

    def __init__(self, seed=b""):
        self.digest = base64.b64encode(seed) + b"&"

    def add_point(self, g):
        """Add an elliptic curve point to the transcript"""
        self.digest += point_to_b64(g)
        self.digest += b"&"

    def add_list_points(self, gs):
        """Add a list of elliptic curve point to the transcript"""
        for g in gs:
            self.add_point(g)

    def add_number(self, x):
        """Add a number to the transcript"""
        self.digest += str(x).encode()
        self.digest += b"&"

    def get_modp(self, p):
        """Generate a number as the hash of the digest"""
        return mod_hash(self.digest, p)


class Proof1:
    """Proof class for Protocol 1"""

    def __init__(self, u_new, P_new, proof2, transcript):
        self.u_new = u_new
        self.P_new = P_new
        self.proof2 = proof2
        self.transcript = transcript


        
class NIProver:
    """Class simulating a NI prover for the inner-product argument (Protocol 1)"""
    def __init__(self, g, h, u, P, c, a, b, group, seed=b""):
        assert len(g) == len(h) == len(a) == len(b)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.a = a
        self.b = b
        self.group = group
        self.transcript = Transcript(seed)

    def prove(self) -> Proof1:
        """
        Proves the inner-product argument following Protocol 1 in the paper
        Returns a Proof1 object.
        """
        # x = mod_hash(self.transcript.digest, self.group.order)
        x = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(x)
        P_new = self.P + (x * self.c) * self.u
        u_new = x * self.u
        Prov2 = FastNIProver2(
            self.g,
            self.h,
            u_new,
            P_new,
            self.a,
            self.b,
            self.group,
            self.transcript.digest,
        )
        return Proof1(u_new, P_new, Prov2.prove(), self.transcript.digest)


class FastNIProver2:
    """Class simulating a NI prover for the inner-product argument (Protocol 2)"""
    def __init__(self, g, h, u, P, a, b, group, transcript: Optional[bytes]=None):
        assert len(g) == len(h) == len(a) == len(b)
        assert len(a) & (len(a) - 1) == 0
        self.log_n = len(a).bit_length() - 1
        self.n = len(a)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.a = a
        self.b = b
        self.group = group
        self.transcript = Transcript()
        if transcript:
            self.transcript.digest += transcript
            self.init_transcript_length = len(transcript.split(b"&"))
        else:
            self.init_transcript_length = 1


    def prove(self):
        """
        Proves the inner-product argument following Protocol 2 in the paper
        Returns a Proof2 object.
        """
        gp = self.g
        hp = self.h
        ap = self.a
        bp = self.b

        xs = []
        Ls = []
        Rs = []

        while True:
            if len(ap) == len(bp) == len(gp) == len(hp) == 1:
                return Proof2(
                    ap[0],
                    bp[0],
                    xs,
                    Ls,
                    Rs,
                    self.transcript.digest,
                    self.init_transcript_length,
                )
            np = len(ap) // 2
            cl = inner_product(ap[:np], bp[np:])
            cr = inner_product(ap[np:], bp[:np])
            L = vector_commitment(gp[np:], hp[:np], ap[:np], bp[np:]) + cl * self.u
            R = vector_commitment(gp[:np], hp[np:], ap[np:], bp[:np]) + cr * self.u
            Ls.append(L)
            Rs.append(R)
            self.transcript.add_list_points([L, R])
            # x = mod_hash(self.transcript.digest, self.group.order)
            x = self.transcript.get_modp(self.group.q)
            xs.append(x)
            self.transcript.add_number(x)
            gp = [x.inv() * gi_fh + x * gi_sh for gi_fh, gi_sh in zip(gp[:np], gp[np:])]
            hp = [x * hi_fh + x.inv() * hi_sh for hi_fh, hi_sh in zip(hp[:np], hp[np:])]
            ap = [x * ai_fh + x.inv() * ai_sh for ai_fh, ai_sh in zip(ap[:np], ap[np:])]
            bp = [x.inv() * bi_fh + x * bi_sh for bi_fh, bi_sh in zip(bp[:np], bp[np:])]


def subset_of(l):
    return sum(map(lambda r: list(combinations(l, r)), range(1, len(l)+1)), [])

class Pippenger:
    def __init__(self, group):
        self.G = group
        self.order = group.order
        self.lamb = group.order.bit_length()
    
    # Returns g^(2^j)
    def _pow2powof2(self, g, j):
        tmp = g
        for _ in range(j):
            tmp = self.G.square(tmp)
        return tmp

    # Returns Prod g_i ^ e_i
    def multiexp(self, gs, es):
        if len(gs) != len(es):
            raise Exception('Different number of group elements and exponents')

        es = [ei%self.G.order for ei in es]

        if len(gs) == 0:
            return self.G.unit

        lamb = self.lamb
        N = len(gs)
        s = integer_nthroot(lamb//N, 2)[0]+1
        t = integer_nthroot(lamb*N,2)[0]+1
        gs_bin = []
        for i in range(N):
            tmp = [gs[i]]
            for j in range(1,s):
                tmp.append(self.G.square(tmp[-1]))
            gs_bin.append(tmp)
        es_bin = []
        for i in range(N):
            tmp1 = []
            for j in range(s):
                tmp2 = []
                for k in range(t):
                    tmp2.append(int( bin(es[i])[2:].zfill(s*t)[-(j+s*k+1)]) )
                tmp1.append(tmp2)
            es_bin.append(tmp1)
        
        Gs = self._multiexp_bin(
                [gs_bin[i][j] for i in range(N) for j in range(s)],
                [es_bin[i][j] for i in range(N) for j in range(s)]
                )

        ans2 = Gs[-1]
        for k in range(len(Gs)-2,-1,-1):
            ans2 = self._pow2powof2(ans2, s)
            ans2 = self.G.mult(ans2, Gs[k])

        return ans2
        
    def _multiexp_bin(self, gs, es):
        assert len(gs) == len(es)
        M = len(gs)
        b = floor( log2(M) - log2(log2(M)) )
        b = b if b else 1
        subsets = [list(range(i,min(i+b,M))) for i in range(0,M,b)]
        Ts = [{sub: None for sub in subset_of(S)} for S in subsets]

        for T,S in zip(Ts, subsets):
            for i in S:
                T[(i,)] = gs[i]
            # Recursively set the subproducts in T
            def set_sub(sub):
                if T[sub] is None:
                    if T[sub[:-1]] is None:
                        set_sub(sub[:-1])
                    T[sub] = self.G.mult(T[sub[:-1]], gs[sub[-1]])
            for sub in T:
                set_sub(sub)
            
        Gs = []
        for k in range(len(es[0])):
            tmp = self.G.unit
            for T,S in zip(Ts, subsets):
                sub_es = [j for j in S if es[j][k]]
                sub_es = tuple(sub_es)
                if not sub_es:
                    continue
                tmp = self.G.mult(tmp, T[sub_es])
            Gs.append(tmp)
            
        return Gs


    
class Group(ABC):
    def __init__(self, unit, order):
        self.unit = unit
        self.order = order

    @abstractmethod
    def mult(self, x, y):
        pass

    def square(self, x):
        return self.mult(x, x)


class MultIntModP(Group):
    def __init__(self, p, order):
        Group.__init__(self, ModP(1, p), order)

    def mult(self, x, y):
        return x * y


class EC(Group):
    def __init__(self, curve: Curve):
        Group.__init__(self, curve.G.IDENTITY_ELEMENT, curve.q)

    def mult(self, x, y):
        return x + y

class EC(Group):
    def __init__(self, curve: Curve):
        Group.__init__(self, curve.G.IDENTITY_ELEMENT, curve.q)

    def mult(self, x, y):
        return x + y

    
PipSECP256k1 = Pippenger(EC(secp256k1))

def commitment(g, h, x, r):
    return x * g + r * h


def vector_commitment(g, h, a, b):
    assert len(g) == len(h) == len(a) == len(b)
    
    # return sum([ai*gi for ai,gi in zip(a,g)], Point(None,None,None)) \
    #         + sum([bi*hi for bi,hi in zip(b,h)], Point(None,None,None))
    return PipSECP256k1.multiexp(g + h, a + b)


def _mult(a: int, g: Point) -> Point:
    if a < 0 and abs(a) < 2 ** 32:
        return abs(a) * _inv(g)
    else:
        return a * g


def _inv(g: Point) -> Point:
    return Point(g.x, -g.y, g.curve)
