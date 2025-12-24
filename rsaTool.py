"""
RSA Key Pair Utility Module for CTF Challenges

This module provides a class to manage and calculate various components of
the RSA cryptosystem, including private/public keys and CRT parameters.
"""

import gmpy2


class rsaKeyPair:
    """
    A class to represent and calculate RSA key pair components.

    Attributes:
        p (int): The first prime factor.
        q (int): The second prime factor.
        e (int): Public exponent.
        n (int): Modulus (p * q).
        d (int): Private exponent.
        phiN (int): Euler's totient function of n.
        dp (int): CRT exponent for p (d mod (p-1)).
        dq (int): CRT exponent for q (d mod (q-1)).
    """

    p: int | None = None
    q: int | None = None
    e: int | None = None
    n: int | None = None
    d: int | None = None
    phiN: int | None = None
    dp: int | None = None
    dq: int | None = None

    def stat(self) -> dict:
        """
        Return the current state of all RSA parameters.

        Returns:
            dict: A dictionary containing p, q, e, n, d, phiN, dp, and dq.
        """
        return {
            "p": self.p,
            "q": self.q,
            "e": self.e,
            "n": self.n,
            "d": self.d,
            "phiN": self.phiN,
            "dp": self.dp,
            "dq": self.dq,
        }

    def setP(self, p: int):
        """Set the value of prime p."""
        self.p = p

    def setQ(self, q: int):
        """Set the value of prime q."""
        self.q = q

    def setE(self, e: int):
        """Set the public exponent e."""
        self.e = e

    def setDp(self, dp: int):
        """Set the CRT exponent dp."""
        self.dp = dp

    def setDq(self, dq: int):
        """Set the CRT exponent dq."""
        self.dq = dq

    def calculateEFromDpAndDq(self):
        """
        Calculate the public exponent e using dp, dq, and the primes.

        Raises:
        ValueError: If dp or dq is not set.

        Note: This is an unusual recovery method based on CRT properties.
        """
        if not ((self.dp and self.p) or (self.dq and self.q)):
            raise ValueError("Need (dp and p) OR (dq and q) to calculate e")

        # 尝试从 p 侧恢复 e
        if self.dp and self.p:
            try:
                # e * dp = 1 mod (p-1) => e = invert(dp, p-1)
                self.e = int(gmpy2.invert(self.dp, self.p - 1))
            except ZeroDivisionError:
                raise ValueError("d_p is not invertible mod (p-1)")

        # 如果 p 侧不行，尝试从 q 侧恢复，或者用于校验
        elif self.dq and self.q:
            try:
                self.e = int(gmpy2.invert(self.dq, self.q - 1))
            except ZeroDivisionError:
                raise ValueError("d_q is not invertible mod (q-1)")

        # 如果 p 和 q 都在，计算 n
        if self.p and self.q:
            self.n = self.p * self.q

    def calculateKeyPair(self):
        """
        Calculate all remaining RSA parameters (n, phiN, d, dp, dq)
        based on the currently set p, q, and e.

        Raises:
            ValueError: If the public exponent e has not been set.
        """
        if not self.e:
            raise ValueError("e is not set")
        if not self.p or not self.q:
            raise ValueError("p or q is not set")

        self.n = self.p * self.q
        self.phiN = (self.p - 1) * (self.q - 1)

        try:
            self.d = int(gmpy2.invert(self.e, self.phiN))
        except ZeroDivisionError:
            raise ValueError(
                f"e ({self.e}) is not coprime to phiN, modular inverse does not exist."
            )

        self.dp = int(gmpy2.invert(self.e, self.p - 1))
        self.dq = int(gmpy2.invert(self.e, self.q - 1))

    def encrypt(self, msg: int) -> int:
        if not self.e or not self.n:
            raise ValueError("e and n are required for encryption")
        return int(gmpy2.powmod(msg, self.e, self.n))

    def decrypt(self, msg: int) -> int:
        if not self.d or not self.n:
            raise ValueError("d and n are required for decryption")
        return int(gmpy2.powmod(msg, self.d, self.n))


if __name__ == "__main__":
    key = rsaKeyPair()
    helpText = """h -> str                print help text
bye                     exit program
p <p:int>               set prime p
q <q:int>               set prime q
e <e:int>               set public exponent
dp <dp:int>             set dp
dq <dq:int>             set dq
s -> dict               print all parameters
ce                      calculate e from dp and dq
ck                      calculate n, phiN, d, dp, dq
enc <msg:int> -> int    encrypt msg
dec <msg:int> -> int    decrypt msg"""
    while 1:
        userInput = input("rsa tool> ").lower().strip().split()
        mode = userInput[0] if len(userInput) > 0 else None
        arg = int(userInput[1]) if len(userInput) > 1 else None
        if not mode:
            continue
        match mode:
            case "bye":
                break
            case "h":
                print(helpText)
            case "p":
                if not arg:
                    print("[!] missing argument")
                    continue
                key.setP(arg)
            case "q":
                if not arg:
                    print("[!] missing argument")
                    continue
                key.setQ(arg)
            case "e":
                if not arg:
                    print("[!] missing argument")
                    continue
                key.setE(arg)
            case "dp":
                if not arg:
                    print("[!] missing argument")
                    continue
                key.setDp(arg)
            case "dq":
                if not arg:
                    print("[!] missing argument")
                    continue
                key.setDq(arg)
            case "s":
                print(key.stat())
            case "ce":
                key.calculateEFromDpAndDq()
            case "ck":
                key.calculateKeyPair()
            case "enc":
                if not arg:
                    print("[!] missing argument")
                    continue
                print(key.encrypt(arg))
            case "dec":
                if not arg:
                    print("[!] missing argument")
                    continue
                print("\n" + str(key.decrypt(arg)))
            case _:
                print("[!] unknown command")
