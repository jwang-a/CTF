"""
The MIT License (MIT)
Copyright (c) 2019-2020 Nao Yonashiro
Modified 2020 James Wang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
"""
from typing import Tuple, Iterator, Iterable, Optional
from Crypto.Util.number import GCD
import random

def isqrt(n: int) -> int:
    """
    ref: https://en.wikipedia.org/wiki/Integer_square_root
    
    >>> isqrt(289)
    17
    >>> isqrt(2)
    1
    >>> isqrt(1000000 ** 2)
    1000000
    """
    if n == 0:
        return 0

    # ref: https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Rough_estimation
    x = 2 ** ((n.bit_length() + 1) // 2)
    while True:
        y = (x + n // x) // 2
        if y >= x:
            return x
        x = y


def is_perfect_square(n: int) -> bool:
    """
    ref: http://d.hatena.ne.jp/hnw/20140503
    ref: https://github.com/AlexeiSheplyakov/gmp.pkg/blob/master/mpn/generic/perfsqr.c

    >>> is_perfect_square(100)
    True
    
    >>> is_perfect_square(2000000000000000000000000000 ** 2)
    True

    >>> is_perfect_square(2000000000000000000000000000 ** 2 + 1)
    False
    """
    sq_mod256 = (1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0)
    if sq_mod256[n & 0xff] == 0:
        return False

    mt = (
        (9, (1,1,0,0,1,0,0,1,0)),
        (5, (1,1,0,0,1)),
        (7, (1,1,1,0,1,0,0)),
        (13, (1,1,0,1,1,0,0,0,0,1,1,0,1)),
        (17, (1,1,1,0,1,0,0,0,1,1,0,0,0,1,0,1,1))
    )
    a = n % (9 * 5 * 7 * 13 * 17)
    if any(t[a % m] == 0 for m, t in mt):
        return False

    return isqrt(n) ** 2 == n


def rational_to_contfrac(x: int, y: int) -> Iterator[int]:
    """
    ref: https://en.wikipedia.org/wiki/Euclidean_algorithm#Continued_fractions
    
    >>> list(rational_to_contfrac(4, 11))
    [0, 2, 1, 3]
    """
    while y:
        a = x // y
        yield a
        x, y = y, x - a * y


def contfrac_to_rational_iter(contfrac: Iterable[int]) -> Iterator[Tuple[int, int]]:
    """
    ref: https://www.cits.ruhr-uni-bochum.de/imperia/md/content/may/krypto2ss08/shortsecretexponents.pdf (6)
    """
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for q in contfrac:
        n = q * n1 + n0
        d = q * d1 + d0
        yield n, d
        n0, d0 = n1, d1
        n1, d1 = n, d


def convergents_from_contfrac(contfrac: Iterable[int]) -> Iterator[Tuple[int, int]]:
    """
    ref: https://www.cits.ruhr-uni-bochum.de/imperia/md/content/may/krypto2ss08/shortsecretexponents.pdf Section.3
    """
    n_, d_ = 1, 0
    for i, (n, d) in enumerate(contfrac_to_rational_iter(contfrac)):
        if i % 2 == 0:
            yield n + n_, d + d_
        else:
            yield n, d
        n_, d_ = n, d


def attack(e: int, n: int) -> Optional[int]:
    """
    ref: https://www.cits.ruhr-uni-bochum.de/imperia/md/content/may/krypto2ss08/shortsecretexponents.pdf Section.4
    ref: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf
    modified to return (d,p,q)
    """
    d = None
    f_ = rational_to_contfrac(e, n)
    for k, dg in convergents_from_contfrac(f_):
        edg = e * dg
        phi = edg // k

        x = n - phi + 1
        if x % 2 == 0 and is_perfect_square((x // 2) ** 2 - n):
            g = edg - phi * k
            d = dg // g
            break
    if d is None:
        return None
    k = d*e-1
    t=0
    r=k
    while r%2!=1:
        r//=2
        t+=1
        if t==0:
            return (D,None,None)
    for i in range(100):
        FIN=0
        g = random.randint(0,n-1)
        y = pow(g,r,n)
        if y==1 or y==n-1:
            continue
        for j in range(t):
            x = pow(y,2,n)
            if x==1:
                FIN = 2
                break
            if x==n-1:
                FIN = 1
                break
            y = x
        if FIN==1:
            continue
        if FIN==2:
            break
        x = pow(y,2,n)
        if x==1:
            break
    p = GCD(y-1,n)
    q = n//p
    return (d,p,q)

