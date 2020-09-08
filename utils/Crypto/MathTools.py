import gmpy2

def fermat_sieve(n,rounds):
    a = gmpy2.isqrt_rem(n)[0]
    valid = n%20
    Val = [0,1,4,5,9,16]
    Cand = set()
    for i in range(10):
        for j in Val:
            if ((a-i)**2-j)%20 in Val:
              Cand.add(j)
    b = 0
    for i in range(rounds):
        a_2 = a**2
        b_2 = a_2-n
        if b_2%20 in Cand:
            if gmpy2.is_square(b_2):
                b = gmpy2.iroot(b_2,2)[0]
                return a-b,a+b
        a_min_b = int(a-b)
        a+=1
    return None,None
