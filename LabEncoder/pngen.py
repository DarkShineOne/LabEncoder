import random


def mod_power(a, n, m):
    r = 1
    while n > 0:
        if n & 1 == 1:
            r = (r * a) % m
        a = (a * a) % m
        n >>= 1
    return r


# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]


def nBitRandom(n):
    return random.randrange(2**(n-1)+1, 2**n - 1)


def getLowLevelPrime(n):
    while True:
        pc = nBitRandom(n)

        # Test divisibility by pre-generated
        # primes
        for divisor in first_primes_list:
            if pc % divisor == 0:
                break
        else:
            return pc


def miller_rabin(n, k):
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s >>= 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def getRandomPrime(bits):
    while (True):
        n = bits
        # prime_candidate = randprime(2**(n-1)+1, 2**n - 1)
        prime_candidate = getLowLevelPrime(n)
        # tic = time.perf_counter()
        if not miller_rabin(prime_candidate, 64):
            # toc = time.perf_counter()
            # print(toc-tic)
            continue
        else:
            return prime_candidate


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x
