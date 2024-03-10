import random

def bad_prng(n):
    """ an INSECURE pseudo-random number generator """
    random.seed(random.randbytes(2))
    return random.randbytes(n)

def bad_otp():
    for _ in range(2 ** 16):
        random.seed(random.randbytes(2))
        if bad_prng(1) == 42:
            return True
    return False

def main():
    if bad_otp():
        print("Insecure PRNG is vulnerable.")
    else:
        print("Insecure PRNG is not vulnerable.")

if __name__ == "__main__":
    main()