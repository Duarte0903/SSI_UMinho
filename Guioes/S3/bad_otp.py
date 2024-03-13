import sys
import random

def bad_prng(n):
    """ an INSECURE pseudo-random number generator """
    random.seed(random.randbytes(2))
    return random.randbytes(n)

def generate_random_bytes(num_bytes):
    return bad_prng(num_bytes)

def read_bytes_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def otp_setup(num_bytes, key_filename):
    random_bytes = generate_random_bytes(num_bytes)
    with open(key_filename, 'wb') as file:
        file.write(random_bytes)

def otp_enc(message_filename, key_filename):
    message = read_bytes_from_file(message_filename)
    key = read_bytes_from_file(key_filename)

    encrypted_message = bytes(x ^ y for x, y in zip(message, key))

    with open(message_filename + ".enc", 'wb') as file:
        file.write(encrypted_message)

def otp_dec(ciphertext_filename, key_filename):
    ciphertext = read_bytes_from_file(ciphertext_filename)
    key = read_bytes_from_file(key_filename)

    decrypted_message = bytes(x ^ y for x, y in zip(ciphertext, key))

    with open(ciphertext_filename + ".dec", 'wb') as file:
        file.write(decrypted_message)

def main():
    if len(sys.argv) < 2:
        print("Usage: python bad_otp.py <setup|enc|dec> args...")
        sys.exit(1)

    command = sys.argv[1]

    if command == "setup":
        _, _, num_bytes, key_filename = sys.argv
        num_bytes = int(num_bytes)
        otp_setup(num_bytes, key_filename)

    elif command == "enc":
        message_filename, key_filename = sys.argv[2:]
        otp_enc(message_filename, key_filename)

    elif command == "dec":
        ciphertext_filename, key_filename = sys.argv[2:]
        otp_dec(ciphertext_filename, key_filename)

if __name__ == "__main__":
    main()