#!/usr/bin/env python3

import hashlib
import timeit

NUMBER_HASHES = 10000


def hash_loop(hash_algo, data):
    _digest = hash_algo(data).digest()

def hash_measurement(hash_algo, hash_algo_name, data_len):
    data = b'\xab' * data_len
    measured_function = lambda: hash_loop(hash_algo, data)
    time_in_secs = timeit.timeit(measured_function, number=NUMBER_HASHES)
    hashes_per_second = NUMBER_HASHES / time_in_secs
    print("{:10}  {:10,}  {:10,}".format(hash_algo_name, data_len, int(hashes_per_second)))

def experiment():
    print("{:10}  {:10}  {:10}".format("Algo", "Data size", "Hashes/sec"))
    line = '-' * 10
    print("{:10}  {:10}  {:10}".format(line, line, line))
    for data_len in [10, 100, 1000, 10000]:
        for hash_algo, hash_algo_name in [(hashlib.md5, "MD-5"),
                                          (hashlib.sha1, "SHA-1"),
                                          (hashlib.sha224, "SHA-224"),
                                          (hashlib.sha256, "SHA-256"),
                                          (hashlib.sha384, "SHA-384"),
                                          (hashlib.sha512, "SHA-512"),
                                          (hashlib.sha3_224, "SHA3-224"),
                                          (hashlib.sha3_256, "SHA3-256"),
                                          (hashlib.sha3_384, "SHA3-384"),
                                          (hashlib.sha3_512, "SHA3-512"),
                                          (hashlib.blake2b, "BLAKE-2B"),
                                          (hashlib.blake2s, "BLAKE-2S")]:
            hash_measurement(hash_algo, hash_algo_name, data_len)

if __name__ == "__main__":
    experiment()
