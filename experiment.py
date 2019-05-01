#!/usr/bin/env python3

import hashlib
import hmac
import timeit

NUMBER_DIGESTS = 100000

SECRET = "This-is-my-super-duper-secret-key-12345#"

def digest_loop(digestmod, data):
    the_hmac = hmac.new(SECRET.encode(), digestmod=digestmod)
    the_hmac.update(data)
    _digest = the_hmac.digest()

def digest_measurement(digestmod, digestmod_name, data_len):
    data = b'\xab' * data_len
    measured_function = lambda: digest_loop(digestmod, data)
    time_in_secs = timeit.timeit(measured_function, number=NUMBER_DIGESTS)
    hashes_per_second = NUMBER_DIGESTS / time_in_secs
    usecs_per_hash = 1000000 / hashes_per_second
    print("{:12}  {:12,}  {:12,}  {:12,}".format(digestmod_name, data_len, int(hashes_per_second),
                                         int(usecs_per_hash)))

def experiment():
    print("{:12}  {:12}  {:12}  {:12}".format("Algo", "Data size", "Digests/sec", "Usec/digest"))
    line = '-' * 12
    print("{:12}  {:12}  {:12}  {:12}".format(line, line, line, line))
    for data_len in [10, 100, 1500, 10000]:
        for digestmod, digestmod_name in [(hashlib.md5, "MD-5"),
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
            digest_measurement(digestmod, digestmod_name, data_len)

if __name__ == "__main__":
    experiment()
