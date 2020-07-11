#! /usr/bin/python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import yaml
from datetime import datetime
import binascii
import random

def generate_xxx(cipher_mode, key_size, num_aes_blocks, yamlfile):
    assert(key_size in [128,192,256])

    iv = os.urandom(16)

    if(cipher_mode == 'AES_CBC'):
        mode = modes.CBC(iv)
    elif(cipher_mode == 'AES_CFB'):
        mode = modes.CFB(iv)
    elif(cipher_mode == 'AES_OFB'):
        mode = modes.OFB(iv)
    elif(cipher_mode == 'AES_CTR'):
        mode = modes.CTR(iv)
    elif(cipher_mode == 'AES_ECB'):
        mode = modes.ECB()
        iv = b''
    else:
        print("Invalid cipher_mode parameter = %s" % cipher_mode)


    key = os.urandom(key_size//8)
    
    alg = algorithms.AES(key)
    
    cipher = Cipher(alg,mode,default_backend())
    enc = cipher.encryptor()
    pt = os.urandom(num_aes_blocks*16)
    ct = enc.update(pt)

    testvector = {  'Mode'  : cipher_mode,
                    'key'   : binascii.hexlify(key).decode("utf-8"),
                    'iv'    : binascii.hexlify(iv).decode("utf-8"),
                    'pt'    : binascii.hexlify(pt).decode("utf-8"),
                    'ct'    : binascii.hexlify(ct).decode("utf-8")
                }

    yaml.dump([testvector],yamlfile,default_flow_style=False)

def generate_gcm(key_size, ptlen, aadlen):
    assert(key_size in [128,192,256])
    key = os.urandom(key_size//8)
    iv = os.urandom(12)
    pt = os.urandom(ptlen)
    aad = os.urandom(aadlen)
    alg = algorithms.AES(key)
    mode = modes.GCM(iv)
    cipher = Cipher(alg,mode,default_backend())
    enc = cipher.encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(pt)
    enc.finalize()
    tag = enc.tag
    testvector = {  'Mode'  : 'AES_GCM',
                    'key'   : binascii.hexlify(key).decode("utf-8"),
                    'iv'    : binascii.hexlify(iv).decode("utf-8"),
                    'pt'    : binascii.hexlify(pt).decode("utf-8"),
                    'aad'   : binascii.hexlify(aad).decode("utf-8"),
                    'ct'    : binascii.hexlify(ct).decode("utf-8"),
                    'tag'   : binascii.hexlify(tag).decode("utf-8")
                }
    yaml.dump([testvector],yamlfile,default_flow_style=False)

yamlfile = open('test_vectors.yml', 'w')
test_count = 0
num_vectors = int(sys.argv[1])

for i in range(0,num_vectors):
    for mode in ['AES_CBC', "AES_CFB", "AES_OFB", "AES_CTR", "AES_ECB"]:
        for keysize in [128,192,256]:
            generate_xxx(
                mode,
                keysize,
                random.randint(16,10000)//16 * 16,
                yamlfile
            )
            test_count = test_count + 1
            print ("Generated " + str(test_count) + " vectors")

for i in range(0,num_vectors):
    for keysize in [128,192,256]:

        generate_gcm(
            keysize,
            random.randint(16,10000)//16 * 16,
            random.randint(16,10000)//16 * 16
        )
        test_count = test_count + 1
        print ("Generated " + str(test_count) + " vectors")

yamlfile.close()

