#!/usr/bin/env python

import sys
import os
from optparse import OptionParser

sys.path.insert(0, os.path.join(os.path.dirname(sys.argv[0]), "pywallet"))
import pywallet

# Needs PyCrypto
from Crypto.Random.random import sample as secure_sample
from Crypto.Hash import SHA256

def valid_mini(candidate):
    return SHA256.new(candidate + "?").digest()[0] == "\0"

def generate_mini_private_key(length=30):       # length can be 22, 26, or 30
    while True:
        candidate = "S" + "".join(secure_sample(pywallet.__b58chars, 1)[0] for i in range(length-1))
        if valid_mini(candidate):
            return candidate

def main():
    count = 0
    while count < 50:
        parser = OptionParser()
        parser.add_option("--testnet", help="generate testnet addresses", dest="testnet", action="store_true", default=False)
        parser.add_option("--wif", help="specify a WIF address on the command line instead of generating it", dest="wif", action="store_true", default=False)
        (options, args) = parser.parse_args()
        if options.testnet:
            pywallet.addrtype = 111
        if options.wif:
            sec_mini = None
            sec_raw = pywallet.DecodeBase58Check(args[0])[1:]
        elif args:
            sec_mini = args[0]
            if not valid_mini(sec_mini):
                print >>sys.stderr, "not a valid mini key"
                sys.exit(1)
            sec_raw = SHA256.new(sec_mini).digest()
        else:
            sec_mini = generate_mini_private_key()
            sec_raw = SHA256.new(sec_mini).digest()
        sec_hex = sec_raw.encode('hex').upper()
        sec_wallet = pywallet.EncodeBase58Check("\x80" + sec_raw)   # wallet import format
        pkey = pywallet.regenerate_key(pywallet.SecretToASecret(sec_raw))
        assert sec_raw == pywallet.GetSecret(pkey)
        priv_key = pywallet.GetPrivKey(pkey)
        pub_key = pywallet.GetPubKey(pkey)
        pub_addr = pywallet.public_key_to_bc_address(pub_key)
        #print "Address:        %s" % (pub_addr,)
        #print "Privkey:        %s" % (sec_wallet,)
        #print "Privkey (hex):  %s" % (sec_hex,)
        #print "Privkey (mini): %s" % (sec_mini,)
        #print "EC private key: %s" % (priv_key.encode('hex'),)
        #print "EC public key: %s" % (pub_key.encode('hex'),)
        with open("minigen.csv", "a") as f:
            f.write(pub_addr + ", " + sec_wallet)
            f.flush()
            #os.sync()
            count += 1
            print("%s keys generated." % (count,))
if __name__ == '__main__':
    main()
