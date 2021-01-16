#!/bin/python3

'''
# SEA API (https://gun.eco/docs/SEA)

POC for transposing SEA in python.

The default cryptographic primitives for the asymmetric keys
are ECDSA for signing and ECDH for encryption.

returns Object { 
    pub: (public key); ECDSA [verify]
    priv: (private key); ECDSA [sign]
    epub: (public key for encryption); ECDH
    epriv: (private key for encryption);  ECDH 
    }
'''

import base64
from ecdsa import SigningKey,VerifyingKey, NIST256p, ECDH
from hashlib import sha256

# Example signed message and key 'SEA.pair()' objects


signed = {
    "m":"hello",
    "s":"aI/PWFd7cpicyND1VO6FQ2+fehyobTv0qntDRJ+GFgQn/RrT381vKJiW6BRhy7Ml/XTbGkX+PKMsf1V3D2l/SQ=="
}

data = {
    "pub": "dcrLDjYBF026W13qEYovv63DeyU2lFq1ZdsrtXq1VxE.R_X_BqcWVTOU0WJkcZUWBkt6VmslSbQsFKfu7b8TKp4",
    "priv": "PxaktJt4YtMxQg_p9B7Ij_W7CrUMiYNbOuhISfaM-ZI",
    "epub": "v7NG8_-r_-7LJhiZEX5tBONau_troH471SWd0Wtut2k.vQeeMMkgLDrbE6Vgz6tSyXrt6tOEHVZFPmlLY0av2xQ",
    "epriv": "OSl6ydfoZTq7qZsC-0KKEmnmB4O4KGwxd3ey7-3FKAw"
}

# base64 URL encoding helpers 

def base64urlencode(arg):
    stripped = arg.split(b"=")[0]
    filtered = stripped.replace(b"+", b"-").replace(b"/", b"_")
    return filtered

def base64urldecode(arg):
    filtered = arg.replace("-", "+").replace("_", "/")
    padded = filtered + "=" * ((len(filtered) * -1) % 4)
    return padded


# ECDSA sign verify

# 1. Decode K
pk = base64urldecode(data["priv"])
pk = base64.b64decode(pk)
k = SigningKey.from_string(pk, curve=NIST256p)

# 2. Generate a public key
pub = k.get_verifying_key().to_string()
x, y = pub[:32], pub[32:]
x = base64urlencode(base64.b64encode(x))
y = base64urlencode(base64.b64encode(y))
print(f"ECDSA Public key:\n\t" + x.decode("utf-8") + "." + y.decode("utf-8") + "\n\t"+data['pub'])

# 3. Check Verification method
x, y = data["pub"].split('.')
vpub = base64.b64decode(base64urldecode(x)) + base64.b64decode(base64urldecode(y)) 
vpub = VerifyingKey.from_string(vpub, curve=NIST256p, hashfunc=sha256)

integrity = sha256(signed['m'].encode('utf-8'))

print(f'Verify signature: {vpub.verify(base64.b64decode(signed["s"]), integrity.digest(), hashfunc=sha256)}')


# ECDH
epriv = base64urldecode(data["epriv"])
epriv = base64.b64decode(epriv)

# 1. Decode k
ecdh = ECDH(curve=NIST256p)
k = ecdh.load_private_key_bytes(epriv)

# 2. Generate public key
epub = k.to_string()
ex, ey = epub[:32], epub[32:]
ex = base64urlencode(base64.b64encode(ex))
ey = base64urlencode(base64.b64encode(ey))
print(f"ECDSA Public key:\n\t" + ex.decode("utf-8") + "." + ey.decode("utf-8") + "\n\t"+data['epub'])
