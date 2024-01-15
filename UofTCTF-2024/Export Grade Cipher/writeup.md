# UofTCTF 2024 Export Grade Cipher Writeup

![image](https://hackmd.io/_uploads/rkFYP5fK6.png)

This crypto challenge is a custom cipher, so we can't really rely on any known attacks. It doesn't require many complex math but the difficulty lies on being able to extract any useful information from this chosen-plaintext attack

## TL;DR

In the update function, if we supply `v` such that `v == i`, the S-box will not change and consecutive characters will have the same output. We can use this to recover `i`, which is just the xor of the two LFSR state, bruteforce LFSR17 to get the LFSR32 state, and unshift them to recover the key.

---

We are given a source code and a module, this is what `chal.py` looks like

```python=
import ast
import threading
from exportcipher import *
try:
    from flag import FLAG
except:
    FLAG = "test{FLAG}"

MAX_COUNT = 100
TIMEOUT = 120 # seconds

def input_bytes(display_msg):
    m = input(display_msg)
    try:
        m = ast.literal_eval(m)
    except:
        # might not be valid str or bytes literal but could still be valid input, so just encode it
        pass
    if isinstance(m, str):
        m = m.encode()
    assert isinstance(m, bytes)
    return m

def timeout_handler():
    print("Time is up, you can throw out your work as the key changed.")
    exit()

if __name__ == "__main__":
    print("Initializing Export Grade Cipher...")
    key = int.from_bytes(os.urandom(5))
    cipher = ExportGradeCipher(key)
    print("You may choose up to {} plaintext messages to encrypt.".format(MAX_COUNT))
    print("Recover the 40-bit key to get the flag.")
    print("You have {} seconds.".format(TIMEOUT))
    # enough time to crack a 40 bit key with the compute resources of a government
    threading.Timer(TIMEOUT, timeout_handler).start()
    
    i = 0
    while i < MAX_COUNT:
        pt = input_bytes("[MSG {}] plaintext: ".format(i))
        if not pt:
            break
        if len(pt) > 512:
            # don't allow excessively long messages
            print("Message Too Long!")
            continue
        nonce = os.urandom(256)
        cipher.init_with_nonce(nonce)
        ct = cipher.encrypt(pt)
        print("[MSG {}] nonce: {}".format(i, nonce))
        print("[MSG {}] ciphertext: {}".format(i, ct))
        # sanity check decryption
        cipher.init_with_nonce(nonce)
        assert pt == cipher.decrypt(ct)
        i += 1
    recovered_key = ast.literal_eval(input("Recovered Key: "))
    assert isinstance(recovered_key, int)
    if recovered_key == key:
        print("That is the key! Here is the flag: {}".format(FLAG))
    else:
        print("Wrong!")
```

So here we can encrypt 100 ciphertext using ExportGradeCipher each with different nonce, and then we have to guess the 40 bit key.

So how does ExportGradeCipher work?

```python=
import os

class LFSR:
    def __init__(self, seed, taps, size):
        assert seed != 0
        assert (seed >> size) == 0
        assert len(taps) > 0 and (size - 1) in taps
        self.state = seed
        self.taps = taps
        self.mask = (1 << size) - 1

    def _shift(self):
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        self.state = ((self.state << 1) | feedback) & self.mask
    
    def next_byte(self):
        val = self.state & 0xFF
        for _ in range(8):
            self._shift()
        return val


class ExportGradeCipher:
    def __init__(self, key):
        # 40 bit key
        assert (key >> 40) == 0
        self.key = key
        self.initialized = False
    
    def init_with_nonce(self, nonce):
        # 256 byte nonce, nonce size isnt export controlled so hopefully this will compensate for the short key size
        assert len(nonce) == 256
        self.lfsr17 = LFSR((self.key & 0xFFFF) | (1 << 16), [2, 9, 10, 11, 14, 16], 17)
        self.lfsr32 = LFSR(((self.key >> 16) | 0xAB << 24) & 0xFFFFFFFF, [1, 6, 16, 21, 23, 24, 25, 26, 30, 31], 32)
        self.S = [i for i in range(256)]
        # Fisher-Yates shuffle S-table
        for i in range(255, 0, -1): 
            # generate j s.t. 0 <= j <= i, has modulo bias but good luck exploiting that
            j = (self.lfsr17.next_byte() ^ self.lfsr32.next_byte()) % (i + 1)
            self.S[i], self.S[j] = self.S[j], self.S[i]
        j = 0
        # use nonce to scramble S-table some more
        for i in range(256):
            j = (j + self.lfsr17.next_byte() ^ self.lfsr32.next_byte() + self.S[i] + nonce[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.S_inv = [0 for _ in range(256)]
        for i in range(256):
            self.S_inv[self.S[i]] = i
        self.initialized = True
    
    def _update(self, v):
        i = self.lfsr17.next_byte() ^ self.lfsr32.next_byte()
        self.S[v], self.S[i] = self.S[i], self.S[v]
        self.S_inv[self.S[v]] = v
        self.S_inv[self.S[i]] = i
    
    def encrypt(self, msg):
        assert self.initialized
        ct = bytes()
        for v in msg:
            ct += self.S[v].to_bytes()
            self._update(v)
        return ct
    
    def decrypt(self, ct):
        assert self.initialized
        msg = bytes()
        for v in ct:
            vo = self.S_inv[v]
            msg += vo.to_bytes()
            self._update(vo)
        return msg


if __name__ == "__main__":
    cipher = ExportGradeCipher(int.from_bytes(os.urandom(5)))
    nonce = os.urandom(256)
    print("="*50)
    print("Cipher Key: {}".format(cipher.key))
    print("Nonce: {}".format(nonce))
    msg = "ChatGPT: The Kerckhoffs' Principle, formulated by Auguste Kerckhoffs in the 19th century, is a fundamental concept in cryptography that states that the security of a cryptographic system should not rely on the secrecy of the algorithm, but rather on the secrecy of the key. In other words, a cryptosystem should remain secure even if all the details of the encryption algorithm, except for the key, are publicly known. This principle emphasizes the importance of key management in ensuring the confidentiality and integrity of encrypted data and promotes the development of encryption algorithms that can be openly analyzed and tested by the cryptographic community, making them more robust and trustworthy."
    print("="*50)
    print("Plaintext: {}".format(msg))
    cipher.init_with_nonce(nonce)
    ct = cipher.encrypt(msg.encode())
    print("="*50)
    print("Ciphertext: {}".format(ct))
    cipher.init_with_nonce(nonce)
    dec = cipher.decrypt(ct)
    print("="*50)
    try:
        print("Decrypted: {}".format(dec))
        assert msg.encode() == dec
    except:
        print("Decryption failed") 
```

Essentially it generates a very scrambled S-box using the key and nonce, and then do substitution to the plaintext. But to add more confusion we update the S-box for every character that we substitute.

So how do we approach this problem, we can start by analyzing some possible simple attack first

## Bruteforce?

As noted by the comments as well, it seems very unlikely to bruteforce the whole 40 bit key in reasonable time. However, do take a look at how the key is actually used

```python
self.lfsr17 = LFSR((self.key & 0xFFFF) | (1 << 16), [2, 9, 10, 11, 14, 16], 17)
self.lfsr32 = LFSR(((self.key >> 16) | 0xAB << 24) & 0xFFFFFFFF, [1, 6, 16, 21, 23, 24, 25, 26, 30, 31], 32)
```

So it breaks the key into 2 parts, the last 16 bits is used for LFSR17, and the other 24 bits is used for LFSR32

This means that although we can't bruteforce the entire key, we might be able to just bruteforce the LFSR17 which is 16 bits of the key in case we need it. This observation alone will not lead us to the solution but it will be used later.

The other thing that we might need to note is that everything here operates using this LFSR, in LFSR we can shift and also unshift the state. This means that if we recover any state of the LSFR, we can unshift them back to the original key

## Recovering LFSR State

So the idea is getting clearer, we want to extract the state of the LFSR, preferably LFSR32 since as we discuss previously we can just perform bruteforcing to find LFSR17

We can analyze this very confusing S-box generating function and we can probably found some crazy relation with the LFSR state maybe?
There is just one problem: ITS WAY TOO SCRAMBLY

Let's just cross the init_with_nonce out and suppose it's secure, there is only one place left where the LFSR is actually used, the \_update() function

### \_update()

We know how the encryption works, it substitutes the plaintext using the generated S-box and then update the S-box by swapping the value for the current character with another number produced by the LFSR

```python
def _update(self, v):
    i = self.lfsr17.next_byte() ^ self.lfsr32.next_byte()
    self.S[v], self.S[i] = self.S[i], self.S[v]
    self.S_inv[self.S[v]] = v
    self.S_inv[self.S[i]] = i

def encrypt(self, msg):
    assert self.initialized
    ct = bytes()
    for v in msg:
        ct += self.S[v].to_bytes()
        self._update(v)
    return ct
```

This is interesting because it makes it such that the same consecutive characters will have different values.

You can try it yourself, it will gives different values for each consecutive characters

![image](https://hackmd.io/_uploads/rylyNsfY6.png)

But do take a look at the code again, what _if_ v is equal to i?

```python
def _update(self, v):
    i = self.lfsr17.next_byte() ^ self.lfsr32.next_byte()
    self.S[v], self.S[i] = self.S[i], self.S[v]
    self.S_inv[self.S[v]] = v
    self.S_inv[self.S[i]] = i
```

if v == i, then the S-box will not change, thus the consecutive characters WILL HAVE THE SAME VALUE

Let's try to check the i value and give inputs that matches it. I updated the script and also doesn't print the nonce for debug purposes
```python
def _update(self, v):
    i = self.lfsr17.next_byte() ^ self.lfsr32.next_byte()
    print(f"{hex(i) = }")
    self.S[v], self.S[i] = self.S[i], self.S[v]
    self.S_inv[self.S[v]] = v
    self.S_inv[self.S[i]] = i
```

![image](https://hackmd.io/_uploads/ByRVLjGt6.png)

So we are right, we can now extract i by trying all to input a consecutive value.

This works for any index too

![image](https://hackmd.io/_uploads/rJA2LoGKa.png)

## Putting it all together

We know `i` is just xor of the 2 states of the LFSR, and we can bruteforce for LFSR17, so in order to get the full state of LFSR32, we need 4 consecutive `i` (each `i` is 1 byte and LFSR32 is 4 bytes), because we can only do 100 plaintext, it's not guaranteed, but the length limit is not bad (512 bytes) we have a very decent chance that at least 4 consecutive `i` between the 512 have the value below 100

After recovering a 4 consecutive i value, we can bruteforce all LFSR17, got the state of LFSR32, and unshift them enough to get the original key

It needs a little bit of calculation but basically the `init_with_nonce` function do 511 `next_byte` per LFSR so its 4088 shift, we also need to add the the starting point from the 512 bytes that we encrypt

4088 shift is a lot of work even to bruteforce the LFSR17 so I reccomend to do a precalculation before connecting to the remote server.


full solver:
```python
from wrth import *
from tqdm import tqdm
class LFSR:
    def __init__(self, seed, taps, size):
        assert seed != 0
        assert (seed >> size) == 0
        assert len(taps) > 0 and (size - 1) in taps
        self.state = seed
        self.taps = taps
        self.mask = (1 << size) - 1
        self.size = size

    def _shift(self):
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        self.state = ((self.state << 1) | feedback) & self.mask
    
    def _unshift(self):
        feedback = self.state & 1
        self.state >>= 1
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        self.state |= feedback << (self.size-1)

    def next_byte(self):
        val = self.state & 0xFF
        for _ in range(8):
            self._shift()
        return val

lfsr17precalc = []
print("precalc")
for i in tqdm(range(2**16)):
    lfsr17 = LFSR((i & 0xFFFF) | (1 << 16), [2, 9, 10, 11, 14, 16], 17)
    for _ in range(4088):
        lfsr17._shift()
    lfsr17precalc.append(lfsr17)

r = con("nc 0.cloud.chals.io 23753")
def recover_i():
    res = [-1]*512
    print("generating ciphertext...")
    for i in tqdm(range(100)):
        secret = []
        test = bytes([i]*512)
        r.sendlineafter(b"plaintext: ", str(test))
        r.recvuntil(b"nonce: ")
        nonce = r.recvline()
        r.recvuntil(b"ciphertext: ")
        ct = eval(r.recvline())
        for j in range(512-4):
            if ct[j] == ct[j+1]:
                res[j] = i
                break

    starting = -1
    for i in range(len(res)):
        if res[i] != -1 and res[i+1] != -1 and res[i+2] != -1 and res[i+3] != -1:
            starting = i
            break

    if starting == -1:
        print("run again")
        exit()

    print(f"{starting = }")
    recovered = res[starting:starting+4]
    print(f"{recovered = }")
    
    return starting, recovered, res

starting, recovered, res = recover_i()

shiftamount = 4088 + (starting)*8
for keylsb in tqdm(range(2**16)):
    lfsr32state = []
    lfsr17 = lfsr17precalc[keylsb]
    for _ in range(starting*8):
        lfsr17._shift()
    for i in range(4):
        lfsr32state.append(lfsr17.next_byte() ^ recovered[i])
    lfsr32state = int.from_bytes(bytes(lfsr32state))
    lfsr32 = LFSR(lfsr32state, [1, 6, 16, 21, 23, 24, 25, 26, 30, 31], 32)
    good = True
    for i in range(4*8):
        lfsr17._unshift()
    for i in range(3*8):
        lfsr32._unshift()
    for i in range(starting, len(res)):
        byte17 = lfsr17.next_byte()
        byte32 = lfsr32.next_byte()
        if res[i] != -1:
            if byte17 ^ byte32 != res[i]:
                good = False
                break
    if good:
        for i in range(starting, len(res)):
            for j in range(8):
                lfsr32._unshift()

        for i in range(shiftamount):
            lfsr32._unshift()

        keymsb = (lfsr32.state & 2**24 - 1)
        print(keymsb)
        print(keylsb)
        key = (keymsb << 16) + keylsb
        print(key)
        r.sendlineafter(b"Key: ",str(key))
        r.interactive()
```

Flag: uoftctf{wH0_w0u1D_h4ve_7houGHt_l0ng_nONceS_CAnt_S4ve_w3ak_KeYS}