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