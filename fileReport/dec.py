import time


MASK32 = 0xffffffff


class Lrand48:
    def __init__(self, seed):
        self.a = 0x5DEECE66D
        self.c = 0xB
        self.m = 1 << 48
        self.state = ((seed & 0xffffffff) << 16) | 0x330E

    def lrand48(self):
        self.state = (self.state * self.a + self.c) & (self.m - 1)
        return self.state >> 17


class XTEACBC:
    BLOCK_SIZE = 8
    DELTA = 1640531527

    def __init__(self, key_bytes: bytes, endian: str = 'little'):
        if len(key_bytes) != 16:
            raise ValueError("Key must be 16 bytes!")
        self.key = self._prepare_key(key_bytes, endian)
        self.key_bytes = key_bytes
        self.endian = endian

    @staticmethod
    def _prepare_key(key_bytes: bytes, endian: str = 'little'):
        return [int.from_bytes(key_bytes[i*4:(i+1)*4], endian) for i in range(4)]

    @staticmethod
    def _add32(a, b):
        return (a + b) & MASK32

    @staticmethod
    def _sub32(a, b):
        return (a - b) & MASK32

    @staticmethod
    def _xtea_decrypt_block_custom(v0: int, v1: int, key: list, rounds: int = 32, c: int = 1640531527):
        s = (-957401312) & MASK32
        for _ in range(rounds):
            t = (v0 + ((16 * v0) ^ (v0 >> 5))) & MASK32
            idx0 = ((s >> 9) & 0xC) >> 2
            part0 = (s + key[idx0]) & MASK32
            v1 = XTEACBC._sub32(v1, t ^ part0)
            t2 = (v1 + ((16 * v1) ^ (v1 >> 5))) & MASK32
            idx1 = (((s & 0xff) + 71) & 3)
            part1 = (s + key[idx1] + c) & MASK32
            v0 = XTEACBC._sub32(v0, t2 ^ part1)
            s = XTEACBC._add32(s, c)
        return v0, v1

    @staticmethod
    def _bytes_to_block(b: bytes):
        if len(b) != 8:
            raise ValueError("Block must be 8 bytes!")
        w0 = int.from_bytes(b[0:4], 'little')
        w1 = int.from_bytes(b[4:8], 'little')
        return (w0, w1)

    @staticmethod
    def _block_to_bytes(block: tuple):
        return block[0].to_bytes(4, 'little') + block[1].to_bytes(4, 'little')

    @staticmethod
    def remove_padding(data: bytes, block_size: int = 8):
        if not data:
            raise ValueError("Data is empty!")
        pad = data[-1]
        if pad < 1 or pad > block_size:
            raise ValueError(f"Invalid padding value: {pad}")
        if data[-pad:] != bytes([pad] * pad):
            raise ValueError("Invalid padding!")
        return data[:-pad]

    def crypt_xtea_cbc_decrypt(self, ciphertext: bytes, endian='little') -> bytes:
        if len(ciphertext) % self.BLOCK_SIZE != 0 or len(ciphertext) < self.BLOCK_SIZE:
            raise ValueError("Ciphertext length invalid!")
        nblocks = len(ciphertext) // self.BLOCK_SIZE
        blocks = [self._bytes_to_block(
            ciphertext[i * self.BLOCK_SIZE:(i + 1) * self.BLOCK_SIZE]) for i in range(nblocks)]
        iv = blocks[0]
        decrypted = b""
        prev = iv
        for block in blocks[1:]:
            v0, v1 = block
            d0, d1 = self._xtea_decrypt_block_custom(
                v0, v1, self.key, rounds=32, c=self.DELTA)
            prev0, prev1 = prev
            p0 = d0 ^ prev0
            p1 = d1 ^ prev1
            decrypted += p0.to_bytes(4, 'little') + p1.to_bytes(4, 'little')
            prev = block
        output_len = len(ciphertext) - 16
        raw = decrypted[:output_len]
        return self.remove_padding(raw, self.BLOCK_SIZE)

    def crypt_xtea_cbc_encrypt(self, plaintext: bytes) -> bytes:
        v46 = len(plaintext)
        full_blocks = v46 >> 3
        v52 = 8 * full_blocks
        v48 = full_blocks
        out_size = v52 + 24
        out_dwords = [0] * (out_size // 4)
        rng = Lrand48(int(time.time()))
        v4 = rng.lrand48() & 0xffffffff
        v5 = rng.lrand48() & 0xffffffff
        v6 = v4 | (v5 >> 31)
        v8 = 0
        delta = 0x61C88647
        rounds = 32
        v49 = v6
        v50 = v5
        for _ in range(rounds):
            temp1 = (v6 + ((16 * v6) ^ (v6 >> 5))) & 0xffffffff
            k1 = int.from_bytes(
                self.key_bytes[((v8 & 3) * 4):((v8 & 3) * 4 + 4)], 'little')
            temp2 = (v8 + k1) & 0xffffffff
            v5 = (v5 + (temp1 ^ temp2)) & 0xffffffff
            temp1 = (v5 + ((16 * v5) ^ (v5 >> 5))) & 0xffffffff
            second_index = (((v8 - delta) >> 9) & 0xC) >> 2
            k2 = int.from_bytes(
                self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
            temp2 = (v8 + k2) & 0xffffffff
            temp2 = (temp2 - delta) & 0xffffffff
            v6 = (v6 + (temp1 ^ temp2)) & 0xffffffff
            v8 = (v8 - delta) & 0xffffffff
        out_dwords[0] = v5
        out_dwords[1] = v6
        pos = 0
        out_index = 2
        for i in range(v48):
            p0 = int.from_bytes(plaintext[pos:pos+4], 'little')
            p1 = int.from_bytes(plaintext[pos+4:pos+8], 'little')
            pos += 8
            combined = ((p1 & 0xffffffff) << 32) | (p0 & 0xffffffff)
            old_pair = ((v49 & 0xffffffff) << 32) | (v50 & 0xffffffff)
            total = (combined + old_pair) & 0xffffffffffffffff
            v49 = (total >> 32) & 0xffffffff
            v50 = (v50 + p0) & 0xffffffff
            v6 = v6 ^ p1
            v16 = p0 ^ v5
            v17 = 0
            for j in range(32):
                temp1 = (v6 + ((16 * v6) ^ (v6 >> 5))) & 0xffffffff
                k1 = int.from_bytes(
                    self.key_bytes[((v17 & 3) * 4):((v17 & 3) * 4 + 4)], 'little')
                temp2 = (v17 + k1) & 0xffffffff
                v16 = (v16 + (temp1 ^ temp2)) & 0xffffffff
                temp1 = (v16 + ((16 * v16) ^ (v16 >> 5))) & 0xffffffff
                second_index = (((v17 - delta) >> 9) & 0xC) >> 2
                k2 = int.from_bytes(
                    self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
                temp2 = (v17 + k2) & 0xffffffff
                temp2 = (temp2 - delta) & 0xffffffff
                v6 = (v6 + (temp1 ^ temp2)) & 0xffffffff
                v17 = (v17 - delta) & 0xffffffff
            v5 = v16
            out_dwords[out_index] = v16
            out_dwords[out_index + 1] = v6
            out_index += 2
        rem = v46 & 7
        if rem != 0:
            tmp = bytearray(8)
            tmp[0:rem] = plaintext[pos:pos+rem]
        else:
            tmp = bytearray(8)
        pad_val = (8 - rem) if rem != 0 else 8
        for i in range(8 - rem):
            tmp[rem + i] = pad_val
        v53 = int.from_bytes(tmp, 'little')
        v26 = (v53 & 0xffffffff) ^ v5
        v27 = ((v53 >> 32) & 0xffffffff) ^ v6
        v28 = 0
        for i in range(32):
            temp1 = (v27 + ((16 * v27) ^ (v27 >> 5))) & 0xffffffff
            k1 = int.from_bytes(
                self.key_bytes[((v28 & 3) * 4):((v28 & 3) * 4 + 4)], 'little')
            temp2 = (v28 + k1) & 0xffffffff
            v26 = (v26 + (temp1 ^ temp2)) & 0xffffffff

            temp1 = (v26 + ((16 * v26) ^ (v26 >> 5))) & 0xffffffff
            second_index = (((v28 - delta) >> 9) & 0xC) >> 2
            k2 = int.from_bytes(
                self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
            temp2 = (v28 + k2) & 0xffffffff
            temp2 = (temp2 - delta) & 0xffffffff
            v27 = (v27 + (temp1 ^ temp2)) & 0xffffffff

            v28 = (v28 - delta) & 0xffffffff
        out_dwords[out_index] = v26
        out_dwords[out_index + 1] = v27
        out_index += 2
        combined_pair = ((v49 & 0xffffffff) << 32) | (v50 & 0xffffffff)
        total_64 = (combined_pair + v53) & 0xffffffffffffffff
        v30 = (total_64 >> 32) & 0xffffffff
        v31 = (v50 + (v53 & 0xffffffff)) & 0xffffffff
        v32 = v26 ^ v31
        v33 = v27 ^ v30
        v34 = 0
        for i in range(32):
            temp1 = (v33 + ((16 * v33) ^ (v33 >> 5))) & 0xffffffff
            k1 = int.from_bytes(
                self.key_bytes[((v34 & 3) * 4):((v34 & 3) * 4 + 4)], 'little')
            temp2 = (v34 + k1) & 0xffffffff
            v32 = (v32 + (temp1 ^ temp2)) & 0xffffffff
            temp1 = (v32 + ((16 * v32) ^ (v32 >> 5))) & 0xffffffff
            second_index = (((v34 - delta) >> 9) & 0xC) >> 2
            k2 = int.from_bytes(
                self.key_bytes[(second_index * 4):(second_index * 4 + 4)], 'little')
            temp2 = (v34 + k2) & 0xffffffff
            temp2 = (temp2 - delta) & 0xffffffff
            v33 = (v33 + (temp1 ^ temp2)) & 0xffffffff
            v34 = (v34 - delta) & 0xffffffff
        out_dwords[out_index] = v32
        out_dwords[out_index + 1] = v33
        out_index += 2
        result = b"".join(dw.to_bytes(4, 'little') for dw in out_dwords)
        return result


if __name__ == '__main__':
    key_bytes = bytes.fromhex("2c1950ab80093a377e991eb6a3e14db7")
    xtea_cbc = XTEACBC(key_bytes)
    ciphertext = bytes.fromhex(
        "35251d7889dfdf611d29b4fb900bf58e1590d2fe481174c21b2058094f1ea4e62a6e16c75180d4764e473735bfa0dfe019c24e85c46458461aeae5f5c58f0f47")
    plaintext = xtea_cbc.crypt_xtea_cbc_decrypt(ciphertext)
    print(plaintext.hex())
    print(plaintext)