import struct

# Constants for SHA-512
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]

# Initial hash values for SHA-512/224
H = [
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1
]

def rotate_right(value, bits, size=64):
    """Rotate right operation."""
    return ((value >> bits) | (value << (size - bits))) & ((1 << size) - 1)

def sha512_224(message):
    """Implements SHA-512/224."""
    if isinstance(message, str):
        message = message.encode()

    # Preprocessing: Padding the message
    message_len = len(message) * 8
    message += b'\x80'
    while (len(message) * 8 + 64) % 1024 != 0:
        message += b'\x00'
    message += struct.pack('>Q', message_len)

    # Process the message in 1024-bit chunks
    chunks = [message[i:i + 128] for i in range(0, len(message), 128)]
    hash_values = H[:]

    for chunk in chunks:
        W = list(struct.unpack('>16Q', chunk))
        for i in range(16, 80):
            s0 = rotate_right(W[i-15], 1) ^ rotate_right(W[i-15], 8) ^ (W[i-15] >> 7)
            s1 = rotate_right(W[i-2], 19) ^ rotate_right(W[i-2], 61) ^ (W[i-2] >> 6)
            W.append((W[i-16] + s0 + W[i-7] + s1) & ((1 << 64) - 1))

        a, b, c, d, e, f, g, h = hash_values

        for i in range(80):
            S1 = rotate_right(e, 14) ^ rotate_right(e, 18) ^ rotate_right(e, 41)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & ((1 << 64) - 1)
            S0 = rotate_right(a, 28) ^ rotate_right(a, 34) ^ rotate_right(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & ((1 << 64) - 1)

            h = g
            g = f
            f = e
            e = (d + temp1) & ((1 << 64) - 1)
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & ((1 << 64) - 1)

        hash_values = [
            (hash_values[0] + a) & ((1 << 64) - 1),
            (hash_values[1] + b) & ((1 << 64) - 1),
            (hash_values[2] + c) & ((1 << 64) - 1),
            (hash_values[3] + d) & ((1 << 64) - 1),
            (hash_values[4] + e) & ((1 << 64) - 1),
            (hash_values[5] + f) & ((1 << 64) - 1),
            (hash_values[6] + g) & ((1 << 64) - 1),
            (hash_values[7] + h) & ((1 << 64) - 1)
        ]

    # Combine the first seven hash values for SHA-512/224
    final_hash = ''.join(f'{x:016x}' for x in hash_values[:7])
    return final_hash[:56]
    
#Demo 
if __name__ == "__main__":
    data=input("enter the value to hash: ")
    hash_result = sha512_224(data)
    print("SHA-512/224:", hash_result)
