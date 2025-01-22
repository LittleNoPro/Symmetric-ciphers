def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, n):
    i, j = 0, 0
    key = []
    while n > 0:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key.append(S[(S[i] + S[j]) % 256])
        n -= 1
    return key

def RC4(key, plaintext):
    S = KSA(key)
    keystream = PRGA(S, len(plaintext))
    ciphertext = [chr(ord(plaintext[i]) ^ keystream[i]) for i in range(len(plaintext))]
    return ''.join(ciphertext)
