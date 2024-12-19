from Crypto.Util.number import *
from pwn import *
import json
from tqdm import *

conn = remote("socket.cryptohack.org", 13421, level="debug")
conn.recvline()

encrypt = {"option": "encrypt"}
conn.send(json.dumps(encrypt))
ct = bytes.fromhex(json.loads(conn.recvline())["ct"])
iv, ct = ct[:16], ct[16:]

def check_padding(iv, ct):
    check = {"option": "unpad", "ct": (iv+ct).hex()}
    conn.send(json.dumps(check))
    return json.loads(conn.recvline())["result"]

def attack_block(iv, ct):
    r = b""
    for i in reversed(range(16)):
        s = bytes([16 - i] * (16 - i))
        for ch in trange(256):
            iv_ = bytes(i) + xor(s, bytes([ch]) + r)
            if check_padding(iv_, ct):
                r = bytes([ch]) + r
                break

    return xor(iv, r)

def attack(iv, ct):
    pt = attack_block(iv, ct[:16])
    for i in range(16, len(ct), 16):
        pt += attack_block(ct[i - 16:i], ct[i:i + 16])
    return pt

msg = attack(iv, ct)
print(f"message: {msg}")
check = {"option": "check", "message": msg.decode()}
conn.send(json.dumps(check))
data = json.loads(conn.recvline())
print(data['flag'])

# Flag: crypto{if_you_ask_enough_times_you_usually_get_what_you_want}