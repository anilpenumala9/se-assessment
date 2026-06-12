import base64
from Crypto.Cipher import ChaCha20

# 1. Update this with the ETag of the file you are testing
ETAG = "bd023ce37fb05e1d7f472c81374d8c7fccbec45695b54bea0d9189405f391798"
# 2. Update this with the raw base64 string from that specific record
B64_DATA = "{bèÓc’\´6…$ÈÁeY³iK	Þ( í„Q…Ô’UQ<NŒ^R¡)T5{‚Ùr™"¨-^&*0GÆ¼²5jpÒó‡¯’‘½Œl _Þ°×Ôéâ¸=çP\t ŽÍ—dTIJúiµÔˆ„^àèN8tœ¨ïÃ©-ÄY¿YæŠ-ëåyÑ¦¢Ýÿm¡›1&ÅqûÞ·G/D£¶@%Fž1øúçP­g¬ øVÆîõàb	vDEWiù}Fœ˜÷ôØ€•Ú¸r¢ýî`¿UB´»â1fùQä¤-¨lìhd¦’¶!†y.
Ì°Ð3á®ØgE[<¦Wñ†±x/«÷q´ <èC"

def test_nonces():
    key = bytes.fromhex(ETAG)
    ciphertext = base64.b64decode(B64_DATA)
    
    # We test 5 common ways developers derive the Nonce
    # Counter is usually the record index
    counter = 19 # The record number in your file name
    
    strategies = {
        "1. First 12 bytes of ETag": key[:12],
        "2. Counter (padded to 12 bytes)": counter.to_bytes(12, 'big'),
        "3. ETag[:8] + Counter(BigEndian)": key[:8] + counter.to_bytes(4, 'big'),
        "4. Counter(LittleEndian) + ETag[4:12]": counter.to_bytes(4, 'little') + key[4:12],
        "5. ETag[:4] + Counter(BigEndian) + ETag[8:12]": key[:4] + counter.to_bytes(4, 'big') + key[8:12]
    }
    
    for name, nonce in strategies.items():
        try:
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
            # We look for the start of a JSON file
            if decrypted.startswith(b'{') or decrypted.startswith(b'['):
                print(f"🎉 FOUND SUCCESSFUL NONCE STRATEGY: {name}")
                print(f"Content Preview: {decrypted[:100]}")
                return
        except Exception:
            continue
    print("❌ None of these strategies worked.")

test_nonces()