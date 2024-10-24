import streamlit as st
import base64
import os
from itertools import cycle
import random
import math
from hashlib import sha256

# ========== Caesar Cipher ==========
def caesar_cipher(text, key, mode='encrypt'):
    result = ""
    key = key if mode == 'encrypt' else -key
    for char in text:
        if char.isalpha():
            shifted = (ord(char.lower()) - 97 + key) % 26 + 97
            result += chr(shifted)
        else:
            result += char
    return result


# ========== Vigenere Cipher ==========
def vigenere(text, key, mode='encrypt'):
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    result = list(text)  # Mengubah text menjadi list untuk memudahkan penggantian karakter
    
    alphabet_pos = 0
    
    for i in range(len(text)):
        if text[i].isalpha():
            # Mendapatkan shift berdasarkan karakter key
            # Gunakan alphabet_pos untuk mengtrack posisi key yang sebenarnya
            key_shift = key_as_int[alphabet_pos % key_length] - ord('A')

            is_upper = text[i].isupper()
            char_num = ord(text[i].upper()) - ord('A')
            
            if mode == 'encrypt':
                # Enkripsi: (text + key) mod 26
                value = (char_num + key_shift) % 26
            else:
                # Dekripsi: (text - key + 26) mod 26
                value = (char_num - key_shift + 26) % 26
            
            # Konversi kembali ke karakter dengan mempertahankan case asli
            if is_upper:
                result[i] = chr(value + ord('A'))
            else:
                result[i] = chr(value + ord('a'))
                
            # Increment alphabet_pos hanya ketika memproses huruf
            alphabet_pos += 1
        else:
            # Jika bukan huruf, biarkan karakter tidak berubah
            result[i] = text[i]
    
    # Mengembalikan hasil sebagai string
    return ''.join(result)
    
# ========== Simple RSA Implementation ==========
def is_prime(n, k=5):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0: return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s, d = s+1, d//2
    for i in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1: continue
        for r in range(s-1):
            x = (x * x) % n
            if x == n-1: break
        else: return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        if n % 2 != 0 and is_prime(n):
            return n

def generate_rsa_keys(bits=2048):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def two_to_one(d,n):
    return (d,n)


def rsa_encrypt(message, public_key):
    e, n = public_key
    message_bytes = message.encode()
    message_int = int.from_bytes(message_bytes, 'big')
    if message_int >= n:
        raise ValueError("Message too long for current key size")
    encrypted_int = pow(message_int, e, n)
    return base64.b64encode(encrypted_int.to_bytes((encrypted_int.bit_length() + 7) // 8, 'big')).decode()

def rsa_decrypt(encrypted_message, private_key):
    try:
        d, n = private_key
        encrypted_int = int.from_bytes(base64.b64decode(encrypted_message), 'big')
        decrypted_int = pow(encrypted_int, d, n)
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        return decrypted_bytes.decode()
    except Exception as e:
        return f"Dekripsi gagal: {str(e)}"

# ========== Simple AES Implementation ==========
def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def aes_key_expansion(key):
    # Simplified key expansion for demo purposes
    return sha256(key).digest()

def aes_encrypt(plain_text, key):
    try:
        if isinstance(plain_text, str):
            plain_text = plain_text.encode()
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Expand key using SHA-256
        expanded_key = aes_key_expansion(key)
        
        # Pad the plaintext
        padded_text = pad(plain_text)
        
        # XOR with IV and expanded key for simplification
        encrypted = b''
        prev_block = iv
        for i in range(0, len(padded_text), 16):
            block = padded_text[i:i+16]
            # XOR with previous block (CBC mode) and key
            encrypted_block = bytes(a ^ b ^ c for a, b, c in zip(block, prev_block, cycle(expanded_key)))
            encrypted += encrypted_block
            prev_block = encrypted_block
        
        # Combine IV and ciphertext
        final_encrypted = iv + encrypted
        return base64.b64encode(final_encrypted).decode()
    except Exception as e:
        return f"Enkripsi gagal: {str(e)}"

def aes_decrypt(encrypted_text, key):
    try:
        # Decode base64
        encrypted_data = base64.b64decode(encrypted_text)
        
        # Split IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Expand key using SHA-256
        expanded_key = aes_key_expansion(key)
        
        # Decrypt
        decrypted = b''
        prev_block = iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            # XOR with previous block (CBC mode) and key
            decrypted_block = bytes(a ^ b ^ c for a, b, c in zip(block, prev_block, cycle(expanded_key)))
            decrypted += decrypted_block
            prev_block = block
        
        # Unpad
        unpadded = unpad(decrypted)
        return unpadded.decode()
    except Exception as e:
        return f"Dekripsi gagal: {str(e)}"

# ========== Streamlit UI ==========
st.title("Aplikasi Kriptografi")

# Initialize session state for RSA keys
if 'public_key' not in st.session_state or 'private_key' not in st.session_state:
    st.session_state.public_key, st.session_state.private_key = generate_rsa_keys()

# Initialize session state for AES key
if 'aes_key' not in st.session_state:
    st.session_state.aes_key = os.urandom(32)

menu = st.sidebar.selectbox("Pilih Metode", ["Caesar Cipher", "Vigenere", "RSA", "AES","Super Enkripsi"])

if menu == "Caesar Cipher":
    st.header("Caesar Cipher")
    text = st.text_input("Masukkan Teks")
    key = st.number_input("Masukkan Key", min_value=1, max_value=25, step=1)
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if st.button("Proses"):
        result = caesar_cipher(text, key, mode.lower())
        st.write(f"Hasil: {result}")

elif menu == "Vigenere":
    st.header("Vigenere Cipher")
    text = st.text_input("Masukkan Teks")
    key = st.text_input("Masukkan Key")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if st.button("Proses"):
        if key and text:  # Memastikan input tidak kosong
            result = vigenere(text, key, mode.lower())
            st.success(f"Hasil: {result}")
        else:
            st.error("Mohon isi teks dan key terlebih dahulu")


elif menu == "RSA":
    st.header("RSA Cipher")
    st.write("Public Key (e, n):", st.session_state.public_key)
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        text = st.text_input("Masukkan Teks")
        if st.button("Enkripsi"):
            try:
                result = rsa_encrypt(text, st.session_state.public_key)
                st.write(f"Hasil Enkripsi: {result}")
                st.write(f"Private Key (d,n) : {st.session_state.private_key}")
            except ValueError as e:
                st.error(str(e))

    else:
        encrypted_text = st.text_input("Masukkan Teks Terenkripsi")
        keyd = st.number_input("Masukkan Private key(d)",value=None)
        keyn = st.number_input("Masukkan Private key(n)",value=None)
        if st.button("Dekripsi"):
            key = two_to_one(keyd,keyn)
            result = rsa_decrypt(encrypted_text,key)
            st.write(f"Hasil Dekripsi: {result}")

elif menu == "AES":
    st.header("AES Cipher")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        text = st.text_input("Masukkan Teks")
        if st.button("Enkripsi"):
            result = aes_encrypt(text, st.session_state.aes_key)
            st.write(f"Hasil Enkripsi: {result}")
            st.write(f"Kunci (hex): {st.session_state.aes_key.hex()}")
            st.info("Simpan kunci ini untuk dekripsi!")

    else:
        encrypted_text = st.text_input("Masukkan Teks Terenkripsi")
        key_hex = st.text_input("Masukkan Kunci (hex)")
        if st.button("Dekripsi"):
            try:
                key = bytes.fromhex(key_hex)
                result = aes_decrypt(encrypted_text, key)
                st.write(f"Hasil Dekripsi: {result}")
            except ValueError:
                st.error("Format kunci tidak valid!")

elif menu == "Super Enkripsi":
    st.header("Super Enkripsi Caesar dan Vigenere")
    text = st.text_input("Masukkan Teks")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
