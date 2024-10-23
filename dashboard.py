import streamlit as st
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Fungsi Caesar Cipher
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

# Fungsi Rail Fence Cipher
def rail_fence(text, key, mode='encrypt'):
    if mode == 'encrypt':
        rail = [['\n' for _ in range(len(text))] for _ in range(key)]
        direction_down, row, col = False, 0, 0

        for char in text:
            if row == 0 or row == key - 1:
                direction_down = not direction_down
            rail[row][col] = char
            col += 1
            row += 1 if direction_down else -1

        return ''.join([rail[i][j] for i in range(key) for j in range(len(text)) if rail[i][j] != '\n'])

    else:  # dekripsi
        rail = [['\n' for _ in range(len(text))] for _ in range(key)]
        direction_down, row, col = None, 0, 0

        for i in range(len(text)):
            if row == 0:
                direction_down = True
            if row == key - 1:
                direction_down = False
            rail[row][col] = '*'
            col += 1
            row += 1 if direction_down else -1

        index = 0
        for i in range(key):
            for j in range(len(text)):
                if rail[i][j] == '*' and index < len(text):
                    rail[i][j] = text[index]
                    index += 1

        result = []
        row, col = 0, 0
        for i in range(len(text)):
            if row == 0:
                direction_down = True
            if row == key - 1:
                direction_down = False
            if rail[row][col] != '\n':
                result.append(rail[row][col])
            col += 1
            row += 1 if direction_down else -1

        return ''.join(result)

# Fungsi AES Cipher
def aes_encrypt(plain_text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(encrypted_text, key):
    encrypted_data = base64.b64decode(encrypted_text)
    iv, encrypted_message = encrypted_data[:16], encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize().decode()

# Fungsi RSA Cipher
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(plain_text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(plain_text.encode())).decode()

def rsa_decrypt(encrypted_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(encrypted_text)).decode()

# Streamlit UI
st.title("Kriptografi Kelompok Wlewle")

menu = st.sidebar.selectbox("Pilih Metode", ["Caesar Cipher", "Rail Fence", "AES", "RSA"])

if menu == "Caesar Cipher":
    st.header("Caesar Cipher")
    text = st.text_input("Masukkan Teks")
    key = st.number_input("Masukkan Key", min_value=1, max_value=25, step=1)
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if st.button("Proses"):
        result = caesar_cipher(text, key, mode.lower())
        st.write(f"Hasil: {result}")

elif menu == "Rail Fence":
    st.header("Rail Fence Cipher")
    text = st.text_input("Masukkan Teks")
    key = st.number_input("Masukkan Key", min_value=2, step=1)
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if st.button("Proses"):
        result = rail_fence(text, key, mode.lower())
        st.write(f"Hasil: {result}")

elif menu == "AES":
    st.header("AES Cipher")
    key = os.urandom(32)  # Kunci AES 256-bit
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        text = st.text_input("Masukkan Teks")
        if st.button("Proses"):
            result = aes_encrypt(text, key)
            st.write(f"Hasil Enkripsi: {result}")
            st.write(f"Kunci (hex): {key.hex()}")

    else:
        encrypted_text = st.text_input("Masukkan Teks Terenkripsi")
        key_hex = st.text_input("Masukkan Kunci (hex)")
        if st.button("Proses"):
            key = bytes.fromhex(key_hex)
            result = aes_decrypt(encrypted_text, key)
            st.write(f"Hasil Dekripsi: {result}")

elif menu == "RSA":
    st.header("RSA Cipher")
    private_key, public_key = generate_rsa_keys()
    st.text_area("Kunci Publik", public_key.decode())
    st.text_area("Kunci Privat", private_key.decode())
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        text = st.text_input("Masukkan Teks")
        if st.button("Proses"):
            result = rsa_encrypt(text, public_key)
            st.write(f"Hasil Enkripsi: {result}")

    else:
        encrypted_text = st.text_input("Masukkan Teks Terenkripsi")
        private_key_input = st.text_area("Masukkan Kunci Privat")
        if st.button("Proses"):
            result = rsa_decrypt(encrypted_text, private_key_input)
            st.write(f"Hasil Dekripsi: {result}")
