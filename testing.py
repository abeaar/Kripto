import streamlit as st
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

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

# Fungsi AES Cipher dengan key management yang lebih aman
def generate_key():
    return os.urandom(32)

def aes_encrypt(plain_text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(encrypted_text, key):
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        iv, encrypted_message = encrypted_data[:16], encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()
    except Exception as e:
        return f"Dekripsi gagal: {str(e)}"

# Streamlit UI
st.title("Aplikasi Kriptografi")

# Simpan key AES di session state
if 'aes_key' not in st.session_state:
    st.session_state.aes_key = generate_key()

menu = st.sidebar.selectbox("Pilih Metode", ["Caesar Cipher", "Rail Fence", "AES"])

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