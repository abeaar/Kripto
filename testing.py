import streamlit as st
import base64
import os
from itertools import cycle

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

# Simple XOR Cipher sebagai pengganti AES
def xor_encrypt(text, key):
    # Convert text to bytes if it's a string
    if isinstance(text, str):
        text = text.encode()
    if isinstance(key, str):
        key = key.encode()
        
    # XOR operation
    xored = bytes(a ^ b for a, b in zip(text, cycle(key)))
    return base64.b64encode(xored).decode('utf-8')

def xor_decrypt(encrypted_text, key):
    try:
        if isinstance(key, str):
            key = key.encode()
        
        # Decode base64 and XOR
        encrypted_bytes = base64.b64decode(encrypted_text)
        decrypted = bytes(a ^ b for a, b in zip(encrypted_bytes, cycle(key)))
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"Dekripsi gagal: {str(e)}"

# Streamlit UI
st.title("Aplikasi Kriptografi")

# Generate random key for XOR cipher
if 'xor_key' not in st.session_state:
    st.session_state.xor_key = os.urandom(16)

menu = st.sidebar.selectbox("Pilih Metode", ["Caesar Cipher", "Rail Fence", "XOR Cipher"])

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

elif menu == "XOR Cipher":
    st.header("XOR Cipher")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])

    if mode == "Encrypt":
        text = st.text_input("Masukkan Teks")
        if st.button("Enkripsi"):
            result = xor_encrypt(text, st.session_state.xor_key)
            st.write(f"Hasil Enkripsi: {result}")
            st.write(f"Kunci (hex): {st.session_state.xor_key.hex()}")
            st.info("Simpan kunci ini untuk dekripsi!")

    else:
        encrypted_text = st.text_input("Masukkan Teks Terenkripsi")
        key_hex = st.text_input("Masukkan Kunci (hex)")
        if st.button("Dekripsi"):
            try:
                key = bytes.fromhex(key_hex)
                result = xor_decrypt(encrypted_text, key)
                st.write(f"Hasil Dekripsi: {result}")
            except ValueError:
                st.error("Format kunci tidak valid!")
