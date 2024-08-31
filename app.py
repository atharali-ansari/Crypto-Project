from flask import Flask, render_template, request, redirect, send_file
import os
import hashlib
import base64
from Crypto import Random
from Crypto.Cipher import AES

app = Flask(__name__)
block_size = 16

def sha256(key):
    sha = hashlib.sha256()
    sha.update(key.encode('utf-8'))
    return sha.digest()

def pad(plain, block):
    pad_len = block - (len(plain) % block)
    return plain + (pad_len * chr(pad_len)).encode('ascii')

def unpad(plain):
    pad_len = plain[-1]
    return plain[:-pad_len]

def encrypt(plain, key):
    plain = pad(plain, block_size)
    iv = Random.new().read(block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    final_cipher = cipher.encrypt(plain)
    return base64.b64encode(iv + final_cipher)

def decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[block_size:])
    return unpad(plaintext)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    key = request.form['key']
    key = sha256(key)
    
    input_file_path = os.path.join('uploads', file.filename)
    output_file_path = os.path.join('encrypted', 'encryptedfile.enc')

    file.save(input_file_path)
    with open(input_file_path, 'rb') as fp:
        file_data = fp.read()
        base64_file = base64.b64encode(file_data)
    enc = encrypt(base64_file, key)
    
    with open(output_file_path, 'wb') as fp1:
        fp1.write(enc)
    
    return send_file(output_file_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    file = request.files['file']
    key = request.form['key']
    extension = request.form['extension']  # Get the selected file extension
    key = sha256(key)
    
    input_file_path = os.path.join('uploads', file.filename)
    output_file_path = os.path.join('decrypted', f'decryptedfile{extension}')  # Use the selected extension

    file.save(input_file_path)
    with open(input_file_path, 'rb') as fp:
        enc = fp.read()
    dec = decrypt(enc, key)
    decoded_file_data = base64.b64decode(dec)
    
    with open(output_file_path, 'wb') as fp2:
        fp2.write(decoded_file_data)
    
    return send_file(output_file_path, as_attachment=True)

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('encrypted', exist_ok=True)
    os.makedirs('decrypted', exist_ok=True)
    app.run(debug=True)
