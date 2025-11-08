# -*- coding: utf-8 -*-

"""
Criptografia autenticada de mensagens em Python utilizando ChaCha20-Poly1305 e derivação de chave com Argon2id.
O algoritmo deriva uma chave segura a partir da senha, gera salt e nonce aleatórios e empacota tudo em um envelope binário codificado em Base64 (Para melhor legibilidade.)
A descriptografia só é possível com a mesma senha e os parâmetros originais do envelope. 
A implementação é resistente a ataques de tempo e força bruta
"""

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
import os
import base64
import struct

global cName
cName = "Xisparis-Crypt" + "-"

def derive_key(senha, salt, memoria=64*1024, iteracoes=7, paralelo=1):
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iteracoes,
        lanes=paralelo,
        memory_cost=memoria,
        ad=None,
        secret=None
    )
    return kdf.derive(senha.encode())

def encrypt(plaintext, senha):
    salt = os.urandom(16)
    key = derive_key(senha, salt)
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)
    ct_len = len(ciphertext)
    envelope = struct.pack(">BBB", 1, 1, 0)
    envelope += struct.pack("B", len(salt)) + salt
    envelope += struct.pack("B", len(nonce)) + nonce
    envelope += struct.pack(">H", ct_len) + ciphertext
    return cName + base64.b64encode(envelope).decode()

def decrypt(envelope_str, senha):
    if not envelope_str.startswith(cName):
        raise ValueError("Envelope inválido ou corrompido.")
    b64 = envelope_str[len(f"{cName}"):]
    data = base64.b64decode(b64)
    version, kdf_id, kdf_params_len = struct.unpack(">BBB", data[:3])
    idx = 3
    salt_len = data[idx]
    idx += 1
    salt = data[idx:idx+salt_len]
    idx += salt_len
    nonce_len = data[idx]
    idx += 1
    nonce = data[idx:idx+nonce_len]
    idx += nonce_len
    ct_len = struct.unpack(">H", data[idx:idx+2])[0]
    idx += 2
    ciphertext = data[idx:idx+ct_len]
    key = derive_key(senha, salt)
    aead = ChaCha20Poly1305(key)
    try:
        enc = aead.decrypt(nonce, ciphertext, None).decode()
    except InvalidTag: 
        return "Invalid Password :("
    return enc

# Usage
'''
mensagem = "Olá Mundo!"

senha = """[xisparis]"""

encriptada = encrypt(mensagem, senha)
print("Encriptada:", encriptada)

decriptada = decrypt(encriptada, senha)
print("Decriptada:", decriptada)
'''
