# MessageCryptAlgorithm

Ferramenta simples em Python para criptografar e descriptografar mensagens usando uma senha.  
Ideal para proteger textos, chaves ou pequenas informações sensíveis de forma rápida e segura.

---

## Uso

```python
from messagecrypt import encrypt, decrypt

mensagem = "Olá Mundo!" 
senha = "[xisparis]" # Sua senha de criptografia Aqui

criptografada = encrypt(mensagem, senha)
print("Encriptada:", criptografada)

decriptada = decrypt(criptografada, senha)
print("Decriptada:", decriptada)
