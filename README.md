# A5-1-Python
A5/1 Stream Cipher in Python 3

## Usage
Encrypt: 
```python
a5 = A5(key)  # Supports bytes, int and str
print(a5.encrypt(sth))  # Supports bytes and str
print(a5.encrypt_int(num))  # Use this to encrypt an integer
```
Decrypt: 
```python
a5 = A5(key)
print(a5.decrypt(sth, type))
```
You can see more information in the code file.
