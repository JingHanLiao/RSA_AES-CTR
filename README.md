# RSA+AES-CTR for Python

This Project will show the using RSA and AES-CTR to encryption the Plaintext then decryption the Ciphertext.

## Table of Contents

- [Top-level directory](#top-level-directory)
- [Install](#install)
- [Quick start](#quick-start)

## Top-level directory

The top-level files and directories in a RSA+AES-CTR project.

    .
    ├── data
    │   ├── encrypted_AES_key.txt
    │   ├── input_msg.txt
    │   ├── msg_cipher.txt
    │   └── output_msg.txt
    │
    ├── RSA_Key
    │   ├── RSA_private_key.key
    │   └── RSA_public_key.pub
    │
    ├── decryption.py
    ├── encryption.py
    └── key_generate.py

## Install

This project uses python 3.10 and Python Cryptography Toolkit (pycrypto) or PyCryptodome, then uses Pycharm IDE, Go check them out if you don't have them locally installed.

```bash
pip install pycryptodome
pip install crypto
pip install pycrypto
```

## Quick start

#### Step-1

execute the `key_generate.py` program to generate the public key and private key of RSA. After the execution is completed, a new folder called RSA_Key will be automatically created, and the public key and private key of RSA will be stored in RSA_Key folder.

![image](https://github.com/JingHanLiao/RSA_AES-CTR/blob/master/IMG/1.png)

#### Step-2

Please execute the `encryption.py` program to encryption the plaintext. During the encryption process, you need to input a string on the terminal, and the program will treat the input string as plaintext and save in `/data/input_msg.txt`. After the execution is completed, the plaintext encrypted to ciphertext save in `/data/msg_cipher.txt` and the encrypted AES key will save in `/data/encrypted_AES_key.txt`.

![image](https://github.com/JingHanLiao/RSA_AES-CTR/blob/master/IMG/2.png)

![image](https://github.com/JingHanLiao/RSA_AES-CTR/blob/master/IMG/3.png)

#### Step-3

Please execute the `decryption.py` program to decryption the ciphertext. After the execution is completed, The program will output decrypting the ciphertext to the result, The result is save in `/data/output_msg.txt`. Finally, you can verify the original message `input_msg.txt` and the decrypted message `output_msg.txt` are the same or consistent.

![image](https://github.com/JingHanLiao/RSA_AES-CTR/blob/master/IMG/4.png)

![image](https://github.com/JingHanLiao/RSA_AES-CTR/blob/master/IMG/5.png)
