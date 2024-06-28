# Encryption and Decryption Tester

Made for beginners to visualize what encryption looks like. Provides output of encryption in ciphertext and the decryption of plaintext. Test Symmetric and Asymmetric encryption; Hashing; File encryption and decryption (NOTE: Encrypting your file will delete the original file. Do not use on sensitive or important files.)

# Installation

```
pip install cryptography

git clone https://github.com/FrogMechRider/Encryption-and-Decryption-tester.git

cd Encryption-and-Decryption-tester

```

# Usage

```
python Encryption_and_Decryption.py

```

Data Encryption and Decryption Tool
1. Symmetric Encryption (AES)
2. Asymmetric Encryption (RSA)
3. Hashing (SHA-256)
4. File Encryption
5. File Decryption
6. Exit

Choose an option:

1. Symmetric encryption:

Generated AES key (hex): ff2e8934d82c2910cdc807b24f633bc530de20280e42f6cfb6a223d937dc77af

Enter plaintext: FrogMechRider

Ciphertext: b'3(\x8b\x8d\xc7\x9a\xeaw\xa8|\xb9\xa8}5\xee\xa7\x87X\x10p\xbe\xff\x11\t\xa8\xb5\xd5\xa5\x8c?\xab\x81'

Enter the AES key to decrypt: ff2e8934d82c2910cdc807b24f633bc530de20280e42f6cfb6a223d937dc77af

Decrypted text: FrogMechRider

### Note: When encrypting a file, the new file will be appended with ".enc". Keep that in mind when decrypting your file.
