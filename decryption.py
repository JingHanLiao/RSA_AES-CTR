import base64
import codecs
from binascii import hexlify
from os import path
from Crypto.Util import Counter
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

#Path
key_path = "RSA_Key/"

data_path = "data/"

data_msg_path = data_path + "input_msg.txt"

output_data_msg_path = data_path + "output_msg.txt"

pub_key_file = key_path + "RSA_public_key"

prv_key_file = key_path + "RSA_private_key.key"

encrypted_aes_key_file = data_path + "encrypted_AES_key.txt"

msg_cipher_file = data_path + "msg_cipher.txt"

#initial
cipher_iv = ""

encrypted_aes_key = ""

private_key = ""

AES_key = ""

output_msg = ""

#step 1
def load_msg_cipher():
    
    print("Step-1 Load cipher message.....Please wait")

    global cipher_iv

    if path.exists(msg_cipher_file):
        
        try:
            
            key = codecs.open(msg_cipher_file, "r", "utf_8").read()
            
            cipher_iv = base64.b64decode(key)
            
        except:
            
            print("ERROR!!! msg_cipher.txt is not found, Please run encryption.py restart encryption")
            
            return False
        
        print("Load cipher message is Done !")
        
        return True
    
    else:
        
        print("ERROR!!! msg_cipher.txt is not found, Please run encryption.py restart encryption")
        
        return False
    
#step 2
def load_encrypted_AES_key():
    
    print("Step-2 Load encrypted AES key.....Please wait")
    
    global encrypted_aes_key
    
    if path.exists(encrypted_aes_key_file):
        
        try:
            
            key = codecs.open(encrypted_aes_key_file, "r", "utf_8").read()
            
            encrypted_aes_key = base64.b64decode(key)
            
        except:

            print("ERROR!!! encrypted AES key is not found, Please run encryption.py restart encryption")

            return False
        
        print("Load encrypted AES key is Done !")
        
        return True
    
    else:
        
        print("ERROR!!! encrypted AES key is not found, Please run encryption.py restart encryption")
        
        return False

#step 3
def load_RSA_private_key():
    
    print("Step-3 Load RSA private key.....Please wait")
    
    global private_key
    
    if path.exists(prv_key_file):
        
        try:
            key = codecs.open(prv_key_file, "r", "utf_8").read()
            
            private_key = RSA.import_key(key)
            
        except:

            print("ERROR!!! RSA private key is not found, Please run encryption.py restart encryption")

            return False

        print("Load RSA private key is Done !")
        
        return True
    
    else:

        print("ERROR!!! RSA private key is not found, Please run encryption.py restart encryption")
        
        return False

#step 4
def decryption_AES_key():

    print("Step-4 Decryption AES key using RSA private key.....Please wait")
    
    global AES_key

    rsa_cipher = PKCS1_OAEP.new(private_key)
    
    AES_key = rsa_cipher.decrypt(encrypted_aes_key)

    print("Decryption AES key using RSA private key is Done !")

#step 5
def decryption_msg_cipher():
    
    print("Step-5 Decryption ciphertext using AES key.....Please wait")
    
    global output_msg

    block_size = 32
    
    aes_key_iv = cipher_iv[:16]
    
    ciphers = cipher_iv[16:]

    ctr = Counter.new(128, initial_value=int(hexlify(aes_key_iv), 16))
    
    aes_cipher = AES.new(AES_key, AES.MODE_CTR, counter=ctr)

    result = b''

    for i in range(0, len(ciphers), block_size):
        
        block = bytes(ciphers[i:i + block_size])

        result = result + aes_cipher.decrypt(block)

    output_msg = result
    
    print("Decryption ciphertext using AES key is Done !")
    
#step 6
def save_output_msg():
    
    print("Step-6 Store the output message....Please wait")
    
    output = output_msg.decode("utf-8")
    
    f = codecs.open(output_data_msg_path, "w", "utf_8")
    
    f.write(output)
    
    f.close()
    
    print("Store the output message is Done !")
    
    
def decryption():

	#step 1
    if not load_msg_cipher():
        return False

    print("")
    
    #step 2
    if not load_encrypted_AES_key():
        return False

    print("")
    
    #step 3
    if not load_RSA_private_key():
        return False

    print("")
    
    #step 4
    decryption_AES_key()

    print("")
    
    #step 5
    decryption_msg_cipher()

    print("")
    
    #step 6
    save_output_msg()

    print("")
    
    print("!!! Please verify that the input_msg.txt and output_msg.txt are the same !!!")

if __name__ == "__main__":
	decryption()