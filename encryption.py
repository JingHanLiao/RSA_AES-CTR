import base64
import codecs
import os.path
from binascii import hexlify
from os import path
from pathlib import Path
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


#Path
key_path = "RSA_Key/"

data_path = "data/"

data_msg_path = data_path + "input_msg.txt"

pub_key_file = key_path + "RSA_public_key"

prv_key_file = key_path + "RSA_private_key"

encrypted_aes_key_file = data_path + "encrypted_AES_key.txt"

msg_cipher_file = data_path + "msg_cipher.txt"

#initial
public_key = ""

aes_key = ""

aes_key_iv = ""

encrypted_aes_key = ""

input_msg = ""

cipher_message = ""

#step 1
def load_RSA_public_key():
    
    print("Step-1 Load RSA public key.....Please wait")
    
    global pub_key_file , public_key
    
    pub_file = pub_key_file + ".pub"

    if path.exists(pub_file):
        
        try:
            key = codecs.open(pub_file, "r", "utf_8").read()
            
            public_key = RSA.import_key(key)
            
            #print(public_key)
            
            print("Load RSA public key is Done !")
            
            return True
            
        except:
            
            print("ERROR!!! Load RSA public key is false , Plese run key_generate.py to generate RSA key")
               
            return False

    else:
    		print("ERROR!!! RSA public key file does not exist , Plese run key_generate.py to generate RSA key")
            
    		return False

#step 2
def AES_key_generate():
    
    print("Step-2 generate AES key.....Please wait")
    
    global aes_key , aes_key_iv

    aes_key = get_random_bytes(16)
    
    aes_key_iv = get_random_bytes(16)
    
    print("generate AES key is Done !")

#step 3 
def create_msg_data():
    
    print("Step-3 create Plaintext data.....Please wait")

    if not path.exists(data_path):
            
        Path(data_path).mkdir(parents=True, exist_ok=True)

    f = codecs.open( data_msg_path , "w", "utf_8")

    print("Please input the Plaintext message in input_msg.txt")

    init_msg = input()

    f.write( init_msg )

    f.close()

    # non exists
    if not os.path.getsize(data_msg_path):
        print("ERROR!!! Please create the input_msg.txt in data Folder then restart encryption.py")
        return False
    # exists input_msg.txt
    else:
        print("create Plaintext data is Done !")
        return True

#step4
def load_msg_data():
    
    print("Step-4 Load Plaintext message.....Please wait")
    
    global input_msg

    if path.exists(data_msg_path):
        
        input_msg = codecs.open(data_msg_path, "r", "utf_8").read().encode(encoding="utf-8")
        
        print("Load Plaintext message is Done !")
        
        return True
    
    else:
        
        print("ERROR!!! input_msg.txt is not found,Please create the input_msg.txt in data Folder then restart encryption.py")
        
        return False
    
#step5
def encryption_msg():

    #Use AES key encryption the Plaintext message(input_msg.txt)
    print("Step-5 encryption Plaintext message.....Please wait")
    
    global cipher_message

    block_size = 32
    
    ctr = Counter.new( 128 , initial_value = int( hexlify(aes_key_iv) , 16 ) )
    
    aes_cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

    result = b''

    for i in range( 0 , len(input_msg) , block_size ):
        
        block = bytes(input_msg[i:i + block_size])

        result = result + aes_cipher.encrypt( block )

    cipher_message = result
    
    print("Use AES key encryption Plaintext message is Done !")

#step6
def encryption_AES_key():
    
    print("Step-6 encryption AES key.....Please wait")
    
    global encrypted_aes_key

    RSA_cipher = PKCS1_OAEP.new(public_key)
    
    encrypted_aes_key = RSA_cipher.encrypt(aes_key)
    
    print("Encryption AES key is Done !")

#step 7
def save_msg_cipher():
    
    print("Step-7 Save cipher message.....Please wait")
    
    Path(data_path).mkdir(parents=True, exist_ok=True)

    cipher_iv = aes_key_iv + cipher_message
    
    output_cipher = base64.b64encode(cipher_iv).decode(encoding="utf-8")
    
    f = codecs.open(msg_cipher_file, "w", "utf_8")
    
    f.write(output_cipher)
    
    f.close()

    print("Save cipher message is Done !")

#step 8
def save_encrypted_AES_key():
    
    print("Step-8 Save encrypted AES key.....Please wait")
    
    Path(data_path).mkdir( parents=True , exist_ok=True )

    output_AES_key = base64.b64encode(encrypted_aes_key).decode(encoding="utf-8")
    
    f = codecs.open(encrypted_aes_key_file , "w" , "utf_8")
    
    f.write( output_AES_key )
    
    f.close()
    
    print("Save encrypted AES key is Done !")

def encryption():
    
	#step 1
    if not load_RSA_public_key():
        return False

    print("")
    
    #step 2
    AES_key_generate()

    print("")
    
    #step 3
    if not create_msg_data():
        return True

    print("")

    #step 4
    if not load_msg_data():
        return True

    print("")
    
    #step 5
    encryption_msg()

    print("")
    
    #step 6
    encryption_AES_key()

    print("")
    
    #step 7
    save_msg_cipher()

    print("")
    
    #step 8
    save_encrypted_AES_key()

    print("")
    
    print("Please run decryption.py to decryption cipher message ")

if __name__ == "__main__":
    encryption()