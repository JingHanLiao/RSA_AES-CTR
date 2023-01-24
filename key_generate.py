import codecs
from pathlib import Path
from Crypto.PublicKey import RSA
from os import path

#Path
key_path = "RSA_Key/" #store key file

data_path = "data/"

pub_key_file = key_path + "RSA_public_key"

prv_key_file = key_path + "RSA_private_key"

def save_key(public_key, private_key):
    
    print("Storing the public key and private key in key file.....Please wait")
    
    global pub_key_file , prv_key_file 
    
    pub_file = pub_key_file + ".pub"
    
    prv_file = prv_key_file + ".key"

    Path(key_path).mkdir( parents=True, exist_ok=True )
    
    f = codecs.open(pub_file, "w", "utf_8")
    
    f.write(public_key.decode("utf-8"))
    
    f.close()
    
    print("public key stored in RSA_Key/RSA_public_key.pub is Done !")

    f = codecs.open(prv_file, "w", "utf_8")
    
    f.write(private_key.decode("utf-8"))
    
    f.close()
    
    print("private key stored in RSA_Key/RSA_private_key.key is Done !")

    print("")

    if not path.exists(data_path):
        Path(data_path).mkdir(parents=True, exist_ok=True)
    
    print("Plese run encryption.py to encryption Plaintext")

def rsa_key_generate():

    print("Generate RSA-key.....Please wait")

    key = RSA.generate(2048)  # use 2048 bits create RSA key

    public_key = key.publickey().exportKey("PEM")

    private_key = key.exportKey("PEM")

    print("Generate RSA 2048 is Done !")

    print("")

    save_key(public_key, private_key)

if __name__ == "__main__":
	rsa_key_generate()
