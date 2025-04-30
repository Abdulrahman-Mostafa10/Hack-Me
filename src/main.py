import json
from sender import Sender
from receiver import Receiver
import hashlib

def main():
    with open("config.json", "r") as f:
        config = json.load(f)
    chunk_size = config["chunk_size"]
    lcg_params = config["lcg"]
    dh_params = config["diffie_hellman"]
    aes_params = config["aes"]
    hmac_params = config["hmac"]
    
    with open(config["input_file"], "rb") as f:
        input_data = f.read()
    
    sender = Sender(
        q=dh_params["q"],
        alpha=dh_params["alpha"],
        m=lcg_params["m"],
        a=lcg_params["a"],
        c=lcg_params["c"],
        key_length=aes_params["key_size"],
        hashfunc=getattr(hashlib, hmac_params["hash_algorithm"])
    )
    
    receiver = Receiver(
        q=dh_params["q"],
        alpha=dh_params["alpha"],
        m=lcg_params["m"],
        a=lcg_params["a"],
        c=lcg_params["c"],
        key_length=aes_params["key_size"],
        hashfunc=getattr(hashlib, hmac_params["hash_algorithm"])
    )
    
    # Diffie-Hellman key exchange
    sender_public = sender.generate_public_key()
    receiver_public = receiver.generate_public_key()
    
    sender.generate_shared_secret(receiver_public)
    receiver.generate_shared_secret(sender_public)
    
    # Send and receive initial seed
    encrypted_seed, hmac_value = sender.send_initial_seed()
    receiver.receive_initial_seed(encrypted_seed, hmac_value)
    
    # Encrypt and decrypt the message 1 byte at a time (can't just delete my creations, it is a part of me, it is what defines me, it is what makes me, me) aaaaaahhhhhh
    # encrypted_message = bytearray()
    # for byte in input_data:
    #     print(f"Byte: {byte}")
    #     encrypted_message.append(sender.process_message(byte))
    
    # decrypted_message = bytearray()
    # for byte in encrypted_message:
    #     decrypted_message.append(receiver.process_message(byte))
    

    # Encrypt and decrypt the message 10 bytes at a time
    encrypted_message = []
    for i in range(0, len(input_data), chunk_size):
        chunk = input_data[i:i + chunk_size]
        chunk_bytes = bytearray(chunk)
        encrypted_message.append(sender.process_message(chunk_bytes))

    decrypted_message = []
    for bytes in encrypted_message:
        decrypted_message.append(receiver.process_message(bytes))

    
    # Write output
    with open(config["output_file"], "wb") as f:
        f.write(b"".join(decrypted_message))
    
    print("\nCommunication successful!")
    if input_data == b"".join(decrypted_message):
        print("Decrypted message matches the original input data.")
    else:
        print("Decrypted message does not match the original input data.")

if __name__ == "__main__":
    main()
