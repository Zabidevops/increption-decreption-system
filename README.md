# increption-decreption-system
from cryptography.fernet import Fernet

def encrypt(message):
    # Generate a key and encrypt the message
    key = Fernet.generate_key()
    fernet = Fernet(key)
    enc_msg = fernet.encrypt(message.encode())
    print(f"Original message: {message}")
    print(f"Encrypted message: {enc_msg}")
    print(f"Key (save this for decryption): {key}")
    return enc_msg, key

def decrypt(enc_msg, key):
    # Decrypt the encrypted message using the key
    fernet = Fernet(key)
    dec_msg = fernet.decrypt(enc_msg).decode()
    print(f"Decrypted message: {dec_msg}")

if __name__ == "__main__":
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            message = input("Enter the message to encrypt: ")
            print("------------------------------------------------------------------")
            enc_msg, key = encrypt(message)
            print("------------------------------------------------------------------")
        
        elif choice == "2":
            if 'enc_msg' and 'key' in locals():
                print("------------------------------------------------------------------")
                decrypt(enc_msg, key)
                print("------------------------------------------------------------------")
            else:
                print("No encrypted message found! Please encrypt a message first.")
        
        elif choice == "3":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice! Please try again.")
