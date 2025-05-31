from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

import json
from colorama import Fore, Style, Back, init as colorama_init
import os
import getpass

def clear_screen():
   """Clear the console screen."""
   os.system('cls' if os.name == 'nt' else 'clear')

def generate_salt():
   """Generate a secure random salt."""
   return get_random_bytes(16)

def generate_key(password: bytes, salt):
   """Generate a secure key from the password and salt."""
   return PBKDF2(password, salt, dkLen=32, count=2000_000, hmac_hash_module=SHA256)

def encrypt_data(data: bytes, salt: bytes, key_password: bytes):
   """Generate a secure data."""
   nonce = get_random_bytes(12)
   key = generate_key(key_password, salt)
   cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
   ciphertext, tag = cipher.encrypt_and_digest(data)
   return {
      "nonce": nonce.hex(),
      "tag": tag.hex(),
      "ciphertext": ciphertext.hex()
   }

def decrypt_data(encrypted_data: dict, salt: bytes, key_password: bytes):
   """Decrypt the encrypted data using the provided salt and password."""
   nonce = bytes.fromhex(encrypted_data["nonce"])
   tag = bytes.fromhex(encrypted_data["tag"])
   ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
   key = generate_key(key_password, salt)
   cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
   return cipher.decrypt_and_verify(ciphertext, tag)

def menu(type=None):
   """Displays different menu options to the user based on the provided type."""

   clear_screen()
   if type == "start":
      print(Fore.RED+ Style.BRIGHT + Back.BLUE + "--- SAFE PASSWORD STORAGE ---")
      print(Fore.CYAN + "1. Generate storage")
      print(Fore.CYAN + "2. Open storage")
      print(Fore.CYAN + "3. Exit")
      print(Fore.GREEN + "Choose an option (1-3): ", end="")
      return input(Fore.GREEN)
   elif type == "generate":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- GENERATE STORAGE ---")
   elif type == "open":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- OPEN STORAGE ---")

# REBUILDING THE FUNCTION TO ADD PASSWORDS
def add_password(storage):
   """Adds a new password to the storage."""
   menu("add")
   name = input(Fore.GREEN + "Enter the name of the password: ")
   password = getpass.getpass(Fore.GREEN + "Enter the password: ")
   re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the password: ")
   if password != re_enter_password:
      print(Fore.RED + "Passwords do not match. Please try again.")
      return
   if not password:
      print(Fore.RED + "Password cannot be empty.")
      return

def open_storage():
   """Opens an existing storage file for passwords."""
   menu("open")
   storage_name = input(Fore.GREEN + "Enter storage name: ")
   if not storage_name:
      print(Fore.RED + "Storage name cannot be empty.")
      return
   storage_name += ".json"
   if not os.path.exists(storage_name):
      print(Fore.RED + "Storage does not exist. Please check the name and try again.")
      return
   storage_password = getpass.getpass(Fore.GREEN + "Enter the storage password: ")
   if not storage_password:
      print(Fore.RED + "Storage password cannot be empty.")
      return
   
   try:
      with open(storage_name, 'r') as f:
         storage_data = json.load(f)
      salt = bytes.fromhex(storage_data["info"]["salt"])
      encrypted_data = storage_data["encrypted_data"]
      decrypted_data = decrypt_data(encrypted_data, salt, storage_password.encode('utf-8'))
      main_password = json.loads(decrypted_data.decode('utf-8'))
      if main_password["main_password"] != storage_password:
         print(Fore.RED + "Incorrect password. Please try again.")
         return
      
      
   except Exception as e:
      print(Fore.RED + f"Error reading storage file: {e}")
      return

def generate_storage():
   """Generates a secure storage file for passwords."""
   menu("generate")
   storage_name = input(Fore.GREEN + "Enter storage name: ")
   if not storage_name:
      print(Fore.RED + "Storage name cannot be empty.")
      return
   storage_name += ".json"
   if os.path.exists(storage_name):
      print(Fore.RED + "Storage already exists. Please choose a different name.")
      return
   
   key_password = getpass.getpass(Fore.GREEN + "Enter a password for the storage: ")
   re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the password: ")
   if key_password != re_enter_password:
      print(Fore.RED + "Passwords do not match. Please try again.")
      return
   if not key_password:
      print(Fore.RED + "Password cannot be empty.")
      return
   
   salt = generate_salt()
   main_password = {
      "main_password": key_password
   }
   main_password = json.dumps(main_password).encode('utf-8')
   data = encrypt_data(main_password, salt, key_password.encode('utf-8'))
   new_storage = {
      "info": {
         "storage_name": storage_name,
         "version": "1.0",
         "salt": salt.hex(),
      },
      "encrypted_data": data
   }

   with open(storage_name, 'w') as f:
      json.dump(new_storage, f, indent=4)
   print(Fore.GREEN + f"Storage '{storage_name}' created successfully.")
   print(Fore.YELLOW + "You can now add passwords to this storage.")

def main():
   colorama_init(autoreset=True)
   menu("start")
   #generate_storage()
   open_storage()


if __name__ == "__main__":
    main()