from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

import json
from colorama import Fore, Style, Back, init as colorama_init
import os
import getpass
import time

def loading_animation():
   """Display a loading animation."""
   for _ in range(3):
      time.sleep(0.6)
      print(Fore.YELLOW + '.', end='')
   time.sleep(1)

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
      print(Fore.CYAN + "1. Add password")
      print(Fore.CYAN + "2. View passwords")
      print(Fore.CYAN + "3. Back to main menu")
      print(Fore.GREEN + "Choose an option (1-3): ", end="")
      return input(Fore.GREEN)
   elif type == "open":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- OPEN STORAGE ---")
      print(Fore.CYAN + "1. Add password")
      print(Fore.CYAN + "2. View passwords")
      print(Fore.CYAN + "3. Back to main menu")
      print(Fore.GREEN + "Choose an option (1-3): ", end="")
      return input(Fore.GREEN)




# REBUILDING THE FUNCTION TO ADD PASSWORDS
def add_password(decrypted_data):
   """Adds a new password to the storage."""
   menu("add")
   print(decrypted_data)
   while True:
      name = input(Fore.GREEN + "Enter the name of the password: ")
      password = getpass.getpass(Fore.GREEN + "Enter the password: ")
      re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the password: ")
      if password != re_enter_password:
         print(Fore.RED + "Passwords do not match. Please try again.")
         continue
      if not password:
         print(Fore.RED + "Password cannot be empty.")
         continue
         
      if name in decrypted_data["passwords"]:
         print(Fore.RED + "Password with this name already exists. Please choose a different name.")
         continue

      decrypted_data["passwords"][name] = password
      print(Fore.GREEN + f"Password for '{name}' added successfully.")
      want_another = input(Fore.GREEN + "Do you want to add another password? (y/n): ").strip().lower()
      if want_another != 'y':
         return decrypted_data
   
def open_storage():
   """Opens an existing storage file for passwords."""
   print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- OPEN STORAGE ---")
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
   print(Fore.GREEN + f"Storage '{storage_name}' opened successfully")
   print(Fore.YELLOW + "You can now add or view passwords", end="")
   loading_animation()

def generate_storage():
   """Generates a secure storage file for passwords."""
   print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- GENERATE STORAGE ---")
   storage_name = input(Fore.GREEN + "Enter storage name: ")
   if not storage_name:
      print(Fore.RED + "Storage name cannot be empty", end="")
      loading_animation()
      return
   storage_name += ".json"
   if os.path.exists(storage_name):
      print(Fore.RED + "Storage already exists. Please choose a different name", end="")
      loading_animation()
      return
   
   key_password = getpass.getpass(Fore.GREEN + "Enter a password for the storage: ")
   re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the password: ")
   if key_password != re_enter_password:
      print(Fore.RED + "Passwords do not match. Please try again", end="")
      loading_animation()
      return
   if not key_password:
      print(Fore.RED + "Password cannot be empty", end="")
      loading_animation()
      return
   
   salt = generate_salt()
   main_password = {
      "main_password": key_password
   }
   main_password_encoded = json.dumps(main_password).encode('utf-8')
   data = encrypt_data(main_password_encoded, salt, key_password.encode('utf-8'))
   new_storage = {
      "info": {
         "storage_name": storage_name,
         "version": "1.0",
         "salt": salt.hex(),
      },
      "passwords": data
   }
   decrypted_storage = {
      "info": {
         "storage_name": storage_name,
         "version": "1.0",
         "salt": salt.hex(),
      },
      "passwords": main_password
   }
   with open(storage_name, 'w') as f:
      json.dump(new_storage, f, indent=4)
   print(Fore.GREEN + f"Storage '{storage_name}' created successfully.")
   print(Fore.YELLOW + "You can now add passwords to this storage", end="")
   loading_animation()
   return decrypted_storage

def close_storage(decrypted_data):
   """Closes the storage and saves the passwords."""
   print(Fore.GREEN + "Closing storage...", end="")
   with open(decrypted_data["info"]["storage_name"], 'w') as f:
      encrypted_data = encrypt_data(json.dumps(decrypted_data["passwords"]).encode('utf-8'), 
                                     bytes.fromhex(decrypted_data["info"]["salt"]), 
                                     decrypted_data["passwords"]["main_password"].encode('utf-8'))
      storage_data = {
         "info": decrypted_data["info"],
         "encrypted_data": encrypted_data
      }
      json.dump(storage_data, f, indent=4)
   print(Fore.GREEN + "Storage closed successfully.")
   print(Fore.YELLOW + "You can now exit the program or create a new storage", end="")
   loading_animation()
   clear_screen()

def main():
   colorama_init(autoreset=True)
   while True:
      option = menu("start")
      clear_screen()
      if option == "1":
         decrypted_data = generate_storage()
         while True:
            option = menu("generate")
            if option == "1":
               decrypted_data = add_password(decrypted_data)
            elif option == "2":
               print(Fore.YELLOW + "Viewing passwords is not implemented yet.")
            elif option == "3":
               close_storage(decrypted_data)
               break
            else:
               print(Fore.RED + "Invalid option. Please try again.")
               continue
      elif option == "2":
         open_storage()
      elif option == "3":
         print(Fore.GREEN + "Exiting the program. Goodbye!")
         return
      else:
         print(Fore.RED + "Invalid option. Please try again.")
         continue


if __name__ == "__main__":
    main()