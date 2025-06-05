from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

import json
from colorama import Fore, Style, Back, init as colorama_init
import os
import getpass
import time
from pprint import pprint

def loading_animation(color=Fore.YELLOW):
   # Display a loading animation
   for _ in range(3):
      time.sleep(0.6)
      print(color + '.', end='')
   print("")
   time.sleep(1)

def clear_screen():
   # Clear the console screen
   os.system('cls' if os.name == 'nt' else 'clear')

def generate_salt():
   # Generate a secure random salt
   return get_random_bytes(16)

def generate_key(password: bytes, salt):
   # Generate a secure key from the password and salt
   return PBKDF2(password, salt, dkLen=32, count=200_000, hmac_hash_module=SHA256)

def encrypt_data(data: bytes, salt: bytes, key_password: bytes):
   # Generate a secure data
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
   # Decrypt the encrypted data using the provided salt and password
   nonce = bytes.fromhex(encrypted_data["nonce"])
   tag = bytes.fromhex(encrypted_data["tag"])
   ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
   key = generate_key(key_password, salt)
   cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
   return cipher.decrypt_and_verify(ciphertext, tag)

def menu(option=None):
   # Displays different menu options to the user based on the provided type

   clear_screen()
   if option == "start":
      print(Fore.RED+ Style.BRIGHT + Back.BLUE + "--- SAFE PASSWORD STORAGE ---")
      print(Fore.CYAN + "1. Generate storage")
      print(Fore.CYAN + "2. Open storage")
      print(Fore.CYAN + "3. Exit")
      print(Fore.GREEN + "Choose an option (1-3): ", end="")
      return input(Fore.GREEN)
   elif option == "open":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- OPENED STORAGE ---")
      print(Fore.CYAN + "1. Add password")
      print(Fore.CYAN + "2. Delete password")
      print(Fore.CYAN + "3. Edit password")
      print(Fore.CYAN + "4. View passwords")
      print(Fore.CYAN + "5. Edit storage password")
      print(Fore.CYAN + "6. Close storage")
      print(Fore.GREEN + "Choose an option (1-6): ", end="")
      return input(Fore.GREEN)
   elif option == "add":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- ADD PASSWORD ---")
      return


def add_password(decrypted_data):
   # Adds a new password to the storage
   menu("add")
   while True:
      name = input(Fore.GREEN + "Enter the name of the password: ")
      if not name:
         print(Fore.RED + "Name cannot be empty. Please try again.")
         continue
      password = getpass.getpass(Fore.GREEN + "Enter the password: ")
      re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the password: ")
      if password != re_enter_password:
         print(Fore.RED + "Passwords do not match. Please try again.")
         continue
      if not password:
         print(Fore.RED + "Password cannot be empty.")
         continue
         
      if name in decrypted_data["encrypted_data"]["ciphertext"]:
         print(Fore.RED + "Password with this name already exists. Please choose a different name.")
         continue

      decrypted_data["encrypted_data"]["ciphertext"][name] = password
      print(Fore.GREEN + f"Password for '{name}' added successfully.")
      want_another = input(Fore.GREEN + "Do you want to add another password? (y/n): ").strip().lower()
      if want_another != 'y':
         return decrypted_data

def delete_password(decrypted_data):
   # Deletes a password from the storage
   while True:
      clear_screen()
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- CURRENT PASSWORDS ---")
      for name, password in decrypted_data["encrypted_data"]["ciphertext"].items():
         print(Fore.CYAN + f"{name}: {password}")
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- DELETE PASSWORD ---")
      name = input(Fore.GREEN + "Enter the name of the password to delete: ")
      if name == "main_password":
         print(Fore.RED + "Cannot delete the main password. Please choose a different name.")
         continue
      elif name in decrypted_data["encrypted_data"]["ciphertext"]:
         del decrypted_data["encrypted_data"]["ciphertext"][name]
         print(Fore.GREEN + f"Password for '{name}' deleted successfully", end="")
         loading_animation(Fore.GREEN)
      else:
         print(Fore.RED + f"No password found for '{name}'", end="")
         loading_animation(Fore.RED)
      
      want_another = input(Fore.GREEN + "Do you want to delete another password? (y/n): ").strip().lower()
      if want_another != 'y':
         print(Fore.YELLOW + "Returning to main menu", end="")
         loading_animation(Fore.YELLOW)
         break
   return decrypted_data

def edit_password(decrypted_data):
   # Edits an existing password in the storage
   while True:
      clear_screen()
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- CURRENT PASSWORDS ---")
      for name, password in decrypted_data["encrypted_data"]["ciphertext"].items():
         print(Fore.CYAN + f"{name}: {password}")
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "\n--- EDIT PASSWORD ---")
      name = input(Fore.GREEN + "Enter the name of the password to edit (leave empty to exit): ")
      if name == "main_password":
         print(Fore.RED + "Cannot edit the main password. Please choose a different name.")
         continue
      if not name:
         print(Fore.YELLOW + "Exiting edit mode", end="")
         loading_animation(Fore.YELLOW)
         return decrypted_data
      if name not in decrypted_data["encrypted_data"]["ciphertext"]:
         print(Fore.RED + f"No password found for '{name}'.")
         continue

      
      new_name = input(Fore.GREEN + "Enter the new name for the password (leave empty to keep current): ")
      new_password = getpass.getpass(Fore.GREEN + "Enter the new password (leave empty to keep current): ")
      if new_name:
         decrypted_data["encrypted_data"]["ciphertext"][new_name] = decrypted_data["encrypted_data"]["ciphertext"].pop(name)
         name = new_name
      if new_password:
         re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the new password: ")
         if new_password != re_enter_password:
            print(Fore.RED + "Passwords do not match. Please try again.")
            continue
         decrypted_data["encrypted_data"]["ciphertext"][name] = new_password
      
      print(Fore.GREEN + f"Password for '{name}' updated successfully", end="")
      loading_animation(Fore.GREEN)
      want_another = input(Fore.GREEN + "Do you want to edit another password? (y/n): ").strip().lower()
      if want_another != 'y':
         print(Fore.YELLOW + "Returning to main menu", end="")
         loading_animation()
         break

   return decrypted_data

def open_storage():
   # Opens an existing storage file for passwords
   print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- OPEN STORAGE ---")
   storage_name = input(Fore.GREEN + "Enter storage name: ")

   # Some validation for storage name, existence check and password
   if not storage_name:
      print(Fore.RED + "Storage name cannot be empty", end="")
      loading_animation(Fore.RED)
      return
   storage_name += ".json"
   if not os.path.exists(storage_name):
      print(Fore.RED + "Storage does not exist. Please check the name and try again", end="")
      loading_animation(Fore.RED)
      return
   storage_password = getpass.getpass(Fore.GREEN + "Enter the storage password: ")
   if not storage_password:
      print(Fore.RED + "Storage password cannot be empty", end="")
      loading_animation(Fore.RED)
      return
   
   # Attempt to read and decrypt the storage file
   try:
      try:
         with open(storage_name, 'r') as f:
            storage_data = json.load(f)
      except json.JSONDecodeError:
         print(Fore.RED + "Corrupted or invalid storage file (invalid JSON format).", end="")
         loading_animation(Fore.RED)
         return

      salt = bytes.fromhex(storage_data["info"]["salt"])
      encrypted_data = storage_data["encrypted_data"]
      decrypted_data = decrypt_data(encrypted_data, salt, storage_password.encode('utf-8'))
      decrypted_data = decrypted_data.decode('utf-8')
      passwords = json.loads(decrypted_data)
      decrypted_data = {
         "nonce": encrypted_data["nonce"],
         "tag": encrypted_data["tag"],
         "ciphertext": passwords
      }
      if passwords["main_password"] != storage_password:
         print(Fore.RED + "Incorrect password. Please try again", end="")
         loading_animation(Fore.RED)
         return
      decrypted_storage = {
         "info": storage_data["info"],
         "encrypted_data": decrypted_data,
      }
   except Exception as e:
      print(Fore.RED + f"Error reading storage file: {e}", end="")
      loading_animation(Fore.RED)
      return
   print(Fore.GREEN + f"Storage '{storage_name}' opened successfully")
   print(Fore.YELLOW + "You can now add or view passwords", end="")
   loading_animation()
   return decrypted_storage

def generate_storage():
   # Generates a secure storage file for passwords
   while True:
      clear_screen()
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- GENERATE STORAGE ---")
      storage_name = input(Fore.GREEN + "Enter storage name (leave empty to exit): ")
      if not storage_name:
         print(Fore.YELLOW + "Exiting", end="")
         loading_animation()
         return None
      storage_name += ".json"
      if os.path.exists(storage_name):
         print(Fore.RED + "Storage already exists. Please choose a different name", end="")
         loading_animation(Fore.RED)
         return None
      
      key_password = getpass.getpass(Fore.GREEN + "Enter a password for the storage: ")
      re_enter_password = getpass.getpass(Fore.GREEN + "Re-enter the password: ")
      if key_password != re_enter_password:
         print(Fore.RED + "Passwords do not match. Please try again", end="")
         loading_animation()
         return None
      if not key_password:
         print(Fore.RED + "Password cannot be empty", end="")
         loading_animation(Fore.RED)
         return None
      
      salt = generate_salt()
      main_password = {
         "main_password": key_password
      }
      main_password_encoded = json.dumps(main_password).encode('utf-8')
      data = encrypt_data(main_password_encoded, salt, key_password.encode('utf-8'))
      decrypted_data = {
         "nonce": data["nonce"],
         "tag": data["tag"],
         "ciphertext": main_password
      }
      new_storage = {
         "info": {
            "storage_name": storage_name,
            "version": "1.0",
            "salt": salt.hex(),
         },
         "encrypted_data": data
      }
      decrypted_storage = {
         "info": {
            "storage_name": storage_name,
            "version": "1.0",
            "salt": salt.hex(),
         },
         "encrypted_data": decrypted_data
      }
      with open(storage_name, 'w') as f:
         json.dump(new_storage, f, indent=4)
      print(Fore.GREEN + f"Storage '{storage_name}' created successfully.")
      print(Fore.YELLOW + "You can now add passwords to this storage", end="")
      loading_animation()
      return decrypted_storage

def close_storage(decrypted_data):
   # Closes the storage and saves the passwords
   print(Fore.YELLOW + "Closing storage...")
   with open(decrypted_data["info"]["storage_name"], 'w') as f:
      encrypted_data = encrypt_data(json.dumps(decrypted_data["encrypted_data"]["ciphertext"]).encode('utf-8'), 
                                     bytes.fromhex(decrypted_data["info"]["salt"]), 
                                     decrypted_data["encrypted_data"]["ciphertext"]["main_password"].encode('utf-8'))
      storage_data = {
         "info": decrypted_data["info"],
         "encrypted_data": encrypted_data
      }
      json.dump(storage_data, f, indent=4)
   print(Fore.GREEN + "Storage closed successfully.")
   print(Fore.YELLOW + "You can now exit the program or create a new storage", end="")
   loading_animation()
   clear_screen()

def print_passwords(decrypted_data):
   # Prints the stored passwords
   clear_screen()
   print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- STORED PASSWORDS ---")
   if not decrypted_data["encrypted_data"]["ciphertext"]:
      print(Fore.YELLOW + "No passwords stored yet.")
      loading_animation()
      return
   for name, password in decrypted_data["encrypted_data"]["ciphertext"].items():
      print(Fore.CYAN + f"{name}: {password}")
   print(Fore.YELLOW + "End of stored passwords.")
   input(Fore.GREEN + "Press Enter to continue...")

def change_storage_password(decrypted_data):
   # Changes the password for the storage
   while True:
      clear_screen()
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- CHANGE STORAGE PASSWORD ---")
      new_password = getpass.getpass(Fore.YELLOW + "Enter the new password for the storage (leave empty to exit): ")
      if not new_password:
         print(Fore.YELLOW + "Exiting", end="")
         loading_animation()
         return
      re_enter_password = getpass.getpass(Fore.YELLOW + "Re-enter the new password: ")
      if new_password != re_enter_password:
         print(Fore.RED + "Passwords do not match. Please try again", end="")
         loading_animation(Fore.RED)
         continue
      
      decrypted_data["encrypted_data"]["ciphertext"]["main_password"] = new_password
      break

   print(Fore.GREEN + "Password changed successful.", end="")
   loading_animation(Fore.GREEN)
   return decrypted_data

def opened_storage(decrypted_data):
   # Function to handle the opened storage
   while True:
      option = menu("open")
      if option == "1":
         decrypted_data = add_password(decrypted_data)
      elif option == "2":
         decrypted_data = delete_password(decrypted_data)
      elif option == "3":
         decrypted_data = edit_password(decrypted_data)
      elif option == "4":
         print_passwords(decrypted_data)
      elif option == "5":
         decrypted_data = change_storage_password(decrypted_data)
      elif option == "6":
         close_storage(decrypted_data)
         break
      else:
         print(Fore.RED + "Invalid option. Please try again.")
         continue

def main():
   colorama_init(autoreset=True)
   try:
      while True:
         option = menu("start")
         clear_screen()
         if option == "1":
            decrypted_data = generate_storage()
            if decrypted_data == None:
               continue
            opened_storage(decrypted_data)
         elif option == "2":
            decrypted_data = open_storage()
            if decrypted_data == None:
               continue
            opened_storage(decrypted_data)
         elif option == "3":
            print(Fore.GREEN + "Exiting the program. Goodbye!")
            return
         else:
            print(Fore.RED + "Invalid option. Please try again.")
            continue
   except KeyboardInterrupt:
      print(Fore.RED + "\nProgram interrupted. Exiting...")
      return
   except Exception as e:
      print(Fore.RED + f"An error occurred: {e}")
      return


if __name__ == "__main__":
    main()