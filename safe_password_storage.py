from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

import json
from colorama import Fore, Style, Back, init as colorama_init
import os

def clear_screen():
   """Clear the console screen."""
   os.system('cls' if os.name == 'nt' else 'clear')

def generate_salt():
   """Generate a secure random salt."""
   return get_random_bytes(16)

def hash_password(password, salt):
   """Hash a password with a given salt using PBKDF2."""
   return PBKDF2(password, salt, dkLen=32, count=2000_000, hmac_hash_module=SHA256)

def menu(type=None):
   """Displays different menu options to the user based on the provided type."""

   clear_screen()
   if type == "start":
      print(Fore.RED+ Style.BRIGHT + Back.BLUE + "--- SAFE PASSWORD STORAGE ---")
      print(Fore.CYAN + "1. Generate storage")
      print(Fore.CYAN + "2. Open storage")
      print(Fore.CYAN + "3. Exit")
      print(Fore.GREEN + "Choose an option (1-3): ", end="")
   elif type == "generate":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- GENERATE STORAGE ---")

   elif type == "open":
      print(Fore.RED + Style.BRIGHT + Back.BLUE + "--- OPEN STORAGE ---")
   return input(Fore.GREEN)

def main():
   colorama_init(autoreset=True)
   menu("start")


if __name__ == "__main__":
    main()