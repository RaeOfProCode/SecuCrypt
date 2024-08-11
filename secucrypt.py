"""
#╭――――――――――――――――――――――――――――――――――――――――╮#
#│              >>SeCrypt<<               │#
#│  Coded by Rachel Lin (aka) RaeOfCode   │#
#╰――――――――――――――――――――――――――――――――――――――――╯#
"""


#------------------------------IMPORTS------------------------------#
# Imports for TITLE
from pydoc import plain
import shutil
from rich import print
from rich.console import Console

# Imports for TEXT CONVERSION, CRYPTOGRAPHY, and MAIN MENU
import binascii
from rich.prompt import Prompt
from Crypto.Cipher import DES, AES
from Crypto.Hash import MD5, SHA1, SHA256
from Crypto.Util.Padding import pad


#------------------------------CONSOLE SETUPS------------------------------#
# Constructs a Console object using the python library, rich.
console = Console()


# Terminal Size
def get_terminal_size_columns():
    # Gets the terminal size this code is ran on and returns the number of columns (characters per line).
    size = shutil.get_terminal_size()
    return size.columns


def get_terminal_size_rows():
    # Gets the terminal size this code is ran on and returns the number of rows (lines).
    size = shutil.get_terminal_size()
    return size.lines


# The number of columns of the terminal is stored into "terminal_columns".
terminal_columns = get_terminal_size_columns()

# The number of rows of the terminal is stored into "terminal_rows".
terminal_rows = get_terminal_size_rows()


#------------------------------TITLE------------------------------#
# Archived: Full ASCII Art of the Logo Title
full_logo_title = r"""
  _________                    _________                        __   
 /   _____/ ____   ____  __ __ \_   ___ \_______ ___.__._______/  |_ 
 \_____  \_/ __ \_/ ___\|  |  \/    \  \/\_  __ <   |  |\____ \   __\
 /        \  ___/\  \___|  |  /\     \____|  | \/\___  ||  |_> >  |  
/_______  /\___  >\___  >____/  \______  /|__|   / ____||   __/|__|  
        \/     \/     \/               \/        \/     |__|         
"""

# Full ASCII Art of the Logo Description
logo_description = r"""
____ ____ _    ____ ____ ____ ____ ____ ___  ____ _  _ _      ____ ____ ____ __   
| __\| . \||_/\| . \|_ _\|   ||  _\| . \|  \ | . \||_|\||_/\  |_ _\|   ||   || |  
| \__|  <_| __/| __/  || | . || [ \|  <_| . \| __/| _ || __/    || | . || . || |__
|___/|/\_/|/   |/     |/ |___/|___/|/\_/|/\_/|/   |/ |/|/       |/ |___/|___/|___/
"""


def display_logo():
    # Displays the Logo and Logo Description.

    if terminal_columns >= 82:
        # Checks if the terminal is big enough to print the Logo and Description

        # Prints the Logo -> "SecuCrypt"
        print(f'[dark_blue]{r"""  _________                     """}[/dark_blue][dark_orange]{r"""_________                        __    """}[/dark_orange]')
        print(f'[dark_blue]{r""" /   _____/ ____   ____  __ __  """}[/dark_blue][dark_orange]{r"""\_   ___ \_______ ___.__._______/  |_  """}[/dark_orange]')
        print(f'[dark_blue]{r""" \_____  \_/ __ \_/ ___\|  |  \ """}[/dark_blue][dark_orange]{r"""/    \  \/\_  __ <   |  |\____ \   __\ """}[/dark_orange]')
        print(f'[dark_blue]{r""" /        \  ___/\  \___|  |  / """}[/dark_blue][dark_orange]{r"""\     \____|  | \/\___  ||  |_> >  |   """}[/dark_orange]')
        print(f'[dark_blue]{r"""/_______  /\___  >\___  >____/  """}[/dark_blue][dark_orange]{r""" \______  /|__|   / ____||   __/|__|   """}[/dark_orange]')
        print(f'[dark_blue]{r"""        \/     \/     \/        """}[/dark_blue][dark_orange]{r"""        \/        \/     |__|          """}[/dark_orange]')

        # Prints the Logo Description -> "CRYPTOGRAPHY TOOL"
        print(f'[white]{logo_description}[/white]')

    else:
        # Prints the Logo and Description in Plaintext if the terminal isn't big enough.
        print(f'[dark_blue]Secu[/dark_blue][dark_orange]Crypt[/dark_orange]')
        print(f'[white]Cryptography Tool[/white]')


#------------------------------TEXT CONVERSIONS------------------------------#
def ascii_to_hex(ascii_string):
    # Converts a ASCII string into a hexadecimal code.

    # Encodes the string.
    encoded_text = ascii_string.encode() 

    # Converts the encoded text into its hexadeciaml representation. 
    hexlified_text = binascii.hexlify(encoded_text)

    # Decodes the text.
    decoded_text = hexlified_text.decode() 
    return decoded_text


def hex_to_bytes(hex_string):
    # Converts a hexadecimal string into a bytes object.

    unhexlified_text = binascii.unhexlify(hex_string)
    return unhexlified_text


#------------------------------CRYPOGRAPHY------------------------------#
# AES Encryption
def aes_encryption(): 
    # Encrypts text/information using the AES algorithm.

    running_status = True

    while running_status:
        # Prompts the user to enter a ASCII key.
        console.print("[bold red][INPUT][/bold red]", end = "\r")
        ascii_key = Prompt.ask("Enter an ASCII key (Must be 16, 24, or 32 characters)")

        # Checks if the inputted ASCII key is either 16, 24, or 32 characters long.
        key_length = len(ascii_key)
        if key_length not in [16, 24, 32]:
            console.print("[[bold red]ERROR[/bold red]] [white]The ASCII key must be 16, 24, or 32 characters long.[/white]")

        else:
            # Converts the ASCII key to its hexadecimal representation.
            hex_key = ascii_to_hex(ascii_key)

            # Converts the hexadecimal key to its bytes representation.
            bytes_key = hex_to_bytes(hex_key)

            # Creates a new AES object/cipher with the inputted key in bytes representation and in CBC mode.
            cipher_object = AES.new(bytes_key, AES.MODE_CBC)

            # Prompts the user to enter the information/plaintext to encrypt.
            console.print("[bold red][INPUT][/bold red]", end = "\r")
            plaintext_input = str(Prompt.ask("Enter the text/information to be encrypted")).encode()

            # Applies padding to the user's input.
            plaintext_input = pad(plaintext_input, AES.block_size)

            # Converts the plaintext to ciphertext/encrypted text.
            ciphertext = cipher_object.encrypt(plaintext_input)

            # Converts the encoded text into its hexadecimal representation.
            hexlified_cipher_text = binascii.hexlify(ciphertext)

            # Decode the encoded text.
            decoded_cipher_text = hexlified_cipher_text.decode()

            # Return the encrypted text in hexadecimals.
            return decoded_cipher_text


# DES Encryption
def des_encryption():
    # Encrypts text/information using the DES algorithm.

    running_status = True

    while running_status:
        # Prompts the user to enter a ASCII key.
        console.print("[bold red][INPUT][/bold red]", end = "\r")
        ascii_key = Prompt.ask("Enter an ASCII key (Must be 8 characters)")

        # Checks if the inputted ASCII key is exactly 8 characters long.
        key_length = len(ascii_key)
        if key_length != 8:
            console.print("[[bold red]ERROR[/bold red]] [white]The ASCII key must be 8 characters long.[/white]")

        else:
            # Converts the ASCII key to its hexadecimal representation.
            hex_key = ascii_to_hex(ascii_key)

            # Converts the hexadecimal key to its bytes representation.
            bytes_key = hex_to_bytes(hex_key)

            # Creates a new DES object/cipher with the inputted key in bytes representation and in CBC mode.
            cipher_object = DES.new(bytes_key, DES.MODE_CBC)

            # Prompts the user to enter the information/plaintext to encrypt.
            console.print("[bold red][INPUT][/bold red]", end = "\r")
            plaintext_input = str(Prompt.ask("Enter the text/information to be encrypted")).encode()

            # Applies padding to the user's input.
            plaintext_input = pad(plaintext_input, DES.block_size)

            # Converts the plaintext to ciphertext/encrypted text.
            ciphertext = cipher_object.encrypt(plaintext_input)

            # Converts the encoded text into its hexadecimal representation.
            hexlified_cipher_text = binascii.hexlify(ciphertext)

            # Decode the encoded text.
            decoded_cipher_text = hexlified_cipher_text.decode()

            # Return the encrypted text in hexadecimals.
            return decoded_cipher_text


# MD5 Encryption
def md5_encryption():
    # Encrypts text/information using the MD5 algorithm.

    running_status = True

    while running_status:
        # Prompts the user to enter the text/information to be encrypted.
        console.print("[bold red][INPUT][/bold red]", end = "\r")
        plaintext_input = Prompt.ask("Enter the text/information to be encrypted")

        # Checks if there is an user input.
        plaintext_length = len(plaintext_input)
        if plaintext_length == 0:
            console.print("[[bold red]ERROR[/bold red]] [white]No input was detected. Restarting...[/white]")

        else:
            # Converts the plaintext to its hexadecimal representation.
            hex_key = ascii_to_hex(plaintext_input)

            # Converts the plaintext to its bytes representation.
            bytes_key = hex_to_bytes(hex_key)

            # Creates a new MD5 object/hash with the inputted plaintext in bytes representation.
            hash_object = MD5.new(bytes_key)

            # Converts the plaintext to hashtext/encrypted text.
            hash_text = hash_object.hexdigest()

            # Returns the digest of the hashed text/information.
            return hash_text


# SHA-1 Encryption
def sha_1_encryption():
    # Encrypts text/information using the SHA-1 algorithm.

    running_status = True

    while running_status:
        # Prompts the user to enter the text/information to be encrypted.
        console.print("[bold red][INPUT][/bold red]", end = "\r")
        plaintext_input = Prompt.ask("Enter the text/information to be encrypted")

        # Checks if there is an user input.
        plaintext_length = len(plaintext_input)
        if plaintext_length == 0:
            console.print("[[bold red]ERROR[/bold red]] [white]No input was detected. Restarting...[/white]")

        else:
            # Converts the plaintext to its hexadecimal representation.
            hex_key = ascii_to_hex(plaintext_input)

            # Converts the plaintext to its bytes representation.
            bytes_key = hex_to_bytes(hex_key)

            # Creates a new SHA-1 object/hash with the inputted plaintext in bytes representation.
            hash_object = SHA1.new(bytes_key)

            # Converts the plaintext to hashtext/encrypted text.
            hash_text = hash_object.hexdigest()

            # Returns the digest of the hashed text/information.
            return hash_text


# SHA-256 Encryption
def sha_256_encryption():
    # Encrypts text/information using the SHA-256 algorithm.

    running_status = True

    while running_status:
        # Prompts the user to enter the text/information to be encrypted.
        console.print("[bold red][INPUT][/bold red]", end = "\r")
        plaintext_input = Prompt.ask("Enter the text/information to be encrypted")

        # Checks if there is an user input.
        plaintext_length = len(plaintext_input)
        if plaintext_length == 0:
            console.print("[[bold red]ERROR[/bold red]] [white]No input was detected. Try Again.[/white]")

        else:
            # Converts the plaintext to its hexadecimal representation.
            hex_key = ascii_to_hex(plaintext_input)

            # Converts the plaintext to its bytes representation.
            bytes_key = hex_to_bytes(hex_key)

            # Creates a new SHA-256 object/hash with the inputted plaintext in bytes representation.
            hash_object = SHA256.new(bytes_key)

            # Converts the plaintext to hashtext/encrypted text.
            hash_text = hash_object.hexdigest()

            # Returns the digest of the hashed text/information.
            return hash_text


#------------------------------MAIN MENU------------------------------#

def main_menu():
    
    # Main Menu Start Up
    menu_running = True

    while menu_running:
        display_logo() # Displays the Logo.

        # Prints the Main Menu Options
        console.print("[[bold blue]1[/bold blue]] [white]AES Encryption[/white]")
        console.print("[[bold blue]2[/bold blue]] [white]DES Encryption[/white]")
        console.print("[[bold blue]3[/bold blue]] [white]MD5 Encryption[/white]")
        console.print("[[bold blue]4[/bold blue]] [white]SHA-1 Encryption[/white]")
        console.print("[[bold blue]5[/bold blue]] [white]SHA-256 Encryption[/white]")
        console.print("[[bold blue]6[/bold blue]] [white]Exit[/white]")

        # Prompts the user to choose one of the Main Menu Options.
        selection = input("\nSelect an option by entering the corresponding number (1 to 6): ")

        # Performs the encryption/decryption based on the user's input/selection.
        if selection == '1':
            console.print("[bold blue][AES OUTPUT][/bold blue]", end = "\r")
            console.print(aes_encryption())
        elif selection == '2':
            console.print("[bold blue][DES OUTPUT][/bold blue]", end = "\r")
            console.print(des_encryption())
        elif selection == '3':
            console.print("[bold blue][MD5 OUTPUT][/bold blue]", end = "\r")
            console.print(md5_encryption())
        elif selection == '4':
            console.print("[bold blue][SHA-1 OUTPUT][/bold blue]", end = "\r")
            console.print(sha_1_encryption())
        elif selection == '5':
            console.print("[bold blue][SHA-256 OUTPUT][/bold blue]", end = "\r")
            console.print(sha_256_encryption())
        else:
            console.print("[[bold red]EXIT[/bold red]] Exiting...")
            console.print("[[bold red]EXIT[/bold red]] Program Successfully Exited.")
            break

        # Prompts the user to choose to go back to the Main Menu.
        user_input = Prompt.ask("Back to Main Menu [Y/N]: ")
        if (user_input == 'Y') or (user_input == 'y'):
            console.print("[[bold red]EXIT[/bold red]] Returning to Main Menu...")
            console.print("[[bold red]EXIT[/bold red]] Successfully returned to Main Menu.")
            main_menu()
        else:
            console.print("[[bold red]EXIT[/bold red]] Exiting...")
            console.print("[[bold red]EXIT[/bold red]] Program Successfully Exited.")
            break


if __name__ == "__main__":
    main_menu()