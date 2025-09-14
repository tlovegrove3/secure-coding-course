"""
Program: Caesar Cipher
Author: Terry Lovegrove
Date: 2025-09-14
Description: Implement a Caesar cipher using substitution for encryption and decryption of messages.

"""
# Constants
FIRST_CHAR_CODE = ord('A')  # ASCII code for 'A'
LAST_CHAR_CODE = ord('Z')  # ASCII code for 'Z'
CHAR_RANGE = LAST_CHAR_CODE - FIRST_CHAR_CODE + 1  # Number of letters in the alphabet

def caesar_shift(message, shift):

    # Result placeholder
    result = ""

    # Go through each of the letters in the message. 
    for char in message.upper():
        # Convert character to ASCII number
        char_code = ord(char)
        if char.isalpha():
            shifted_char = char_code + shift
            if shifted_char > LAST_CHAR_CODE:
                shifted_char -= CHAR_RANGE

            elif shifted_char < FIRST_CHAR_CODE:
                shifted_char += CHAR_RANGE
            new_char = chr(shifted_char)
            result += new_char
        else:
            result += char
    print(result)

user_message = input("Message to Encrypt/Decrypt: ")
user_shift_key = int(input("Shift Key (positive or negative integer): "))
caesar_shift(user_message, user_shift_key)

