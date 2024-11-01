from cryptography.fernet import Fernet
import argparse

def generate_key():
    # Generate a new encryption key and return it as a bytes object.
    return Fernet.generate_key()

def encrypt_shellcode(shellcode, key):
    # Encrypt the given shellcode using the provided key.
    fernet = Fernet(key)
    encrypted_shellcode = fernet.encrypt(shellcode)
    return encrypted_shellcode

def format_as_c_array(data, array_name):
    # Convert byte data to a C-compatible char array.
    c_array = ', '.join(f'0x{byte:02x}' for byte in data)
    return f'unsigned char {array_name}[] = {{ {c_array} }};'

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Encrypt shellcode and output as C arrays.")
    parser.add_argument("shellcode", help="The shellcode to encrypt (hex string format).")
    
    args = parser.parse_args()

    # Convert the shellcode hex string to bytes
    shellcode_bytes = bytes.fromhex(args.shellcode)

    # Generate a key and encrypt the shellcode
    key = generate_key()
    encrypted_shellcode = encrypt_shellcode(shellcode_bytes, key)

    # Format both the key and the encrypted shellcode as C arrays
    key_c_array = format_as_c_array(key, "encryption_key")
    encrypted_shellcode_c_array = format_as_c_array(encrypted_shellcode, "encrypted_shellcode")

    # Print the output C arrays
    print("\nGenerated C code:\n")
    print(key_c_array)
    print()
    print(encrypted_shellcode_c_array)

if __name__ == "__main__":
    main()