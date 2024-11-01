import argparse  
import subprocess  
import sys  

# Function to run the port scanner tool
def port_scanner():
    from port_scanner import menu  # Import menu from the port scanner module
    menu()

# Function to run the shellcode encryption tool with optional shellcode input
def shellcode_encryptor(shellcode=None):
    if shellcode:
        subprocess.run([sys.executable, 'shellcode_encryptor.py', shellcode])  # Run with provided shellcode
    else:
        print("No shellcode provided. Running interactively.")
        subprocess.run([sys.executable, 'shellcode_encryptor.py'])  # Run interactively if no shellcode provided

# Function to run crypto tool for file encryption/decryption with optional arguments
def crypto_tool(command=None, file_path=None):
    if command and file_path:
        subprocess.run([sys.executable, 'crypto_tool.py', command, file_path])  # Run with command and file path
    else:
        print("Running crypto tool interactively.")
        subprocess.run([sys.executable, 'crypto_tool.py'])  # Run interactively if arguments are missing

# Function to run the HTML smuggling tool
def html_smuggling():
    # Run the HTML smuggling script to generate smuggled HTML content
    subprocess.run([sys.executable, 'html_smuggling.py'])

# Main function to parse arguments and provide an interactive menu
def main():
    parser = argparse.ArgumentParser(description="Toolbox for penetration testing and IT security.")
    parser.add_argument("--tool", choices=["port_scanner", "shellcode_encryptor", "crypto_tool", "html_smuggling"],
                        help="Select a tool to run directly.")
    parser.add_argument("--shellcode", help="Shellcode (in hex) to encrypt (used with shellcode_encryptor).")
    parser.add_argument("--command", choices=["encrypt", "decrypt"],
                        help="Specify encrypt or decrypt for crypto_tool.")
    parser.add_argument("--file", help="File path for encryption/decryption (used with crypto_tool).")

    args = parser.parse_args()

    # Run specified tool directly if command-line argument is given
    if args.tool == "port_scanner":
        port_scanner()
    elif args.tool == "shellcode_encryptor":
        shellcode_encryptor(args.shellcode)
    elif args.tool == "crypto_tool":
        crypto_tool(args.command, args.file)
    elif args.tool == "html_smuggling":
        html_smuggling()
    else:
        # Interactive menu for tool selection
        while True:
            print("\nMain Toolbox Menu:")
            print("1. Run Port Scanner")
            print("2. Run Shellcode Encryptor")
            print("3. Run Crypto Tool")
            print("4. Run HTML Smuggling Tool")
            print("5. Exit")

            choice = input("\nEnter your choice: ")

            if choice == '1':
                port_scanner()
            elif choice == '2':
                shellcode = input("Enter shellcode (in hex) to encrypt, or leave empty for interactive mode: ")
                shellcode_encryptor(shellcode)
            elif choice == '3':
                command = input("Enter command (encrypt/decrypt), or leave empty for interactive mode: ")
                file_path = input("Enter file path, or leave empty for interactive mode: ")
                crypto_tool(command, file_path)
            elif choice == '4':
                html_smuggling()
            elif choice == '5':
                print("Exiting toolbox.")
                break
            else:
                print("Invalid choice. Please try again.")

# Entry point for the script
if __name__ == "__main__":
    main()
