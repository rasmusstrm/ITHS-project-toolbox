###### Project Toolbox ######
The project toolbox integrates all tools into a single interface for comprehensive penetration testing support. Use the toolbox to select and run any of the four tools based on the desired test type.

## Features

The Project Toolbox is a command-line interface for various penetration testing and IT security tools. It integrates the following four modules:

- **Port Scanner**: Scans specified IP addresses and ports to identify open ports and potential vulnerabilities.
- **Shellcode Encryptor**: Encrypts provided shellcode to evade detection or simplify encoding.
- **Crypto Tool**: Offers file encryption and decryption using standard cryptographic algorithms.
- **HTML Smuggling**: Generates HTML content designed for evading network security to deliver payloads in HTML format.

## Requirements

- Python 3.x
- Required libraries for each tool (see `requirements.txt`) 

### Usage
Run the project_toolbox.py and follow on-screen instructions to select a tool.

Example:
    python main_script.py
    Enter choice: 1 for Nmap Port Scanner

## Example Output
Main Toolbox Menu:
1. Run Port Scanner
2. Run Shellcode Encryptor
3. Run Crypto Tool
4. Run HTML Smuggling Tool
5. Exit

Enter your choice: 1

Running Port Scanner...

## Known Limitations
- **Permissions**: Network scanning and encryption require administrative privileges; limited user permissions may restrict functionality.
- **Error Handling**: Limited error handling in the interactive mode for invalid inputs. Unexpected arguments may cause the toolbox to exit.
- **Resource Intensive**: Some tools, particularly those performing network scans or encryption tasks, may consume significant CPU and memory resources.



###### Nmap Port Scanner Tool ######

A simple Python-based port scanner using the Nmap library to aid in penetration testing and network security analysis.
You can run the script in two ways: via command-line arguments or interactively through the user menu.

## Features
- **Single IP Scan**: Scan a single IP address.
- **Batch IP Scan**: Scan multiple IPs listed in a file.
- **Save Results**: Save IPs and scan results to specified text files.
- **File Management**: View or list saved IP and scan result files.
- **Command-Line Usage**

## Requirements
- Python 3.x
- `nmap` package (install via `pip install python-nmap`).
- Nmap tool installed on your machine.

## Usage
1. **Single IP Scan**:
   - Run the script and choose option `1`.
   - Enter the IP address and specify scan type (`-sS`, `-Pn`, etc.).
   - Choose to save the IP and/or scan result.

Example:
    python port_scanner.py
    Enter choice: 1
    Enter IP: 192.168.1.1
    Enter scan type: -Pn


2. **Batch Scan (Multiple IPs)**:
- Save IP addresses in a text file (e.g., `ips.txt`).
- Run the script, choose option `2`, and specify the filename.
- Choose to save each IP’s results individually.

Example:
    python port_scanner.py
    Enter choice: 2
    Enter filename with IPs: ips.txt
    Enter scan type: -sS

3. **View Saved Files**:
- Select option `3` to view the contents of previously saved IPs or scan result files.

4. **Command-Line Usage**:

Example:
    python port_scanner.py --scan-ip 192.168.1.1 --scan-type "-sS" --save-ip "saved_ips.txt" --save-result "scan_results.txt"


## Example Output
Host: 10.2.10.22
State: up

TCP Ports:
Port: 80, State: open, Service: http
Port: 135, State: open, Service: msrpc
Port: 139, State: open, Service: netbios-ssn
Port: 445, State: open, Service: microsoft-ds
Port: 1433, State: open, Service: ms-sql-s
Port: 3389, State: open, Service: ms-wbt-server
Port: 5985, State: open, Service: wsman
Port: 5986, State: open, Service: wsmans

Do you want to (1) save the IP address, (2) save the scan result, (3) save both, or (4) not save anything? (Enter 1, 2, 3, or 4):

## Known Limitations
- **Permissions**: Some scans (e.g., SYN scan) may require root privileges.
- **Error Handling**: Ensure Nmap is installed; otherwise, scans will fail.
- **Resource Intensive**: Large batch scans may consume significant time and resources. May also require root privileges for SYN scans and other advanced types.



###### Shellcode Encryptor ######

The `shellcode_encryptor` is a Python tool designed for encrypting shellcode in hexadecimal format for secure penetration testing, outputting the encryption key and encrypted shellcode as C-compatible byte arrays. This can enhance the obfuscation of shellcode for testing purposes.

## Features
- Encrypts shellcode provided as a hex string.
- Generates a unique encryption key.
- Outputs the encryption key and encrypted shellcode as C-compatible arrays.

## Requirements
- Python 3.x
- `cryptography` library (install via `pip install cryptography`)

## Usage
Run the tool with a hex-formatted shellcode string.
Example: python shellcode_encryptor.py <shellcode>

## Example Output
unsigned char encryption_key[] = { 0x5f, 0xa8, 0x3d, ... };
unsigned char encrypted_shellcode[] = { 0x45, 0x3c, 0xd4, ... };

## Known Limitations
- **Permissions**: Encrypts only hex-formatted shellcode; other formats must be converted first.
- **Error Handling**: Does not store the key; the generated key must be saved separately to decrypt the shellcode.
- **Resource Intensive**: Large shellcode inputs may lead to high memory usage and slow performance during encryption.



###### Crypto Tool ######

## Features
- Secure file encryption and decryption using the Fernet symmetric encryption method.
- Simple command-line interface for encrypting and decrypting files.
- Automatically handles file extensions for encrypted and decrypted files.

## Requirements
- Python 3.x
- `cryptography` library (install via `pip install cryptography`)

## Usage
1. **Generate a Key**: Before using the tool, generate a key using the provided `generate_key.py` script.

2. **Encrypt a File**:
- python crypto_tool.py encrypt <file_path>

3. **Decrypt a File**:
- python crypto_tool.py decrypt <file_path.encrypted>

## Example Output
- Encrypting a file: $ python crypto_tool.py encrypt my_file.txt File 'my_file.txt' has been encrypted and saved as 'my_file.txt.encrypted'.
- Decrypting a file: $ python crypto_tool.py decrypt my_file.txt.encrypted File 'my_file.txt.encrypted' has been decrypted and saved as 'my_file.txt.decrypted'.

## Known Limitations
- **Permissions**: The tool requires the presence of a valid key file (`secret.key`). Ensure it exists before running encryption or decryption.
- **Error Handling**: Encrypted files must have the `.encrypted` extension for successful decryption.
- **Resource Intensive**: If the decryption process encounters an error, it may not provide detailed feedback on the issue.



###### HTML Smuggler Tool ######

## Features
- Encodes and embeds sensitive content (e.g., images) into HTML files.
- Generates a downloadable link to the embedded content.
- Utilizes JavaScript to create Blob URLs for the embedded data.

## Requirements
- Python 3.x
- `jsmin` library: Install using `pip install jsmin`
- `Jinja2` library: Install using `pip install Jinja2`

## Usage
1. Ensure `smuggled_content.txt` contains the Base64 encoded data to be embedded.
2. Run the script: python html_smuggling.py
3. Open the generated def_not_malicious_content.html file in a web browser.
4. Click the "SUPER SAFE LINK TO CLICK!!!" to view the embedded content.
5. `smuggled_content.txt` can be customized to contain any file the user chooses, as long as it is in base64 format. 

## Example Output
HTML smuggling file created: def_not_malicious_content.html

## Known Limitations
- **Permissions**: Ensure that you have read access to `smuggled_content.txt` and write permissions in the directory where the script runs.
- **Error Handling**: The script does not handle exceptions for file read/write operations. Ensure files exist and are correctly formatted.
- **Resource Intensive**: For very large Base64 encoded content, performance may degrade due to memory constraints and processing time.