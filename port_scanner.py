import nmap
import os  
import argparse  

def scan_host(host, scan_type='-Pn --unprivileged'):
    # Perform a scan on the specified host with the given scan type.
    nm = nmap.PortScanner()
    print(f"Scanning IP: {host} with scan type: {scan_type}")  # Debug: Display IP and scan type
    result = nm.scan(host, arguments=scan_type)
    return result

def format_scan_result(result):
    # Format scan result for display.
    if 'scan' not in result or not result['scan']:
        return "No scan results found."
    
    host_info = result['scan'].popitem()  # Get first scanned host's data
    ip, details = host_info

    output = [f"\nHost: {ip}", f"State: {details['status']['state']}"]

    # Append TCP ports details if available
    if 'tcp' in details:
        output.append("\nTCP Ports:")
        for port, port_info in details['tcp'].items():
            output.append(f"Port: {port}, State: {port_info['state']}, Service: {port_info.get('name', 'unknown')}")

    # Append UDP ports details if available
    if 'udp' in details:
        output.append("\nUDP Ports:")
        for port, port_info in details['udp'].items():
            output.append(f"Port: {port}, State: {port_info['state']}, Service: {port_info.get('name', 'unknown')}")

    return "\n".join(output)

def save_scan_result_to_file(ip, result, filename):
    # Save formatted scan result to a file.
    try:
        with open(filename, 'a') as file:
            file.write(f"\nResult of scanning IP {ip}:\n{result}\n")
        print(f"Scan result saved to {filename}")
    except Exception as e:
        print(f"Failed to save result to file: {e}")

def save_ip_to_file(ip, filename):
    # Save IP address to a file.
    try:
        with open(filename, 'a') as file:
            file.write(f"{ip}\n")
        print(f"IP address saved to {filename}")
    except Exception as e:
        print(f"Failed to save IP address to file: {e}")

def read_ips_from_file(filename):
    # Read IP addresses from a specified file.
    try:
        with open(filename, 'r') as file:
            ips = file.read().splitlines()  # Read each line as an IP
        if not ips:
            print(f"The file {filename} is empty.")
        return ips
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

def read_file_content(filename):
    # Read and display content from a file.
    try:
        with open(filename, 'r') as file:
            content = file.read()
        print(f"\nContent of {filename}:\n{content}")
    except FileNotFoundError:
        print(f"File {filename} not found.")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

def list_text_files(directory):
    # List all text files in a specified directory."""
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.txt')]
        if not files:
            print("No text files found in the directory.")
        else:
            print("\nAvailable text files:")
            for i, file in enumerate(files):
                print(f"{i + 1}. {file}")
        return files
    except Exception as e:
        print(f"An error occurred while listing files: {e}")
        return []

def menu():
    # Display a menu for user input and handle choices.
    while True:
        print("\nNmap Scanner Menu:")
        print("1. Scan a single IP")
        print("2. Scan multiple IPs from a file")
        print("3. Read and display a text file")
        print("4. Exit")

        choice = input("\nEnter your choice: ")

        if choice == '1':
            ip = input("\nEnter the IP address to scan: ")
            scan_type = input("Enter the scan type (e.g., '-sS', '-sU', '-Pn'): ") or '-Pn --unprivileged'
            if ip:
                result = scan_host(ip, scan_type)
                formatted_result = format_scan_result(result)
                print(formatted_result)
            else:
                print("Invalid IP address, please enter a valid IP.")

            # Prompt to save IP, scan result, or both
            save_option = input("\nDo you want to (1) save the IP address, (2) save the scan result, (3) save both, or (4) not save anything? (Enter 1, 2, 3, or 4): ")
            
            if save_option == '1':
                filename = input("Enter the filename to save the IP (e.g., 'ip_address.txt'): ")
                save_ip_to_file(ip, filename)
            elif save_option == '2':
                filename = input("Enter the filename to save the scan result (e.g., 'scan_result.txt'): ")
                save_scan_result_to_file(ip, formatted_result, filename)
            elif save_option == '3':
                ip_filename = input("Enter the filename to save the IP (e.g., 'ip_address.txt'): ")
                scan_filename = input("Enter the filename to save the scan result (e.g., 'scan_result.txt'): ")
                save_ip_to_file(ip, ip_filename)
                save_scan_result_to_file(ip, formatted_result, scan_filename)

        elif choice == '2':
            filename = input("Enter the filename containing IP addresses: ")
            ips = read_ips_from_file(filename)

            if ips:
                scan_type = input("Enter the scan type (e.g., '-sS', '-sU', '-Pn'): ") or '-Pn --unprivileged'
                for ip in ips:
                    result = scan_host(ip, scan_type)
                    formatted_result = format_scan_result(result)
                    print(formatted_result)

                    # Prompt to save IP, scan result, or both for each IP
                    save_option = input(f"Do you want to (1) save the IP address, (2) save the scan result, (3) save both, or (4) not save anything for {ip}? (Enter 1, 2, 3, or 4): ")
                    if save_option == '1':
                        filename = input("Enter the filename to save the IP (e.g., 'ip_address.txt'): ")
                        save_ip_to_file(ip, filename)
                    elif save_option == '2':
                        filename = input("Enter the filename to save the scan result (e.g., 'scan_result.txt'): ")
                        save_scan_result_to_file(ip, formatted_result, filename)
                    elif save_option == '3':
                        ip_filename = input("Enter the filename to save the IP (e.g., 'ip_address.txt'): ")
                        scan_filename = input("Enter the filename to save the scan result (e.g., 'scan_result.txt'): ")
                        save_ip_to_file(ip, ip_filename)
                        save_scan_result_to_file(ip, formatted_result, scan_filename)

        elif choice == '3':
            directory = '.'  # Current directory
            text_files = list_text_files(directory)
            if text_files:
                choice = input("Enter the number of the file you want to read: ")
                try:
                    file_index = int(choice) - 1
                    if 0 <= file_index < len(text_files):
                        filename = text_files[file_index]
                        read_file_content(filename)
                    else:
                        print("Invalid selection.")
                except ValueError:
                    print("Please enter a valid number.")

        elif choice == '4':
            print("Exiting the program.")
            break
        else:
            print("\nInvalid choice, please try again.")

def main(args):
    # Run the scanner based on command-line arguments or display menu.
    if args.scan_ip:
        scan_type = args.scan_type or '-Pn --unprivileged'
        result = scan_host(args.scan_ip, scan_type)
        formatted_result = format_scan_result(result)
        print(formatted_result)

        if args.save_ip:
            save_ip_to_file(args.scan_ip, args.save_ip)
        if args.save_result:
            save_scan_result_to_file(args.scan_ip, formatted_result, args.save_result)
    
    elif args.scan_file:
        ips = read_ips_from_file(args.scan_file)
        if ips:
            scan_type = args.scan_type or '-Pn --unprivileged'
            for ip in ips:
                result = scan_host(ip, scan_type)
                formatted_result = format_scan_result(result)
                print(formatted_result)

                if args.save_ip:
                    save_ip_to_file(ip, args.save_ip)
                if args.save_result:
                    save_scan_result_to_file(ip, formatted_result, args.save_result)
        else:
            print("No IP addresses to scan. Please check the file content or file path.")
    else:
        menu()

if __name__ == "__main__":
    # Initialize an argument parser for command-line options and define command-line arguments for IP scan, file scan, scan type, and output file options.
    parser = argparse.ArgumentParser(description="Nmap Scanner")
    parser.add_argument('-ip', '--scan-ip', type=str, help='IP address to scan')
    parser.add_argument('-f', '--scan-file', type=str, help='File containing IP addresses to scan')
    parser.add_argument('-s', '--scan-type', type=str, help='Scan type (e.g., "-sS", "-sU", "-Pn")')
    parser.add_argument('--save-ip', type=str, help='File to save scanned IP address')
    parser.add_argument('--save-result', type=str, help='File to save scan result')

    args = parser.parse_args()
    main(args)