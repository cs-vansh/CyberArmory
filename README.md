# CyberArmory

![Command_Line_Interface](https://github.com/cs-vansh/Tools/assets/104628209/d3bb2336-2531-462b-9601-61fed2e8fa83)

## Introduction

Welcome to the CyberArmory, a collection of cybersecurity tools developed in Python. This suite includes a comprehensive collection of cybersecurity tools designed to address various aspects of network security, reconnaissance, analysis and automation. Developed in Python, these tools cover a range of functionalities as described below.

## Tools

1. **IP Geolocator**
   - Geolocate an IP address using the GeoLite2 City database.

2. **VirusTotal Scan**
   - Scan one or more IP addresses using the VirusTotal API and retrieve detection information.

3. **Recursive Directory Lister**
   - List files with a specific extension in a directory and its subdirectories.

4. **SYN Flood**
   - Perform a SYN flood attack on a target IP address.

5. **WHOIS Lookup**
   - Lookup WHOIS information for a domain name or IP address.

6. **IP WHOIS**
   - Perform an IP WHOIS lookup using the IPWhois library.

7. **Dictionary Pass Cracker**
   - Crack passwords using a dictionary attack.

8. **Brute Force Pass Cracker**
   - Crack passwords using a brute-force attack.
     
<br>

![Level-0 DFD](https://github.com/cs-vansh/CyberArmory/assets/104628209/99c06f83-8249-444d-9480-98283772588e)
*Level-0 DFD*

<br>

![Level-1 DFD](https://github.com/cs-vansh/CyberArmory/assets/104628209/c4b88171-d27f-4523-be08-7a476813f227)
*Level-1 DFD*

<br>

## Disclaimer

Only proceed if you're fully aware of the potential consequences. Keep in mind that wielding these tools without caution may cause unintended effects. It's your responsibility to use them ethically and within the bounds of the law.

## Usage

1. **Requirements**
   - Ensure you have Python installed on your system.
   - Install required libraries using `pip install -r requirements.txt`.

2. **Execution**
   - Run the `CyberArmory.py` script.
   - Choose a tool by entering the corresponding serial number.

3. **Tool-Specific Instructions**
   - For **IP Geolocator**, there is a requirement to download the GeoLite Database(.mmdb file format) by referring to this [MaxMind article](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and then provide the path to the database in the code itself.
   - For using **VirusTotal Scan**, there is a need to create an API Key on the VirusTotal Website and then put that key into the code.
   - Each tool may prompt you for additional input (e.g., IP addresses, file paths, etc.).
   - Follow on-screen instructions for each tool.

## Research and Development

CyberArmory is an actively developed project. Ongoing research and development aim to introduce more tools and enhance the capabilities of the existing ones. Stay tuned for updates!!
