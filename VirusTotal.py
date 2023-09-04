#VirusTotal is used to analyse suspicious files, domains, IPs and URLs to detect malware and other breaches
#Don't entirely depend upon this tool, check GUI for community page, other sources to ensure safety. 
import requests
import csv
from bs4 import BeautifulSoup

API_KEY='...'		#Set up an api_key to get results.

def scan_ip(ip_address):
	ip_scan_endpoint= 'https://www.virustotal.com/vtapi/v2/ip-address/report'
	params= {
	    'apikey': API_KEY,
	    'ip' : ip_address
	}

	response = requests.get(ip_scan_endpoint, params = params)
	return response.json()

def extract_detection_info(scan_result):
	detection_count = scan_result.get('detected_communicating_samples', 0)	
	scan_date = scan_result.get('scan_date', '')
	return detection_count, scan_date

if __name__=='__main__':
	ips_to_scan = ['8.8.8.8', '142.250.195.14'] 	# IPs to scan 

	results=[]
	
	for ip in ips_to_scan:
		ips_result =scan_ip(ip)
		detection_count,scan_date = extract_detection_info(ips_result)
		results.append({'IP': ip, 'Detection Count': detection_count,'Scan Date': scan_date})

	#Writing results into a CSV file. CSV file may be more useful. Example-when using pandas library for data analysis
	csv_path = 'ip_scan_results.csv'
	with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
		fieldnames = ['IP','Detection Count', 'Scan Date']
		csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
		csv_writer.writeheader()
		csv_writer.writerows(results)

	print(f"IP scan results in '{csv_path}")
