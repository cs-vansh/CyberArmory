from geoip2 import database
a="..."   # IP to track

database_path = '...' # Download Geolite Database(eg. name-GeoLite2-City.mmdb) and give its path here

def get_ip_location(ip_address):
	reader = database.Reader(database_path)
	try:
		response = reader.city(ip_address)
		country = response.country.name
		city = response.city.name
		latitude = response.location.latitude
		longitude = response.location.longitude
		
		print(f"IP: {ip_address}\n Country:{country}\nCity: {city}\nLatitude: {latitude}\nLongitude: {longitude}")
	except Exception as e:
		print("Error:",e)
	finally:
		reader.close()
	
if __name__ == "__main__":
	ip_to_lookup = a
	get_ip_location(ip_to_lookup)
	
