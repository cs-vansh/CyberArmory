import hashlib

def read_dictionary(file_path):
    try:
        with open(file_path,'r') as file:
            return [line.strip() for line in file] # returns a list, [] brackets for list 
    except FileNotFoundError:
        print(f"Error: Dictionary file '{file_path}' not found.")
        return []
    
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  #SHA-256 algorithm encoding,conversion to hexadecimal and return as string

def crack_password(target_hash, dictionary):
    for word in dictionary:
        hashed_word = hash_password(word);
        if hashed_word == target_hash:
            return word
    return None

if __name__ == "__main__":
    target_hash = input("Enter the target hash to crack: ") #Hash to crack
    dictionary_file = input("Enter the path to the dictionary file: ") #Path to the dictionary file

    
    dictionary= read_dictionary(dictionary_file)
    if dictionary:
        print("Dictionary loaded successfully.")
        print("Attempting to crack the password...")
        
        cracked_password = crack_password(target_hash, dictionary)
    
        if cracked_password: # true if there is a value in cracked_password variable i.e. a password was cracked
            print(f"Password Cracked! The password is: {cracked_password}")
        else:
            print("Password not found in the dictionary.")
    else:
        print("Unable to proceed without a valid dictionary.")

