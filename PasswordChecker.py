#There are databases of all leaked usernames/passwords
#Hashing - save passwords through a hashing algorithm so it saves it as a encrypted password
#API uses SHA1
#K-anonymity: Allows someone to recieve information about us without giving away our identity

import requests #allows us to make a requests - basically a browser
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # our API with hashed password
    res = requests.get(url)
    if res.status_code != 200: #code 200 means that password hash (5 letters) has matched PWNED passwords database
        raise RuntimeError(f"Error fetching: {res.status_code}", "check api and try again")
    return res #returns the status code

def get_passwords_leaks_count(hashes,hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines()) #hashes.text have the entire encrypted number:number of times it was accessed
    # created a tuple and split it based on the hash:number of times
    for h,count in hashes: # h is the tail, and count is the number of times
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    #check if password exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() # .encode creates it into sha1 object, hexdigest converts object into string

    first5_char, tail = sha1password[:5],sha1password[5:] # grab first 5 characters and the rest
    response = request_api_data(first5_char) # send first 5 char to API, if we get 200, it means its working
    return get_passwords_leaks_count(response, tail)

def main(args): #passwords we want to check
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times... you should probably change your password!")
        else:
            print(f"{password} was NOT found. Carry on!")
    return "done"

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


