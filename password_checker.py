import requests
from hashlib import sha1
import sys


def request_api_data(query):
    url = "https://api.pwnedpasswords.com/range/" + query

    # pulls all api database values that match query
    response = requests.get(url)

    # request status code: OK 200 = The request was fulfilled
    if response.status_code != 200:
        raise RuntimeError(f"URL request error: {response.status_code}")
    else:
        return response


def format_password(password):
    # encodes password and converts it to SHA1 hash as uppercase hexadecimal
    sha1_password = sha1(password.encode("utf-8"))
    sha1_password_hex = sha1_password.hexdigest().upper()

    # splits hashed password as only first 5 characters are sent as query for data security
    first5_char, tail = sha1_password_hex[:5], sha1_password_hex[5:]

    return first5_char, tail


def pwned_api_check(password):
    # see format_password function for format details
    formatted_password = format_password(password)
    first5_char, tail = formatted_password[0], formatted_password[1]

    # grabs the tails of all hashes with matching first 5 characters
    response = request_api_data(first5_char)

    return get_leaks_count(response, tail)


def get_leaks_count(response_hashes, hash_to_check):
    # converts into a list of lines, breaking at line boundaries
    hashes_list = response_hashes.text.splitlines()

    # converts into tuple in the format: hash, count
    hashes_tuples = (line.split(":") for line in hashes_list)

    for h, count in hashes_tuples:
        # if hash is found, returns count
        if h == hash_to_check:
            return count
    # if hash not found, then password is secure
    return 0


def main():
    # checks if passwords are already given as arguments
    if len(sys.argv) > 1:
        passwords = sys.argv[1:]
    else:
        # if not, asks user for passwords
        passwords = []
        num_passwords = int(input("How many passwords would you like to test? "))
        print()
        for password in range(num_passwords):
            passwords.append(input(f"Enter password {password + 1}: "))

    print()
    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was compromised by {count} data breaches")
        else:
            print(f"{password} has never been compromised!")


if __name__ == "__main__":
    main()
    sys.exit()
