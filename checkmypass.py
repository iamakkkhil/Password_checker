import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # hashed password with only the 1st 5 values
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching : {res.status_code}, check the api and try again')
    return res


# def read_res(response):
#     print(response.text)


def get_pass_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # print(hashlib.sha1(password.encode('utf-8')).
    sha1pass = hashlib.sha1(password.encode('utf -8')).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = request_api_data(first5_char)
    return get_pass_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} many times, I\'d advice you to change it')
        else:
            print(f'{password} was not found; It is a safe one')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))