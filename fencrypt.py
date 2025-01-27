#!/usr/bin/env python3

import os
import sys
import json
import hmac
import hashlib
import argparse
import secrets
import regex as re
from os.path import exists, isfile, join
from getpass import getpass
from unicodedata import normalize
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def take_arguments():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', action='store_true')
    group.add_argument('-d', action='store_true')
    parser.add_argument('-j', action='store_true')
    parser.add_argument('-s', action='store_true')
    parser.add_argument('vars', metavar='N', type=str, nargs='*')
    args = parser.parse_args()

    # Handle args and return list depending on what was provided
    if args.e and len(args.vars) > 0:
        if args.j:
            return ['e', 'j', args.vars]
        else:
            return ['e', args.vars]
    elif args.d and len(args.vars) > 0:
        if args.j:
            return ['d', 'j', args.vars]
        else:
            return ['d', args.vars]        
    elif args.s:
        if args.e or args.d or args.j:
            print("-s must be used without other arguments")
            exit()
        elif len(args.vars) < 1:
            print("No search terms provided")
            exit()
        else:
            return ['s', args.vars]
    else:
        print("Parser error")
        exit(1)


def encrypt_files(files, password, json_output):
    json_file_metadata = {}
    for file in files:
        # Generate keys
        salt = secrets.token_bytes(16)
        master_key = generate_master_key(password, salt)
        json_file_metadata[file] = master_key.hex()
        validator, f1, f2, f3, f4, mac, search_term_key = kdf(master_key[:16], master_key[16:])

        # Create metadata
        metadata_file = {}
        metadata_file['salt'] = salt.hex()
        metadata_file['validator'] = validator.hex()

        #metadata_file['mac'] = mac.hex()
        # Read in file
        with open(file, 'rb') as f:
            data = f.read()

        encr_output = encrypt(f1, f2, f3, f4, data)
        metadata_file['mac'] = hmac.new(mac, encr_output, digestmod=hashlib.sha256).hexdigest()

        if check_utf8(data):
            search_terms = casefold_and_normalize(data.decode())
            dup_removed = []
            # Remove duplicates
            [dup_removed.append(i) for i in search_terms if i not in dup_removed]
            hex_term_list = []
            for term in dup_removed:
                hex_term_list.append(hmac.new(search_term_key, msg=bytes(term, encoding='utf8'), digestmod=hashlib.sha256).hexdigest())

            metadata_file['terms'] = hex_term_list
        else:
            metadata_file['terms'] = []

        json_metadata = json.dumps(metadata_file)

        # Save metadata to JSON file
        with open(f".fenc-meta.{file}", 'w') as outfile:
            outfile.write(json_metadata)

        # Encrypt file
        with open(f'{file}', 'wb') as f:
            f.write(encr_output)

    if json_output:
        json_to_write = json.dumps(json_file_metadata)
        sys.stdout.write(json_to_write)


def decrypt_files(files, password, json_output):
    json_file_metadata = {}
    # Check validator
    validator_list = []
    for file in files:
        # Read in json data
        with open(f".fenc-meta.{file}", 'r') as infile:
            data = json.load(infile)

        master_key = generate_master_key(password, bytes.fromhex(data['salt']))
        json_file_metadata[file] = master_key.hex()
        validator, f1, f2, f3, f4, mac, search_term_key = kdf(master_key[:16], master_key[16:])
        if validator.hex() != data['validator']:
            validator_list.append(file)

    if len(validator_list) > 0:
        sys.stderr.write("Wrong password for the following files\n")
        for file in validator_list:
            sys.stderr.write(f"{file}\n")

        exit(1)

    # Decrypt files
    for file in files:
        # Read in json data
        with open(f".fenc-meta.{file}", 'r') as infile:
            json_data = json.load(infile)

        master_key = generate_master_key(password, bytes.fromhex(json_data['salt']))
        validator, f1, f2, f3, f4, mac, search_term_key = kdf(master_key[:16], master_key[16:])
        
        # Check mac
        with open(file, 'rb') as f:
            data = f.read()

        mac_check = hmac.new(mac, data, digestmod=hashlib.sha256).hexdigest()
        if mac_check == json_data['mac']:
            with open(f'{file}', 'wb') as f:
                f.write(decrypt(f1, f2, f3, f4, data))
            os.remove(f".fenc-meta.{file}")
        else:
            sys.stderr.write(f"MACs do not match for {file}. Not decypting.\n")

    if json_output:
        json_to_write = json.dumps(json_file_metadata)
        sys.stdout.write(json_to_write)


def search_files(words, password):
    file_list = [f for f in os.listdir('.') if isfile(f)]
    # Check for files
    if len(file_list) == 0:
        sys.stderr.write("No files in directory")
        exit(1)

    files_hidden_removed = []
    # Remove hidden files from list
    for file in file_list:
        if file[0] != '.':
            files_hidden_removed.append(file)
    # Remove files that don't have metadata
    files = []
    for file in files_hidden_removed:
        if exists(f".fenc-meta.{file}"):
            files.append(file)

    
    # Check validator
    validated_list =[]
    for file in files:
        with open(f".fenc-meta.{file}", 'r') as infile:
            data = json.load(infile) 

        master_key = generate_master_key(password, bytes.fromhex(data['salt']))
        validator, f1, f2, f3, f4, mac, search_term_key = kdf(master_key[:16], master_key[16:])

        if validator.hex() != data['validator']:
            sys.stderr.write(f"Validator did not match for file: {file}\n")
        elif validator.hex() == data['validator']:
            validated_list.append(file)

    # Search files where validator did match
    if len(validated_list) > 0:
        dup_removed = []
        # Remove duplicates
        [dup_removed.append(i) for i in words if i not in dup_removed]

        for file in validated_list:
            with open(f".fenc-meta.{file}", 'r') as infile:
                data = json.load(infile)
            
            master_key = generate_master_key(password, bytes.fromhex(data['salt']))
            validator, f1, f2, f3, f4, mac, search_term_key = kdf(master_key[:16], master_key[16:])
            hex_term_list = []
            for term in dup_removed:
                temp_term = normalize('NFC', term).casefold()
                hex_term_list.append(hmac.new(search_term_key, msg=bytes(temp_term, encoding='utf8'), digestmod=hashlib.sha256).hexdigest())
            
            if len(set(hex_term_list) & set(data['terms'])) > 0:
                sys.stdout.write(f"{file}\n")
    
    else:
        sys.stderr.write("No files matched password provided")
        exit(1)


def check_utf8(data):
    try:
        if data.decode('utf-8'):
            return True
    except UnicodeDecodeError:
        return False


def generate_master_key(password, salt):
    key = PBKDF2(password.encode('utf-8'), salt, 32, count=250000, hmac_hash_module=SHA256)
    
    return key


def byte_addition(val):
    int_val = int.from_bytes(val, "big")
    int_val += 1
    return int_val.to_bytes(16, "big")


def one_ctr_block(k, n):
    ctx = AES.new(k, mode=AES.MODE_ECB)

    return ctx.encrypt(n)


def kdf(key, nonce):
    r2= byte_addition(nonce)
    r3 = byte_addition(r2)
    r4 = byte_addition(r3)
    r5 = byte_addition(r4)
    r6 = byte_addition(r5)
    r7 = byte_addition(r6)

    return (
        one_ctr_block(key, nonce),
        one_ctr_block(key, r2),
        one_ctr_block(key, r3),
        one_ctr_block(key, r4),
        one_ctr_block(key, r5),
        one_ctr_block(key, r6),
        one_ctr_block(key, r7)
    )


def xor_bytes(bl, b2):
    return bytes([x ^ y for x, y in zip(bl, b2)])


def aes_round(block, roundkey):
    l_block = block[:16]
    r_block = block[16:]
    r_block_list = [r_block[i : i + 16] for i in range(0, len(r_block), 16)]
    encrypted_r_block_list = []
    iv = l_block
    for i in range(len(r_block_list)):
        if i == 0:
            encrypted_r_block_list.append(xor_bytes(one_ctr_block(roundkey, iv), r_block_list[i]))
        else:
            iv = byte_addition(iv)
            encrypted_r_block_list.append(xor_bytes(one_ctr_block(roundkey, iv), r_block_list[i]))

    r_out = b''.join(encrypted_r_block_list)
    return l_block + r_out


def hmac_round(block, roundkey):
    l_block = block[:16]
    r_block = block[16:]
    l_out = xor_bytes(hmac.new(roundkey, msg=r_block, digestmod=hashlib.sha256).digest(), l_block)

    return l_out + r_block


def encrypt(k1, k2, k3, k4, pt):
    r1 = aes_round(pt, k1)
    r2 = hmac_round(r1, k2)
    r3 = aes_round(r2, k3)
    return hmac_round(r3, k4)


def decrypt(k1, k2, k3, k4, ct):
    r1 = hmac_round(ct, k4)
    r2 = aes_round(r1, k3)
    r3 = hmac_round(r2, k2)
    return aes_round(r3, k1)


def search_uni_word(str):
    uni_char = re.compile(r'\p{Ll}|\p{Lu}|\p{Lt}|\p{Lm}|\p{Lo}|\p{Mn}|\p{Nd}|\p{Pc}')
    word = []
    word_list = []
    for sub_str in str:
        if uni_char.match(sub_str):
            word.append(sub_str)
        else:
            if len(word) >= 4 and len(word) <= 12:
                word_list.append(''.join(word))
            word = []

    return word_list 


def create_search_terms(str_list):
    search_word_list = []
    temp_list = sorted(str_list)
    for word in temp_list:
        if len(word) > 4:
            for i in range(len(word) - 4):
                    search_word_list.append(word[:i + 4] + "*")
        search_word_list.append(word)

    return search_word_list


def casefold_and_normalize(str):
    search_word_list = create_search_terms(search_uni_word(str))
    case_norm_list = []
    for word in search_word_list:
        case_norm_list.append(normalize('NFC', word).casefold())

    return case_norm_list


def main():
    arg_list = take_arguments()

    # Encryption
    if arg_list[0] == 'e':
        # Check if files exist
        for str in arg_list[-1]:
            if not exists(f"{str}"):
                sys.stderr.write("One or more files don't exist\n")
                exit(1)
        # Check if encrypted files already exist
        for str in arg_list[-1]:
            if exists(f".fenc-meta.{str}"):
                sys.stderr.write("One or more encrypted files already exist\n")
                exit(1)
        # Encrypt files
        try:
            passwd = getpass()
        except:
            sys.stderr.write("Password error")
            exit(1)
        if len(passwd) == 0:
            sys.stderr.write("No password provided")
            exit(1)
        if len(arg_list) == 3 and arg_list[1] == 'j':
            encrypt_files(arg_list[-1], passwd, True)
        elif len(arg_list) == 2:
            encrypt_files(arg_list[-1], passwd, False)

    # Decryption
    if arg_list[0] == 'd':
        # Check if files exist
        for str in arg_list[-1]:
            if not exists(f"{str}"):
                sys.stderr.write("One or more files don't exist\n")
                exit(1)
        # Check if encrypted files already exist
        file_not_enc_list = []
        for str in arg_list[-1]:
            if not exists(f".fenc-meta.{str}"):
                file_not_enc_list.append(str)
        if len(file_not_enc_list) > 0:
            sys.stderr.write("One or more encrypted files does not exist\n")
            print("Files: ")
            for file in file_not_enc_list:
                print(f"{file}\n")

            exit(1)
        # Decrypt files
        try:
            passwd = getpass()
        except:
            sys.stderr.write("Password error")
            exit(1)
        if len(passwd) == 0:
            sys.stderr.write("No password provided")
            exit(1)
        if len(arg_list) == 3 and arg_list[1] == 'j':
            decrypt_files(arg_list[-1], passwd, True)
        elif len(arg_list) == 2:
            decrypt_files(arg_list[-1], passwd, False)

    # Search
    if arg_list[0] == 's':
        try:
            passwd = getpass()
        except:
            sys.stderr.write("Password error")
            exit(1)
        if len(passwd) == 0:
            sys.stderr.write("No password provided")
            exit(1)
        search_files(arg_list[-1], passwd)


if __name__ == "__main__":
    main()
