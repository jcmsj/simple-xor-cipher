from typing import Callable
from file import export_to_file, import_from_file

def xor_bytes(s:bytes, t:bytes) -> bytes:
    """Concat xor two strings together."""
    return bytes([a ^ b for a, b in zip(s, t)])

def xor_curry(callback: Callable[[bytes, bytes], bytes]):
    def wrapper(s:str, t:str):
        return callback(s.encode(), t.encode())
    return wrapper

def xor_verbose(s:int, t:int) -> int:
    """XOR two strings together."""
    result = s ^ t
    # with leading zeroes
    bin_s = bin(s)[2:]
    bin_t = bin(t)[2:]
    bin_length = max(
        len(bin_s),
        len(bin_t)
    )
    # pad the shorter bin
    if len(bin_s)< len(bin_t):
        bin_s = bin_s.zfill(bin_length)
    else: 
        bin_t = bin_t.zfill(bin_length)

    padded_result = bin(s^t)[2:].zfill(bin_length)
    print(f"   {bin_s}")
    print(f"   {bin_t}")
    print(f"XOR{'-'*bin_length}")
    print(f"   {padded_result}\n")
    return result
def xor_tutorial(s:bytes, t:bytes) -> bytes:
    """XOR the byte representations of two characters"""
    return bytes([xor_verbose(a,b) for a, b in zip(s, t)])

xor_tutorial_str = xor_curry(xor_tutorial)
xor_str = xor_curry(xor_bytes)

def cli():
    import argparse
    parser = argparse.ArgumentParser(description='XOR cipher - A command line tool to encrypt/decrypt messages using the XOR cipher')
    parser.add_argument('--encrypt', '-e', help='Encrypts a message')
    parser.add_argument('--decrypt', '-d', help='Decrypts a file containing the cipher text')
    parser.add_argument('--key', '-k', help='Key to encrypt/decrypt with')
    parser.add_argument('--export', '-x', help='Export encrypted message to a file')
    parser.add_argument('--verbose', '-v', help='Verbose mode, shows the entire encryption/decryption process', action='store_true')
    return parser

def repeat_key_till_length(key:str, length:int) -> str:
    '''Repeat key till length'''
    repeat_count = length // len(key) + 1
    return (key * repeat_count)[:length]

def main():
    '''Run if main module'''
    argparser = cli()
    args = argparser.parse_args()
    # Encryption check
    if args.key and args.encrypt:
        padded_key = repeat_key_till_length(args.key, len(args.encrypt)).encode()
        if args.verbose:
            encrypted_message = xor_tutorial(args.encrypt.encode(), padded_key)
        else:
            encrypted_message = xor_bytes(args.encrypt.encode(), padded_key)
        encrypted_message_str = encrypted_message.decode()
        print(f"Padded key:\n{padded_key.decode()}")
        if args.export:
            export_to_file(args.export, encrypted_message_str)
            # export the key to a file: args.export + '.key'
            export_to_file(args.export + '.key', padded_key.decode())
            print("[NOTICE]: Cipher and key were exported to files")
        print(f"Encrypted message:\n{encrypted_message}")
        return
    
    # Decryption check
    if args.key and args.decrypt:
        ciphertext = import_from_file(args.decrypt)
        if args.verbose:
            decrypted_message = xor_tutorial(ciphertext.encode() , args.key.encode())
        else:
            decrypted_message = xor_str(ciphertext, args.key)
        decrypted_message_str = decrypted_message.decode()
        print(f"Decrypted message:\n{decrypted_message_str}")

    else:
        argparser.print_help()
    
if __name__ == '__main__':
    main()
