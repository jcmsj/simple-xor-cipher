from os import urandom
from file import export_to_file, import_from_file

def xor_bytes(s:bytes, t:bytes) -> bytes:
    """Concate xor two strings together."""
    if isinstance(s, bytes):
        # Bytes objects contain integer values in the range 0-255
        return bytes([a ^ b for a, b in zip(s, t)])
    else:
        raise TypeError("'s' must have the type 'bytes'.")

def xor_str(s:str, t:str) -> bytes:
    return xor_bytes(s.encode(), t.encode())

def genkey(length: int) -> bytes:
    """Generate key."""
    return urandom(length)

def cli():
    import argparse
    parser = argparse.ArgumentParser(description='XOR cipher - A command line tool to encrypt/decrypt messages using the XOR cipher')
    parser.add_argument('--encrypt', '-e', help='Encrypts a message')
    parser.add_argument('--decrypt', '-d', help='Decrypts a cypher text')
    parser.add_argument('--key', '-k', help='Key to encrypt/decrypt with')
    parser.add_argument('--key-int', help='Integer key to encrypt/decrypt with', type=int)
    parser.add_argument('--export', '-x', help='Export encrypted message to a file')
    parser.add_argument('--file', '-f', help='Decrypts a cypher text from a file')
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
    if args.file:
        args.decrypt = import_from_file(args.file)
    if args.key and args.decrypt:
        decrypted_message = xor_str(args.decrypt, args.key)
        decrypted_message_str = decrypted_message.decode()
        print(f"Decrypted message:\n{decrypted_message_str}")

    else:
        argparser.print_help()
    
if __name__ == '__main__':
    main()
