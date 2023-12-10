def xor(char:str, key:int) -> str:
    return chr(ord(char) ^ key)

def encrypt(message:str, key:int) -> str:
    return "".join([xor(char,key) for char in message])

def decrypt(ciphertext:str, key:int) -> str:
    return "".join([xor(char,key) for char in ciphertext])

def cli():
    import argparse
    parser = argparse.ArgumentParser(description='XOR cipher - A command line tool to encrypt/decrypt messages using the XOR cipher')
    parser.add_argument('--encrypt', '-e', help='Encrypts a message')
    parser.add_argument('--decrypt', '-d', help='Decrypts a cypher text')
    parser.add_argument('--key', '-k', help='Key to encrypt/decrypt with')
    parser.add_argument('--export', '-x', help='Export encrypted message to a file')
    parser.add_argument('--file', '-f', help='Decrypts a cypher text from a file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Prints verbose output')
    return parser

def sum_string_representation(string:str) -> int:
  char_codes = map(ord, string)
  return sum(char_codes) # Total

def export_to_file(filename:str, text:str):
    # export as raw binary data
    with open(filename, 'wb') as f:
        f.write(text.encode('utf-8'))

def import_from_file(filename:str) -> str:
    with open(filename, 'rb') as f:
        # read from utf-8 encoded file
        return f.read().decode('utf-8')
def main():
    '''Run if main module'''
    argparser = cli()
    args = argparser.parse_args()
    if not args.key:
        argparser.print_help()
        return
    
    if args.encrypt:
        int_key:int = sum_string_representation(args.key)
        encrypted_message:str = encrypt(args.encrypt, int_key)
        if args.export:
            export_to_file(args.export, encrypted_message)
        print(f"Encrypted message:\n{encrypted_message}")
        return
    
    if args.file:
        args.decrypt = import_from_file(args.file)
        
    if args.decrypt:
        int_key:int = sum_string_representation(args.key)
        decrypted_message:str = decrypt(args.decrypt, int_key)
        print(f"Decrypted message:\n{decrypted_message}")
    else:
        argparser.print_help()

if __name__ == '__main__':
    main()
