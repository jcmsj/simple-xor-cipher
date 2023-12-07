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
    parser.add_argument('--key', '-k', type=int, help='Key to encrypt/decrypt with')
    return parser
def main():
    '''Run if main module'''
    argparser = cli()
    args = argparser.parse_args()
    if args.encrypt and args.key:
        encrypted_message = encrypt(args.encrypt, int(args.key))
        print(encrypted_message)
    elif args.decrypt and args.key:
        decrypted_message = decrypt(args.decrypt, int(args.key))
        print(decrypted_message)
    else:
        argparser.print_help()

if __name__ == '__main__':
    main()
