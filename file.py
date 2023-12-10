def export_to_file(filename:str, text:str):
    # export as raw binary data
    with open(filename, 'wb') as f:
        f.write(text.encode('utf-8'))

def import_from_file(filename:str) -> str:
    with open(filename, 'rb') as f:
        # read from utf-8 encoded file
        return f.read().decode('utf-8')
