from cryptography.fernet import Fernet, InvalidToken
import sys
import argparse

# Acts as a command line application for file encryption, file decryption, or private key generation using arguments passed over the command line 

# Adapted from methodology described by Emily Lahren at https://emilylahren.com/2024/07/using-an-encrypted-env-file-with-your-python-script-to-secure-data/

def parse_args():
    parser = argparse.ArgumentParser(
        prog='JSON Transcriber',
        description='Simple CLI tool that extracts all plaintext key:value pairs that follow "KEY: VALUE" formatting from a specified text file ' \
        'and writes them as individual JSON objects to a specified JSON file'
    )
    parser.add_argument('-i','--input', nargs=1, help="Path to input text file containing plaintext key:value pairs with expected formatting")
    parser.add_argument('-o','--output', nargs=1, help="Path to JSON file to have the JSON objects written to")
    parser.add_argument('-t','--total', help="Expected total number of key:value pairs to be extracted")
    return parser.parse_args()

def main():
    args = parse_args()
    if (not args.input):
        raise KeyError("Missing required path to text file to be parsed!")

    if (not args.output):
        raise KeyError("Missing required path to JSON file to be written to!")

    with open(f"{args.input[0]}", 'r') as enc_file:
        enc_data = enc_file.readlines()
        with open(f"{args.output[0]}", "w") as enc_json_file:
            var_count = 0
            for line in enc_data:
                data_line = line.split(':')
                if (len(data_line) > 1):
                    var_count += 1
                    enc_json_file.write("{\t\"name\":\t")
                    data_line[0] = data_line[0].strip().upper().replace(' ', '_')
                    data_line[1] = data_line[1].strip()
                    enc_json_file.write(f"\"{data_line[0]}\",\t")
                    enc_json_file.write(f"\"value\":\t")
                    enc_json_file.write(f"\"{data_line[1].strip()}\"")
                    enc_json_file.write("\t},\n")
            if (args.total is not None and var_count < args.total):
                raise RuntimeError(f'Unexpected File Syntax/Format detected: Only {var_count} of the {args.total} key:value pairs were found in {enc_file.name}!')
            if (args.total is not None and var_count == 0):
                raise RuntimeError(f"No key:value pairs were found in file '{enc_file.name}'!")
if __name__ == '__main__':
    main()