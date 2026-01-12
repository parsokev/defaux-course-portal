import os
import subprocess
import gnupg
from .vc_utils import rotate_unseal_keys, rotate_dev_user_token
import os

import gnupg
import subprocess

# Vault Unsealing Settings
UNSEAL_KEY_1 = os.environ["UNSEAL_KEY_1"].strip()
UNSEAL_KEY_2 = os.environ["UNSEAL_KEY_2"].strip()
UNSEAL_KEY_3 = os.environ["UNSEAL_KEY_3"].strip()
UNSEAL_KEYS = [
    UNSEAL_KEY_1,
    UNSEAL_KEY_2,
    UNSEAL_KEY_3
]

# Vault Authorization Settings
VAULT_TOKEN = os.environ["VAULT_TOKEN"].strip()
GPG_HOME = os.environ["GPG_HOME"]

TOKEN_CRYPT_KEY = str(os.environ["TOKEN_CRYPT_KEY"]).strip()
ALT_TOKEN_CRYPT_KEY = str(os.environ["ALT_TOKEN_CRYPT_KEY"]).strip()

UNSEAL_CRYPT_KEY1 = str(os.environ["UNSEAL_CRYPT_KEY1"]).strip()
UNSEAL_CRYPT_KEY2 = str(os.environ["UNSEAL_CRYPT_KEY2"]).strip()
UNSEAL_CRYPT_KEY3 = str(os.environ["UNSEAL_CRYPT_KEY3"]).strip()

ALT_UNSEAL_CRYPT_KEY1 = str(os.environ["ALT_UNSEAL_CRYPT_KEY1"]).strip()
ALT_UNSEAL_CRYPT_KEY2 = str(os.environ["ALT_UNSEAL_CRYPT_KEY2"]).strip()
ALT_UNSEAL_CRYPT_KEY3 = str(os.environ["ALT_UNSEAL_CRYPT_KEY3"]).strip()

# Vault TLS Settings
VAULT_CERT_PATH = os.environ["VAULT_CERT_PATH"]
VAULT_CERT_KEY_PATH = os.environ["VAULT_CERT_KEY_PATH"]
CERTS = {
    "certificate": VAULT_CERT_PATH,
    "key": VAULT_CERT_KEY_PATH
}
 
# Vault Configuration Settings
VAULT_ADDR = os.environ["VAULT_ADDR"].strip()
VAULT_PROXY_ADDR = os.environ["VAULT_PROXY_ADDR"].strip()

PROXIES = {
    "http": VAULT_PROXY_ADDR,
}

# Vault Secrets Settings
SECRET_MOUNT_PATH = os.environ["SECRET_MOUNT_PATH"].strip()
SECRET_PATH = os.environ["SECRET_PATH"].strip()

# # Vault Transit Settings
TRANSIT_MOUNT_PATH = os.environ["TRANSIT_MOUNT_PATH"].strip()
TRANSIT_KEY = os.environ["TRANSIT_KEY"].strip()


# Temporary Non-Standard Environment Variables
USERNAME = os.environ["USERNAME"]
PASS = os.environ["PASS"]

ORIGINAL_ENV_FILE = os.environ["ORIGINAL_ENV_FILE"]
SOPS_CONFIG_FILE = os.environ["SOPS_CONFIG_FILE"]
TEMP_TEXT_FILE = os.environ["TEMP_TEXT_FILE"]
PGP_FINGERPRINT = os.environ["PGP_FINGERPRINT"]


def rotate_sops_file_encryption(original_env_file: str, sops_config_file: str, temp_env_file, pgp_fingerprint: str):
    print("Running First Command pipe...")
    pipe1_com = subprocess.Popen(
        args=["cat", f"{original_env_file}"],
        stdout=subprocess.PIPE
    )

    pipe2_com = subprocess.Popen(
        args=["sops", "--config", f"{sops_config_file}", "decrypt", "--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin"],
        stdin=pipe1_com.stdout,
        stdout=subprocess.PIPE
    )

    print("Passing first command output to stdin of second command pipe...")

    pipe3_com = subprocess.Popen(
        args=[
            "sops", "--config", f"{sops_config_file}", "encrypt", "--pgp", f"{pgp_fingerprint}", "--filename-override", f"{temp_env_file}",
            "--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin"
        ],
        stdin=pipe2_com.stdout,
        stdout=subprocess.PIPE,
        text=True,
    )
    pipe1_com.stdout.close()
    pipe2_com.stdout.close()

    print("Passing second command output to stdin of third command pipe...")
    output, errors = pipe3_com.communicate()

    if errors:
        print(f"Errors encountered while piping commands: {errors}")
        return

    if len(output) > 0:
        print("Writing to newly encrypted file to temporary buffer file...")
        with open(f"{temp_env_file}", "w") as out_file:
            out_file.write(output)



def encrypt_file(sops_config_file: str, pgp_fingerprint: str, input_file: str):
    sops_encrypt_command = subprocess.run(
        args=[
            "sops", "--config", f"{sops_config_file}", "encrypt", "--pgp", f"{pgp_fingerprint}", f"{input_file}",
            "--in-place"
        ],
        check=True,
    )



def rebuild_encrypted_file(input_file: str, sops_config_file: str, keys: dict, pgp_fingerprint:str):
    print("Generating temporary file with new base64 encoded and pgp encrypted unseal keys...")
    with open(input_file, 'w') as in_file:
        for key, value in keys.items():
            in_file.write(f"{key}: {value}\n")

    try:
        
        print("Attempting to convert generated env file into encrypted file")
        encrypt_file(sops_config_file=sops_config_file, pgp_fingerprint=pgp_fingerprint, input_file=input_file)
    except subprocess.CalledProcessError as e:
        print(f"Building of SOPS-encrypted file with new unseal keys failed: {e}")

    print(f"SOPS encryption of input file successful! Updated env file with new encrypted unseal keys found at file: {input_file}")



def generate_temporary_vault_credentials_file(input_file: str, encrypted_keys: dict, unencrypted_keys: dict):
    print("Generating temporary file with new base64 encoded and pgp encrypted unseal keys...")
    gpg = gnupg.GPG(gnupghome=GPG_HOME)
    gpg.encoding = 'utf-8'
    if 'VAULT_TOKEN' not in unencrypted_keys or 'USERNAME' not in unencrypted_keys or 'PASSWORD' not in unencrypted_keys:
        print("One or more expected vault credentials missing from credentials dict!")
        return
    
    # Write updated vault credentials to temporary text file to be parsed by home brewed JSON transriber CLI tool
    with open(input_file, 'w') as in_file:
        # Write base64-encoded, PGP-encrypted rekeyed unseal keys using line formatting expected JSON transcriber
        for key, value in encrypted_keys.items():
            in_file.write(f"{key}: {value}\n")

        # Write base64-encoded, PGP-encrypted vault user credential values using line formatting expected JSON transcriber
        for key, value in unencrypted_keys.items():
            # Convert in-memory naked credential values into armored base-64 PGP-encrypted values using GnuPG 
            encrypted_value = gpg.encrypt(data=value, recipients=[PGP_FINGERPRINT])

            # Remove PGP Armor to ensure successful in-memory PGP decryption in later steps
            dearmored_value_line_array = str(encrypted_value).split('-----BEGIN PGP MESSAGE-----')[1].strip().split('-----END PGP MESSAGE-----')[0].strip().splitlines()
            concat_final_value = "".join(dearmored_value_line_array)
            in_file.write(f"{key}: {concat_final_value}\n")

    print(f"Base64 encoded, pgp-encrypted unseal keys placed within file '{input_file}'")



def rotate_vault_credentials(username: str, password: str):
    print("Attempting to rotate vault unseal keys..")
    # Initiate vault rekeying/rekey verification of vault unseal keys, which returns
    # base64-encoded, PGP-encrypted unseal keys upon completion of successful rekey verification
    unseal_keys = rotate_unseal_keys()
    if unseal_keys is None:
        print("Rekeyed Unseal keys not recieved!")
        return
    print("Rekeyed Unseal keys received!")
    print("Attempting to rotate user service vault token...")
    # Retrieve newly generated user-based service token using userpass vault authentication method
    unencrypted_vault_creds = {}
    new_vault_token = rotate_dev_user_token(username=username, password=password)
    if new_vault_token is None:
        print("Vault token replacement not recieved!")
        return
    # Build map of base64-encoded, PGP-encrypted updated vault credentials and write them to a temporary text file to be parsed by JSON transcriber
    # NOTE: If calling for first time with 'INITIAL_ROOT_TOKEN' still present in encrypted env file, this will remove this value from the file
    unencrypted_vault_creds['VAULT_TOKEN'] = new_vault_token
    unencrypted_vault_creds['PASSWORD'] = password
    unencrypted_vault_creds['USERNAME'] = username

    print("Newly generated user service vault token recieved!")
    print("Attempting to rebuild encrypted credentials file with updated vault credentials")
    generate_temporary_vault_credentials_file(input_file=TEMP_TEXT_FILE, encrypted_keys=unseal_keys, unencrypted_keys=unencrypted_vault_creds)


# Main Application:
if __name__ == '__main__':
    rotate_vault_credentials(username=USERNAME, password=PASS)