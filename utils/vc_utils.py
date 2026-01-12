from .vault_connector import create_authenticated_vault_connection, unseal_vault_server, create_unauthenticated_vault_connection
import os
import base64
import gnupg
import requests
import hvac

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

# Encryption Key Settings
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


# ========================= VAULT SEALING/UNSEALING FUNCTIONS =======================

def seal_vault():
    try:
        tmp_root_token = generate_temporary_root_key()
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=tmp_root_token,
        )
        print("Attempting to reseal vault...")
        vc.sys.seal()
        assert vc.sys.is_sealed()
        print("Vault resealed!")
        vc.adapter.close()
        revoke_vault_token(tmp_root_token)
        return
    except RuntimeError as e:
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")

def unseal_vault() -> None:
    print("Attempting to unseal vault...")
    try:
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )
        assert not vc.sys.is_sealed()
        vc.adapter.close()
        return
    except RuntimeError as e:
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")

# ================================ VAULT KV (VERSION 2) SECRETS FUNCTIONS ==================================


# Retrieve application credentials from Vault's KV secrets
def get_secrets():
    try:
        # Mitigate potential secret pathing values before interacting with vault server
        assert type(SECRET_MOUNT_PATH) == str, "SECRET_MOUNT_PATH variable must be a string value!"
        assert len(SECRET_MOUNT_PATH) >= 1, "SECRET_MOUNT_PATH variable must be a non-empty string value!"
        assert type(SECRET_PATH) == str, "SECRET_PATH variable must be a string value!"
        assert len(SECRET_PATH) >= 1, "SECRET_PATH variable must a non-empty string value!"
        init_vc = create_unauthenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS
        )

        # Secrets Path: 'mount_point/data/path'
        # Retrieve V2 KV secrets from mounted point for secret at specified path
        vc = create_authenticated_vault_connection(
            vault_address=init_vc.url,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )
        init_vc.adapter.close()
        
        retrieve_secrets = vc.secrets.kv.v2.read_secret_version(
            mount_point=SECRET_MOUNT_PATH,
            path=SECRET_PATH
        )

        secret_data = retrieve_secrets['data']['data']
        vc.adapter.close()
        return secret_data
    except RuntimeError as e:
        if init_vc is not None:
            init_vc.adapter.close()
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")


# Update one or more keys within Vault's KV secrets
def update_secrets(updated_secrets: dict):
    try:
        # Mitigate potential secret pathing values before interacting with vault server
        assert type(SECRET_MOUNT_PATH) == str, "SECRET_MOUNT_PATH variable must be a string value!"
        assert len(SECRET_MOUNT_PATH) >= 1, "SECRET_MOUNT_PATH variable must be a non-empty string value!"
        assert type(SECRET_PATH) == str, "SECRET_PATH variable must be a string value!"
        assert len(SECRET_PATH) >= 1, "SECRET_PATH variable must a non-empty string value!"

        # Create a new vault client for connecting to vault
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )

        # Create or update each provided secret key/value pair within specified secret
        for secret_key, secret_value in updated_secrets.items(): 
            updated_secrets = vc.secrets.kv.v2.patch(
                mount_point=SECRET_MOUNT_PATH,
                path=SECRET_PATH,
                secret={
                    f"{secret_key}": f"{secret_value}"
                }
            )
        vc.adapter.close()
    except RuntimeError as e:
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")

# ============================= VAULT TRANSIT SECRETS FUNCTIONS ==============================


# Adapted from code snippet provided in HVAC documentation. See https://python-hvac.org/en/stable/usage/secrets_engines/transit.html
def base64ify(bytes_or_str):
    """Helper method to perform base64 encoding across Python 2.7 and Python 3.X"""
    if isinstance(bytes_or_str, str):
        input_bytes = bytes_or_str.encode('utf8')
    else:
        input_bytes = bytes_or_str

    output_bytes = base64.urlsafe_b64encode(input_bytes)
    return output_bytes.decode('ascii')


# Decrypt sensitive data using specified transit encryption key
def decrypt_data(data: str):
    print("Attempting to decrypt requested data using Vault transit encryption key...")
    try:
        assert type(TRANSIT_MOUNT_PATH) == str, "TRANSIT_MOUNT_PATH must be a string value!"
        assert len(TRANSIT_MOUNT_PATH) >= 1, "TRANSIT_MOUNT_PATH must be a non-empty string!"
        assert type(TRANSIT_KEY) == str, "TRANSIT_KEY must be a string value!"
        assert len(TRANSIT_KEY) >= 1, "TRANSIT_KEY must be a non-empty string!"

        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )

        decrypted_data = vc.secrets.transit.decrypt_data(
            mount_point=TRANSIT_MOUNT_PATH,
            name=f"{TRANSIT_KEY}",
            ciphertext=data
        )

        plaintext = decrypted_data['data']['plaintext']
        return plaintext
    except RuntimeError as e:
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")

def encrypt_data(data: str):
    print("Attempting to encrypt requested data using Vault transit encryption key...")
    try:
        assert type(TRANSIT_MOUNT_PATH) == str, "TRANSIT_MOUNT_PATH must be a string value!"
        assert len(TRANSIT_MOUNT_PATH) >= 1, "TRANSIT_MOUNT_PATH must be a non-empty string!"
        assert type(TRANSIT_KEY) == str, "TRANSIT_KEY must be a string value!"
        assert len(TRANSIT_KEY) >= 1, "TRANSIT_KEY must be a non-empty string!"
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )

        b64enc_data = base64ify(data.encode())
        encrypted_data = vc.secrets.transit.encrypt_data(
            mount_point=TRANSIT_MOUNT_PATH,
            name=f"{TRANSIT_KEY}",
            plaintext=b64enc_data
        )

        ciphertext = encrypted_data['data']['ciphertext']
        return ciphertext
    except RuntimeError as e:
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")

# ===================== VAULT CREDENTIALS ROTATION FUNCTIONS ======================

def revoke_vault_token(vault_token: str)  -> None:
    try:
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=vault_token
        )
        print("Attempting to revoke passed token...")
        vc.logout(revoke_token=True)
        print("Token successfully revoked.")
    except RuntimeError as e:
        if vc is not None:
            vc.adapter.close()
        raise RuntimeError(f"{e}")

def generate_temporary_root_key():
    try:
        gpg = gnupg.GPG(gnupghome=GPG_HOME)
        gpg.encoding = 'utf-8'
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )

        generate_new_root_token_response = vc.sys.start_root_token_generation(pgp_key=TOKEN_CRYPT_KEY)
        if 'progress' not in generate_new_root_token_response or 'required' not in generate_new_root_token_response:
            print("Request to start generation of temporary vault root token failed unexpectedly")
            if vc is not None:
                vc.adapter.close()
            return
        
        required_unseal_key_count = int(generate_new_root_token_response['required'])
        print(f"Required number of unseal keys: {required_unseal_key_count}")

        token_nonce = generate_new_root_token_response['nonce']
        submit_key1_response = vc.sys.generate_root(key=UNSEAL_KEY_1, nonce=token_nonce)
        if 'progress' not in submit_key1_response or 'required' not in submit_key1_response:
            print("Submission of first unseal key failed unexpectedly")
            if vc is not None:
                vc.sys.cancel_root_generation()
                vc.adapter.close()
            return
        

        print(f"Root Key Generation Progress: {submit_key1_response['progress']}/{submit_key1_response['required']}")

        submit_key2_response = vc.sys.generate_root(key=UNSEAL_KEY_2, nonce=token_nonce)
        if 'progress' not in submit_key2_response or 'required' not in submit_key2_response:
            print("Submission of second unseal key failed unexpectedly")
            if vc is not None:
                vc.sys.cancel_root_generation()
                vc.adapter.close()
            return
        
        print(f"Root Key Generation Progress: {submit_key2_response['progress']}/{submit_key2_response['required']}")
        if 'complete' in submit_key2_response and 'encoded_token' in submit_key2_response and len(str(submit_key2_response['encoded_token']).strip()) > 0:
            try:
                print("New PGP encrypted Base64 encoded root key successfully generated!")
                tmp_b64_enc_root_token = submit_key2_response['encoded_token']
                decoded_token = base64.urlsafe_b64decode(tmp_b64_enc_root_token)
                gpg_decoded_token = str(gpg.decrypt(decoded_token))
                vc.adapter.close()
                return gpg_decoded_token

            except Exception as other:
                print(f"ERROR: Unexpected exception thrown: {other}")
                if vc is not None:
                    vc.sys.cancel_root_generation()
                    vc.adapter.close()
                return
        else:
            print("Final decoding or unseal key submission failed!")
            if vc is not None:
                vc.sys.cancel_root_generation()
                vc.adapter.close()
            return
    except Exception as e:
        print(f"Unexpected exception raised during root token generation process: {e}")
        if vc is not None:
            vc.sys.cancel_root_generation()
            vc.adapter.close()


def rotate_unseal_keys():
    try:
        print("Beginning Rotation of Vault Unseal Keys...")
        gpg = gnupg.GPG(gnupghome=GPG_HOME)
        gpg.encoding = 'utf-8'
        vc = create_authenticated_vault_connection(
            vault_address=VAULT_ADDR,
            proxy_address=PROXIES,
            certs=CERTS,
            unseal_keys=UNSEAL_KEYS,
            token=VAULT_TOKEN
        )
        print("Submitting Rekey Start Request...")
        start_new_rekey_response = vc.sys.start_rekey(
            secret_shares=3,
            secret_threshold=2,
            pgp_keys=[
                ALT_UNSEAL_CRYPT_KEY1,
                ALT_UNSEAL_CRYPT_KEY2,
                ALT_UNSEAL_CRYPT_KEY3
            ],
            require_verification=True
        )

        if 'nonce' not in start_new_rekey_response:
            print("Initial Rekey start request failed!")
            if vc is not None:
                vc.sys.cancel_rekey()
                vc.adapter.close()
            return

        print("Rekey Start Request Approved. Submitting Rekey Request with original Unseal Keys and PGP Encryption Keys...")
        rekey_nonce = start_new_rekey_response['nonce']

        multiple_rekey_submit_response = vc.sys.rekey_multi(
            keys= UNSEAL_KEYS,
            nonce=rekey_nonce
        )

        if 'keys_base64' not in multiple_rekey_submit_response or 'pgp_fingerprints' not in multiple_rekey_submit_response:
            print("Mutiple Rekey request failed! Keys were not recieved in response")
            if vc is not None:
                vc.sys.cancel_rekey()
                vc.adapter.close()
            return

        if 'complete' not in multiple_rekey_submit_response or 'verification_nonce' not in multiple_rekey_submit_response or multiple_rekey_submit_response['complete'] != True:
            print("Multiple Rekey request failed! One or more submitted unseal keys were invalid and failed to be sufficient enough to satisfy rekey requirements.")
            if vc is not None:
                vc.sys.cancel_rekey()
                vc.adapter.close()
            return
        
        print("Rekey Request successful. Extracting new PGP-encrypted and base64-encoded unseal keys...")
        b64_enc_keys = multiple_rekey_submit_response['keys_base64']
        rekey_verify_nonce = multiple_rekey_submit_response['verification_nonce']
        # fingerprints = multiple_rekey_submit_response['pgp_fingerprints']
        # print(f"PGP-encrypted, base64-encoded new unseal keys: {b64_enc_keys}")
        # print(f"PGP Fingerprints: {fingerprints}")

        decoded_unseal_key1 = base64.urlsafe_b64decode(b64_enc_keys[0])
        decrypted_unseal_key1 = str(gpg.decrypt(decoded_unseal_key1))
        
        decoded_unseal_key2 = base64.urlsafe_b64decode(b64_enc_keys[1])
        decrypted_unseal_key2 = str(gpg.decrypt(decoded_unseal_key2))

        decoded_unseal_key3 = base64.urlsafe_b64decode(b64_enc_keys[2])
        decrypted_unseal_key3 = str(gpg.decrypt(decoded_unseal_key3))

        print("Beginning Rekey Verification...")
        rekey_verification_response = vc.sys.rekey_verify_multi(
            keys = [
                decrypted_unseal_key1,
                decrypted_unseal_key2,
                decrypted_unseal_key3
            ],
            nonce=rekey_verify_nonce
        )
        
        if 'complete' not in rekey_verification_response or rekey_verification_response['complete'] != True:
            print("Rekey Verification Request failed! One or more submitted new unseal keys were invalid and failed to be sufficient enough to satisfy rekey verification")
            if vc is not None:
                vc.sys.cancel_rekey_verify()
                vc.sys.cancel_rekey()
                vc.adapter.close()
            return
        
        print("Rekey Verification successful! Reseal keys successfully rotated!")
        vc.adapter.close()

        encrypted_seal_keys = {
            "UNSEAL_KEY_1": b64_enc_keys[0],
            "UNSEAL_KEY_2": b64_enc_keys[1],
            "UNSEAL_KEY_3": b64_enc_keys[2]
        }
        return encrypted_seal_keys
    except Exception as e:
        print(f"Rekey process failed with unexpected exception thrown: {e}")
        if vc is not None:
            vc.sys.cancel_rekey()
            vc.adapter.close()

def rotate_dev_user_token(username: str, password: str) -> str:
    try:
        print("Attempting to establish connection with running vault server instance...")
        # Attempt to establish a connection to the running vault instance
        vc = hvac.Client(
            url=VAULT_ADDR,
            proxies=PROXIES,
            cert=(CERTS['certificate'], CERTS['key']),
            verify=(CERTS['certificate'])
        )
            # See https://python-hvac.org/en/stable/advanced_usage.html#making-use-of-private-ca
        if CERTS['certificate']:
            rs = requests.Session()
            vc.session = rs
            rs.verify = CERTS
        # Check initial vault state at startup
        print("Checking initial vault status...")

        # Verify vault has already been initialized, else raise an exception
        if not vc.sys.is_initialized():
            raise RuntimeError("Vault instance must already be initialized and preconfigured before use in application!")

        # If vault is currently unsealed attempt to unseal it using the provided unseal keys
        if vc.sys.is_sealed():
            try:
                print("Vault is currently sealed. Attempting to unseal the vault using unseal keys...")
                unseal_vault_server(vc, UNSEAL_KEYS)
            # If unsealing process raises an exception indicating failure to unseal vault, raise exception in main function
            except RuntimeError:
                raise RuntimeError("Vault unsealing failed! Please ensure provided unseal keys are valid!")
        vc.adapter.close()
        new_vc = create_unauthenticated_vault_connection(
                vault_address=VAULT_ADDR,
                proxy_address=PROXIES,
                certs=CERTS,
                unseal_keys=UNSEAL_KEYS
        )
        userpass_login_response = new_vc.auth.userpass.login(
            username=username,
            password=password,
            use_token=False
        )
        print(" Verifying vault authentication with generated token is successful...")
        assert new_vc.is_authenticated()
        print("Verifying response contains new token to replace current token...")
        if 'auth' not in userpass_login_response:
            print("Login Request failed. No authorization response found in response body")
            if vc is not None:
                vc.adapter.close()
            return
        
        login_auth_object = userpass_login_response['auth']
        if 'client_token' not in login_auth_object:
            print("Login Request failed. No issued token found in response body")
            
        token = str(login_auth_object['client_token']).strip()
        print("New user token successfully extracted from login response!")
        new_vc.adapter.close()
        revoke_vault_token(VAULT_TOKEN)
        return token
    except Exception as e:
        print(f"Rekey process failed with unexpected exception thrown: {e}")
        if new_vc is not None:
            new_vc.adapter.close()
        if vc is not None:
            vc.sys.cancel_rekey()
            vc.adapter.close()