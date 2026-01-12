import hvac
import requests


def unseal_vault_server(vault_client: hvac.Client, unseal_keys: list) -> None:
    vault_client.sys.submit_unseal_keys(unseal_keys)
    if not vault_client.sys.is_sealed():
        print("Vault unsealing successful!")
    else:
        raise RuntimeError("Vault unsealing failed! Please ensure provided unseal keys are valid!")


def get_authenticated_vault(vault_client: hvac.Client, token:str, certs: object, proxy_address: object) -> hvac.Client:
    assert vault_client.url is not None and len(str(vault_client.url)) > 0
    assert certs['certificate'] is not None and len(certs['certificate']) > 0
    assert certs['key'] is not None and len(certs['key']) > 0
    assert proxy_address is not None
    assert token is not None and len(str(token)) > 0
    authenticated_vault = hvac.Client(
        url=vault_client.url,
        cert=(certs['certificate'], certs['key']),
        verify=certs['certificate'],
        proxies=proxy_address,
        token=token
    )
    vault_client.adapter.close()
    # See https://python-hvac.org/en/stable/advanced_usage.html#making-use-of-private-ca
    if certs:
        rs = requests.Session()
        authenticated_vault.session = rs
        rs.verify = certs
    
    print("Verifying vault authentication was successful...")
    if not authenticated_vault.is_authenticated():
        authenticated_vault.adapter.close()
        raise RuntimeError("Authentication with vault instance failed! Please ensure the provided token is valid!")
    
    print("Authenticated connection with vault instance successfully established!")

    return authenticated_vault


def create_unauthenticated_vault_connection(vault_address: str, proxy_address: object, certs: object, unseal_keys: list ) -> hvac.Client:
    print("Attempting to establish connection with running vault server instance...")
    # Attempt to establish a connection to the running vault instance
    vault_client = hvac.Client(
        url=vault_address,
        cert=(certs['certificate'], certs['key']),
        verify=certs['certificate'],
        proxies=proxy_address
    )
    if certs:
        rs = requests.Session()
        vault_client.session = rs
        rs.verify = certs
    # Check initial vault state at startup
    print("Checking initial vault status...")

    # Verify vault has already been initialized, else raise an exception
    if not vault_client.sys.is_initialized():
        raise RuntimeError("Vault instance must already be initialized and preconfigured before use in application!")

    # If vault is currently unsealed attempt to unseal it using the provided unseal keys
    if vault_client.sys.is_sealed():
        try:
            print("Vault is currently sealed. Attempting to unseal the vault using unseal keys...")
            unseal_vault_server(vault_client, unseal_keys)
        # If unsealing process raises an exception indicating failure to unseal vault, raise exception in main function
        except RuntimeError:
            raise RuntimeError("Vault unsealing failed! Please ensure provided unseal keys are valid!")
    return vault_client


def create_authenticated_vault_connection(vault_address: str, proxy_address: object, certs: object, unseal_keys: list, token: str ) -> hvac.Client:
    print("Attempting to complete initial setup connection with running vault server instance...")
    # Attempt to establish a connection to the running vault instance
    vault_client = hvac.Client(
        url=vault_address,
        cert=(certs['certificate'], certs['key']),
        verify=certs['certificate'],
        proxies=proxy_address
    )
    if certs:
        rs = requests.Session()
        vault_client.session = rs
        rs.verify = certs

    # Check initial vault state at startup
    print("Checking initial vault status...")

    # Verify vault has already been initialized, else raise an exception
    if not vault_client.sys.is_initialized():
        raise RuntimeError("Vault instance must already be initialized and preconfigured before use in application!")

    # If vault is currently unsealed attempt to unseal it using the provided unseal keys
    if vault_client.sys.is_sealed():
        try:
            print("Vault is currently sealed. Attempting to unseal the vault using unseal keys...")
            unseal_vault_server(vault_client, unseal_keys)
        # If unsealing process raises an exception indicating failure to unseal vault, raise exception in main function
        except RuntimeError:
            raise RuntimeError("Vault unsealing failed! Please ensure provided unseal keys are valid!")
    try:
        print("Attempting to upgrade connection with vault using application-configured settings...\n")
        initial_vault = create_unauthenticated_vault_connection(
            vault_address=vault_client.url,
            proxy_address=proxy_address,
            certs=certs,
            unseal_keys=unseal_keys
        )
        vault_client.adapter.close()
        print("Attempting to authenticate to running vault instance using provided vault access token...")
        authenticated_vault = get_authenticated_vault(initial_vault, token, certs, proxy_address)
    except RuntimeError:
        raise RuntimeError("Authentication with vault instance failed! Please ensure the provided token is valid!")

    return authenticated_vault
