from . import vc_utils as vc_op
from google.cloud import secretmanager
from google.oauth2.credentials import Credentials
from google.api_core.exceptions import AlreadyExists
import os


# Adapted from code snippets provided by Google secret manager codelabs.
# See https://codelabs.developers.google.com/codelabs/secret-manager-python#5
def create_secret(credentials: str, project_id: str, secret_id: str):
    """Create a new secret in Secret Manager."""
    gcp_credentials = Credentials(credentials)
    gcp_sm_client = secretmanager.SecretManagerServiceClient(credentials=gcp_credentials)
    parent = f"projects/{project_id}"

    # Build a dict of settings for the secret (automatic replication is recommended)
    secret = {'replication': {'automatic': {}}}

    # Create the secret
    response = gcp_sm_client.create_secret(
        request={"parent": parent, "secret_id": secret_id, "secret": secret}
    )
    print(f'Created secret: {response.name}')
    return response.name


# Adapted from code snippets provided by Google secret manager codelabs.
# See https://codelabs.developers.google.com/codelabs/secret-manager-python#5
def add_secret_version(credentials: str, project_id: str, secret_id: str, payload):
    """Add a new version to an existing secret with the given payload."""
    gcp_credentials = Credentials(credentials)
    gcp_sm_client = secretmanager.SecretManagerServiceClient(credentials=gcp_credentials)
    # Build the resource name of the parent secret
    parent = f"projects/{project_id}/secrets/{secret_id}"
    
    # Convert the string payload into bytes, as required by the API
    if isinstance(payload, str):
        payload_bytes = payload.encode('UTF-8')
    else:
        payload_bytes = payload

    # Add the secret version
    response = gcp_sm_client.add_secret_version(
        request={"parent": parent, "payload": {"data": payload_bytes}}
    )
    print(f'Added secret version: {response.name}')


def update_gcp_secrets():
    vc_data = vc_op.get_secrets()
    access_token = str(vc_data["TMP_SERVICE_TOKEN"]).strip()
    project_id = vc_data["PROJECT_ID"]

    try:
        for name, value in dict(vc_data).items():
           secret_name = create_secret(credentials=access_token, project_id=project_id, secret_id=name)
           if secret_name != name:
               print(f"Returned secret name or ID does not match initial name of secret '{name}'!")
    except AlreadyExists:
        print(f"Secret '{name}' already exists in GCP secrets manager!")
    try:
        for name, value in dict(vc_data).items():
            add_secret_version(credentials=access_token, project_id=project_id, secret_id=name, payload=value)
    except Exception as e:
        raise RuntimeError(f"Failed to update secret version for '{name}': {e}")


def update_gcp_certs(new_creds: bool = False):
    if new_creds:
        vc_data = vc_op.get_secrets()
        access_token = str(vc_data["TMP_SERVICE_TOKEN"]).strip()
        project_id = vc_data["PROJECT_ID"]
        ssl_cert_secrets = {}
        ssl_cert_secrets["SSL_CERT_FILE"] = os.environ["SSL_CERT_FILE"]
        ssl_cert_secrets["SSL_CERT_KEY_FILE"] = os.environ["SSL_CERT_KEY_FILE"]

        try:
            for name, value in ssl_cert_secrets.items():
                secret_name = create_secret(credentials=access_token, project_id=project_id, secret_id=name)
            if secret_name != name:
                print(f"Returned secret name or ID does not match initial name of secret '{name}'!")
        except AlreadyExists:
            print(f"Secret '{name}' already exists in GCP secrets manager!")
        try:
            for name, value in ssl_cert_secrets.items():
                add_secret_version(credentials=access_token, project_id=project_id, secret_id=name, payload=value)
        except Exception as e:
            raise RuntimeError(f"Failed to update secret version for '{name}': {e}")
    else:
        print("Bypassing repopulating of existing credentials..")


def update_gcp_secret(secret_name: str, secret_value: str):
    vc_data = vc_op.get_secrets()
    access_token = str(vc_data["TMP_SERVICE_TOKEN"]).strip()
    project_id = vc_data["PROJECT_ID"]
    try:
        add_secret_version(credentials=access_token, project_id=project_id, secret_id=secret_name, payload=secret_value)
    except Exception as e:
        raise RuntimeError(f"Failed to update secret version for '{secret_name}': {e}")


def get_gcp_secret(secret_id: str, version_id="latest", is_deployed: bool = False):
    # Create the Secret Manager client.
    if is_deployed:
        gcp_sm_client = secretmanager.SecretManagerServiceClient()
        project_id = os.environ["PROJECT_ID"]
    else:
        vc_data = vc_op.get_secrets()
        access_token = str(vc_data["TMP_SERVICE_TOKEN"]).strip()
        project_id = vc_data["PROJECT_ID"]
        gcp_credentials = Credentials(access_token)
        gcp_sm_client = secretmanager.SecretManagerServiceClient(credentials=gcp_credentials)
    
    secret_resource_name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = gcp_sm_client.access_secret_version(name=secret_resource_name)

    # Return the decoded payload.
    return response.payload.data.decode('UTF-8')


if __name__ == "__main__":
    update_gcp_secrets()
    update_gcp_certs(False)