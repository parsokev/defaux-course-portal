from . import vc_utils as vc_op
from . import update_gcp_secrets as gcp_op
from subprocess import run, CalledProcessError
import os
import requests
import secrets

UPDATE_CREDS = True if os.environ["UPDATE_CREDS"] == 'true' else False

def rotate_app_creds_using_gcloud():
    try:
        # Ensure you have your HashiCorp Vault server instance running before executing this python script!
        print("Request to update GCP OAuth2 Service Token received. Gathering required authorization credentials...")

        # Extract required authentication credentials from vault secrets
        vc_data = vc_op.get_secrets()
        GCP_SERVICE_ACCOUNT = vc_data["GCP_SERVICE_ACCOUNT"]

        print("Attempting to authenticate with gcloud using chosen service account...")
        run(["gcloud", "auth", "activate-service-account", f"{GCP_SERVICE_ACCOUNT}", f"--key-file={os.environ["CRED_FILE"]}"],
            check=True)
        
        print("Attempting to retrieve new temporary GCP access token using specified service account...")
        token = run(["gcloud", "auth", "print-access-token", f"--impersonate-service-account={GCP_SERVICE_ACCOUNT}"],
                    capture_output=True, text=True, check=True)
        
        print("Successfully retrieved temporary GCP Service Token! Refreshing service token and server session secrets...")

        app_session_secret = secrets.token_urlsafe(32)

        # Add or update the key for storing the value of the issued temporary service token to the vault's secrets
        vc_op.update_secrets({ "TMP_SERVICE_TOKEN": token.stdout, "APP_SECRET": app_session_secret})
        gcp_op.update_gcp_secret("TMP_SERVICE_TOKEN", token.stdout)
        gcp_op.update_gcp_secret("APP_SECRET", app_session_secret)
        gcp_op.update_gcp_certs(UPDATE_CREDS)
        print("Refreshing of temporary service authentication token and server session complete!")

    except CalledProcessError as e:
        print(f"ERROR: Authenticating as chosen service account failed with exit code '{e.returncode}'")
        print(f"OUTPUT: {e.output}")
    except Exception as other:
        print(f"ERROR: Unexpected exception thrown: {other}")


def rotate_app_creds_using_rest():
    # See official GCP Documentation on creating temporary service tokens using Google STS token exchange
    # https://docs.cloud.google.com/iam/docs/create-short-lived-credentials-direct#rest_6
    # https://docs.cloud.google.com/iam/docs/tutorial-cloud-run-workload-id-federation

    # NOTE: Ensure you have already setup workload federated identity that utilizes the specified service account
    # For possible ways to do this, an excellent source for completing this process this can be found here:
    # https://gist.github.com/wvanderdeijl/95f511d4f2749b8b6ad38c26f27da251
    try:
        # Extract required authentication credentials from vault secrets
        print("Authenticating with running vault server to retrieve required service account credentials...")
        vc_data = vc_op.get_secrets()

        WIF_AUDIENCE = vc_data["WIF_AUDIENCE"]
        MTM_CLIENT_ID = vc_data["MTM_CLIENT_ID"]
        MTM_CLIENT_SECRET = vc_data["MTM_CLIENT_SECRET"]
        DOMAIN = vc_data["DOMAIN"]
        GCP_SERVICE_ACCOUNT = vc_data["GCP_SERVICE_ACCOUNT"]

        print("Credentials successfully retrieved from vault secrets. Submitting request for retrieval of Auth0 OIDC Access Token...")
        # Retrieve OAuth OIDC access token from Auth0 token endpoint
        auth0_access_token_response = requests.post(
            url=f"{DOMAIN}/oauth/token",
            headers={"content-type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": MTM_CLIENT_ID,
                "client_secret": MTM_CLIENT_SECRET,
                "audience": WIF_AUDIENCE
            }
        ).json()

        # print(f"Auth0 Access Token Response: {auth0_access_token_response}")
        if 'access_token' not in auth0_access_token_response:
            print("Access token not found in response to Auth0 OIDC Access Token request! Please ensure request headers and body are valid")
            return
        
        auth0_access_token = auth0_access_token_response["access_token"]

        print("Submitting request to exchange Auth0 OIDC access token with temporary Google STS token...")
        # Exchange OIDC token for an OAuth2 Google STS token
        sts_token_response = requests.post(
            url="https://sts.googleapis.com/v1/token",
            headers={ "content-type": "application/x-www-form-urlencoded" },
            data={
                "audience": WIF_AUDIENCE,
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "subject_token": auth0_access_token
            }
        ).json()

        if 'access_token' not in sts_token_response:
            print("Access token not found in response to OAuth2 Google STS token request! Please ensure you have:\n")
            print("\t\tProperly setup a valid workload federated identity for the specified GCP service account")
            print("\t\tSetup a workload pool provider using Auth0 as the external OIDC provider")
            print("\t\tConfigured the machine-to-machine application and standalone api within your Auth0 application")
            print("Please review the project README for further details on the setup process")
            return
        sts_token = sts_token_response["access_token"]
        # print(f"STS Token Response: {sts_token_response}")

        print("Submitting request to generate a short-lived Google OAuth2.0 access token impersonating the specified Google service account...")
        # print("Attempting to generate signed JWT for authenticating as requested GCP service account...")
        # # Generate stringified JWT payload using service account with updated issue time and staggered expiration timestamp 
        # jwt_payload_value = (
        #     "{" +
        #     "\"sub\":\"" + GCP_SERVICE_ACCOUNT +
        #     "\",\"iss\":\"" + GCP_SERVICE_ACCOUNT +
        #     "\",\"aud\":\"" + "http://127.0.0.1:8080" +
        #     "\",\"iat\":" + f"{int(datetime.now().timestamp())}" + 
        #     ",\"exp\":" + f"{int(datetime.now().timestamp() + 300)}" +
        #     "}"
        # )

        # Generate an OAuth2 service token that impersonates the specified Google Service Account using the STS token in authorization header
        tmp_service_token_response = requests.post(
            url=f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{GCP_SERVICE_ACCOUNT}:generateAccessToken",
            # url=f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{GCP_SERVICE_ACCOUNT}:signJwt",
            headers={ "content-type": "application/x-www-form-urlencoded", "Authorization": f"Bearer {sts_token}" },
            data={
                # "payload": jwt_payload_value
                "scope": [
                    "https://www.googleapis.com/auth/sqlservice.admin",
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/iam"
                ]
            }
        ).json()

        if 'accessToken' not in tmp_service_token_response:
            print("Access token not found in response to OAuth2 Google STS token request! Please ensure request headers and body are valid")
            print("Please ensure you have: \n")
            print("\t\tProperly setup a valid workload federated identity for the specified GCP service account")
            print("\t\tSetup a workload pool provider using Auth0 as the external OIDC provider")
            print("\t\tConfigured the machine-to-machine application and standalone api within your Auth0 application")
            print("Please review the project README for further details on the setup process")
            return
        # print(f"Temporary Service Token Response: {tmp_service_token_response}")
        tmp_service_token = tmp_service_token_response["accessToken"]

        app_session_secret = secrets.token_urlsafe(32)

        # Add or update the key for storing the valut of the issued temporary service JWT to the vault's secrets
        print("Attempting to update vault with updated application credentials...")
        vc_op.update_secrets({ "TMP_SERVICE_TOKEN": tmp_service_token, "APP_SECRET": app_session_secret})
        print("Attempting to update GPC secrets manager with updates applicaiton credentials...")
        gcp_op.update_gcp_secret("TMP_SERVICE_TOKEN", tmp_service_token)
        gcp_op.update_gcp_secret("APP_SECRET", app_session_secret)
        gcp_op.update_gcp_certs(UPDATE_CREDS)
        print("Refreshing of temporary service authentication token complete!")
    except Exception as e:
        print(f"Generation of short-lived OAuth2.0 Google Access Token failed with the following exception:\n\t{e}")


if __name__ == "__main__":
    # rotate_app_creds_using_gcloud()
    rotate_app_creds_using_rest()