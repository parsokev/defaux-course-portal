import requests
import json
import os
from urllib.request import urlopen
from . import db_utils as db_op
from jose import jwt
from functools import wraps
from flask import session, flash, url_for, redirect

# Nginx Reverse-Proxy Server External Address
PROXY_ADDR = os.environ["PROXY_ADDR"].strip()
ALGORITHMS = ["RS256"]
APP_ENV = os.environ["APP_ENV"]

if APP_ENV != 'deploy' and APP_ENV != 'test':
    from . import vc_utils as vc_op
    # Injected Vault Secrets
    vc_data = vc_op.get_secrets()

    CLIENT_ID = vc_data["CLIENT_ID"]
    CLIENT_SECRET = vc_data["CLIENT_SECRET"]
    DOMAIN = vc_data["DOMAIN"]
    AUTH_MANAGEMENT_API_ID = vc_data["AUTH_MANAGEMENT_API_ID"]
    DEFAULT_ADMIN_USERNAME = vc_data["DEFAULT_ADMIN_USERNAME"]
    DEFAULT_ADMIN_PASS = vc_data["DEFAULT_ADMIN_PASS"]
    AUTH_DB_CONNECTION = vc_data["AUTH_DB_CONNECTION"]

else:
    CLIENT_ID = os.environ["CLIENT_ID"]
    CLIENT_SECRET = os.environ["CLIENT_SECRET"]
    DOMAIN = os.environ["DOMAIN"]
    AUTH_MANAGEMENT_API_ID = os.environ["AUTH_MANAGEMENT_API_ID"]
    DEFAULT_ADMIN_USERNAME = os.environ["DEFAULT_ADMIN_USERNAME"]
    DEFAULT_ADMIN_PASS = os.environ["DEFAULT_ADMIN_PASS"]
    AUTH_DB_CONNECTION = os.environ["AUTH_DB_CONNECTION"]

# Error Message Constants
# 400
BAD_REQUEST = 'Invalid request'
# 401
UNAUTHORIZED = 'Unauthorized'
# 403
FORBIDDEN = "You don't have permission to access this resource"
# 404
NOT_FOUND = 'Not found'
# 409
CONFLICT = 'Submission data is invalid'

# ===================================== WSGI SERVER ROUTE GUARDS ========================================

# https://stackoverflow.com/questions/32640090/python-flask-keeping-track-of-user-sessions-how-to-get-session-cookie-id


# Route guard wrapper for endpoints that are restricted to authenticated users only (role agnostic)
def check_user(route_handler):
    @wraps(route_handler)
    def wrapper(*args, **kwargs):
        has_creds = 'credentials' in session
        if has_creds:
            # Build request object with authorization header using session token
            ses_request = build_auth_headers(session['credentials'])
            try:
                # Send request to Auth0 for authentication and extract auth sub
                payload = verify_jwt(ses_request)
            except AuthError:
                return route_handler(*args, **kwargs)
            
            # Retrieve user with matching authenticated subject from database
            match_user = db_op.check_for_user(str(payload['sub']))
            if match_user is None:
                return route_handler(*args, **kwargs)
            
            # Set session variables for referencing authenticated user information
            session['user_id'] = match_user['id']
            session['user_subject'] = str(payload['sub'])
            return route_handler(*args, **kwargs)
        else:
            return route_handler(*args, **kwargs)
    return wrapper


# Route guard wrapper for endpoints that are restricted to authenticated users only (role agnostic)
def authenticate_user(route_handler):
    @wraps(route_handler)
    def wrapper(*args, **kwargs):
        has_creds = 'credentials' in session
        if has_creds:
            # Build request object with authorization header using session token
            ses_request = build_auth_headers(session['credentials'])
            try:
                # Send request to Auth0 for authentication and extract auth sub
                payload = verify_jwt(ses_request)
            except AuthError:
                # If submitted login credentials are invalid, redirect to error page
                # Retain AuthError output for debugging, return generic msg
                flash(f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.",
                       category='unauthorized-user-error')
                return redirect(url_for('login', logged_in=False), code=301)
            
            # Retrieve user with matching authenticated subject from database
            match_user = db_op.check_for_user(str(payload['sub']))
            if match_user is None:
                flash(f"ERROR: {NOT_FOUND}. User with username/email no longer exists. Please login with a different username/email",
                       category="user-not-found-error")
                # If no matching user is found in database, redirect to user login page
                return redirect(url_for('login', logged_in=False), code=301)
            
            # Set session variables for referencing authenticated user information
            session['user_id'] = match_user['id']
            session['user_subject'] = str(payload['sub'])
            return route_handler(*args, **kwargs)

        else:
            # Redirect to login page if user is not logged in
            flash(f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.",
                   category='unauthorized-user-error')
            session.clear()
            return redirect(url_for('login', logged_in=False), code=301)
    return wrapper


# For pages that contain both restricted and unrestricted features, assess whether user's session credentials are valid
def verify_user_credentials() -> tuple[bool, dict | None]:
    # Verify user has all session keys populated after completing successful login
    has_session_creds = 'credentials' in session and 'user_id' in session and 'user_subject' in session
    has_populated_creds = (
        has_session_creds and len(str(session['credentials']).strip()) > 0 and
        len(str(session['user_id']).strip()) > 0 and len(str(session['user_subject']).strip()) > 0
    )
    # Authenticate session credentials
    if not has_populated_creds:
        return (False, None)
        

    # Build request object with authorization header using session token
    ses_request = build_auth_headers(session['credentials'])
    try:
        # Send request to Auth0 for authentication and extract auth sub
        payload = verify_jwt(ses_request)
        session['user_subject'] = (
            str(payload['sub']) if str(payload['sub']) != session['user_subject']
            else session['user_subject']
        )
    except AuthError:
        return (False, None)
    # Retrieve user with matching authenticated subject from database
    match_user = db_op.check_for_user(session['user_subject'])
    if match_user is None:
        return (False, None)
    session['user_id'] = (
        match_user['id'] if session['user_id'] != match_user['id']
        else session['user_id']
    )
    return (True, match_user)


# Route guard wrapper for endpoints that are restricted to authenticated admin users only
def verify_admin_user(route_handler):
    @wraps(route_handler)
    def wrapper(*args, **kwargs):
        has_creds = 'credentials' in session and len(str(session['credentials']).strip()) > 0
        if has_creds:
            # Build request object with authorization header using session token
            ses_request = build_auth_headers(session['credentials'])
            try:
                # Send request to Auth0 for authentication and extract auth sub
                payload = verify_jwt(ses_request)
            except AuthError:
                # If submitted login credentials are invalid, redirect to error page
                # Retain AuthError output for debugging, return generic msg
                flash(
                    f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.",
                    category='unauthorized-user-error'
                )
                session.clear()
                return redirect(url_for('login', logged_in=False), code=301)
                        # Retrieve user with matching authenticated subject from database
            match_user = db_op.check_for_user(str(payload['sub']))
            if match_user is None:
                flash(f"ERROR: {NOT_FOUND}. User with username/email no longer exists. Please login with a different username/email",
                 category="user-not-found-error")
                # If no matching user is found in database, redirect to user login page
                session.clear()
                return redirect(url_for('login', logged_in=False), code=301)
            
            # Update session variables for referencing authenticated user information
            session['user_id'] = match_user['id']
            session['user_subject'] = str(payload['sub'])
            is_admin = db_op.verify_admin(session['user_subject'])

            if not is_admin:
                # If user is not an admin user, redirect back to homepage since they are still an authenticated user
                flash(f"ERROR: {FORBIDDEN}. You are not authorized to access this resource.", category='forbidden-user-error')
                return redirect(url_for('get_matching_user', user_id=match_user['id'], logged_in=False), code=301)
            
            # If user is a verified user, allow user to access admin-only endpoint
            return route_handler(*args, **kwargs)
        else:
            # If user is not logged in, redirect to login page
            flash(f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please log in.", category='unauthorized-user-error')
            return redirect(url_for('login', logged_in=False), code=301)
        
    return wrapper

# ================ APPLICATION AUTHORIZATION/AUTHENTICATION EXCEPTION CLASS =====================

# Customized Exception Class for handling JWT, Endpoint, User Authentication/ Authorization errors
class AuthError(Exception):
    def __init__(self, error, status_code, debugMsg):
        self.error = error
        self.status_code = status_code
        self.debugMsg = debugMsg


# =============================== JWT VERIFICATION OPERATIONS ==================================

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    # Check for JWT token in Authorization Headers of request object
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        # Extract 'id_token' value
        token = auth_header[1]
    else:
        # If JWT is absent (no Authorization Headers at all), throw
        # customized Exception class with output to return in response
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)
    # Extract response object from Auth Domian that is in JSON format
    jsonurl = urlopen(DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        # Attempt to decode JWT header contents and return dict on success
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        # Throw exception with appropriate output in response if invalid
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    # Check 'alg' value in JWT header for verification it is expected alg type
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    # If alg uses RSA256, verify and extract RSA key for decoding JWT contents
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    # If RSA key is present, use it along with user credentials to decode JWT
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer=DOMAIN + "/"
            )
        # Catch exceptions and return output based on condition that raised it
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)
        # Prevent logging of sensitive payload data generated by key errors if payload is missing subject
        if 'sub' not in payload:
            raise AuthError({"code": "invalid_payload",
                             "description":
                             "Decrypted payload is missing expected subject field"},
                             401)
        # If no exceptions thrown in decoding process, JWT is valid
        return payload
    else:
        # If valid RSA key not found in JWT, throw exception
        raise AuthError({"code": "no_rsa_key",
                         "description":
                         "No RSA key in JWKS"}, 401)


# ======================== FLASK AUTHORIZATION OPERATIONS ==============================


def build_auth_headers(token: str) -> requests.Request:
    token_headers = {'content-type': 'application/json',
                     'Authorization': f'Bearer {token}'}
    # Build request object using received authorization token in header
    payload_request = requests.Request('GET', headers=token_headers)

    return payload_request


def get_api_access_token():
    # Use a root admin user's credentials to generate a new ID token for authenticating with Auth0 application
    pw_body = {
        'grant_type': 'password', 'username': DEFAULT_ADMIN_USERNAME, 'password': DEFAULT_ADMIN_PASS,
        'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    id_token_request_url = DOMAIN + '/oauth/token'
    admin_ID_token_request = requests.post(url=id_token_request_url, json=pw_body, headers=headers, timeout=3).json()
        
    # Extract 'id_token' from response and place it as an authorization header in a new request
    if 'id_token' not in admin_ID_token_request:
        raise AuthError(error=f"ERROR: {FORBIDDEN}. Invalid password or username. Please retry with different credentials.",
                        status_code=403, debugMsg="ERROR: id_token not found in request for default admin ID token")
    user_token = admin_ID_token_request['id_token']
    token_headers = {'content-type': 'application/json',
                    'Authorization': f"Bearer {user_token}"}
    # Build request object using received authorization token in header
    payload_request = requests.Request('GET', headers=token_headers)
    # Send newly constructed request to verify_jwt to verify received id_token JWT is valid and extract its payload upon success
    try:
        payload = verify_jwt(payload_request)
    except AuthError:
        # Catch thrown AuthError exceptions due to invalid JWT errors
        raise AuthError(error=f"ERROR: {FORBIDDEN}. Invalid password or username. Please retry with different credentials.",
                        status_code=403, debugMsg="ERROR: Default admin id_token JWT was malformed or invalid!")
    
    # Submit request to Auth0's Management API OAuth token endpoint using client_credentials grant type and extracted id_token
    cc_body = {
        "grant_type": 'client_credentials', 'client_id': CLIENT_ID,  'client_secret': CLIENT_SECRET,
        'audience': AUTH_MANAGEMENT_API_ID
    }
    access_token_response = requests.post(url=id_token_request_url, json=cc_body, headers=token_headers, timeout=3).json()
    if 'access_token' not in access_token_response:
        raise AuthError(
            error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
            debugMsg="ERROR: Access_token not found in response to auth management API access token request!"
        )
    # Extract 'access_token' from response to be used as access token for placing user-based request to Auth0 Management API endpoints
    return access_token_response['access_token']


def retrieve_user_id(email, password):
    # Generate new request for receiving the JWT payload containing the user's Auth0-issued ID
    new_user_body = {
        'grant_type': 'password', 'username': email, 'password': password,
        'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET
    }
    user_id_token_url = DOMAIN + '/oauth/token'
    user_id_token_headers = {'content-type': 'application/json'}

    # Submit request to Auth0 token endpoint to retrieve new user's ID token
    new_user_token_request = requests.post(url=user_id_token_url, json=new_user_body, headers=user_id_token_headers, timeout=3)
    if 'id_token' not in new_user_token_request.json():
        raise AuthError(error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
                        debugMsg=f"ERROR: Request for id token of newly added user failed with status code: {new_user_token_request.status_code}")

    # Build request object using received ID token in authorization header
    new_user_token = new_user_token_request.json()['id_token']
    user_token_headers = {'content-type': 'application/json',
                    'Authorization': f"Bearer {new_user_token}"}
    user_payload_request = requests.Request('GET', headers=user_token_headers)
    try:
        # Send constructed request to verify received id_token JWT is valid
        user_payload = verify_jwt(user_payload_request)
    except AuthError:
        raise AuthError(error=f"ERROR: {FORBIDDEN}. Invalid password or username. Please retry with different credentials.", status_code=403,
                        debugMsg="ERROR: Request for user's ID produced an invalid or malformed JWT")
    
    # Extract the user id from the validated JWT payload's subject field
    return str(user_payload['sub'])


def register_new_auth0_user(access_token: str, email: str, password: str) -> None:
    try:
        # Retrieve Auth0 Management API access token and build request for submitting new user
        access_token_headers = {
            'content-type': 'application/json',
            'Authorization': f"Bearer {access_token}"
        } 
        add_user_url = f"{AUTH_MANAGEMENT_API_ID}users"
        add_user_body = {
            "email": email, "password": password,
            "connection": AUTH_DB_CONNECTION
        }
        add_auth0_user_response = requests.post(url=add_user_url, json=add_user_body, headers=access_token_headers, timeout=3)
        # Verify successful addition of user to Auth0 database with 201 response status
        if add_auth0_user_response.status_code != 201:
            raise AuthError(error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
                            debugMsg=f" ERROR: Create user request failed with status code {add_auth0_user_response.status_code}!")
        
    except AuthError as e:
        # Catch thrown AuthError exceptions and forward the exception to parent calling function
        raise AuthError(error=f"{e.error}", status_code=e.status_code, debugMsg=e.debugMsg)


def get_auth0_role(access_token: str, user_id: str) -> str:
    # Build Auth0 Management API request for retrieving assigned role of registered Auth0 user with matching userID
    access_token_headers = {
        'content-type': 'application/json', 'Authorization': f"Bearer {access_token}"
    }
    request_user_role_url = f"{AUTH_MANAGEMENT_API_ID}users/{user_id}/roles"
    user_role_response = requests.get(url=request_user_role_url, headers=access_token_headers)

    # Confirm request successfully returns a list of one or more roles assigned to the user
    if user_role_response.status_code != 200:
        raise AuthError(error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
                        debugMsg=f"ERROR: Request for user's assigned roles failed with status code {user_role_response.status_code}")
    
    if user_role_response.json() is None or len(user_role_response.json()) == 0 or len(user_role_response.json()) > 1:
        raise AuthError(
            error=f"ERROR: {BAD_REQUEST}. One or more required information fields are missing.", status_code=400,
            debugMsg=f"ERROR: Request for user's assigned roles returned an unexpected or empty role response of {user_role_response.json()}"
        )
    # Return the first array index Auth0-assigned roles for the specified user
    return user_role_response.json()[0]['name']


def assign_auth0_role(access_token: str, user_id: str, role_id: str) -> None:
    # Build Auth0 Management API request for assigning role to registered Auth0 user with matching ID
    access_token_headers = {
        'content-type': 'application/json', 'Authorization': f"Bearer {access_token}"
    }
    assign_role_url = f"{AUTH_MANAGEMENT_API_ID}users/{user_id}/roles"
    assign_role_body = { "roles": [ role_id ] }
    assign_user_role_response = requests.post(url=assign_role_url, json=assign_role_body, headers=access_token_headers)

    # Verify assignment of specified role to new user to Auth0 database with 204 response status    
    if assign_user_role_response.status_code != 204:
        raise AuthError(
            error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
            debugMsg=f"ERROR: Assign new user role request failed with status code {assign_user_role_response.status_code}!"
        )


def update_auth0_user(access_token: str, user: dict, update_request: dict) -> None:
    # Build Auth0 Management API request for assigning role to registered Auth0 user with matching ID
    access_token_headers = {
        'content-type': 'application/json', 'Authorization': f"Bearer {access_token}"
    }

    if 'sub' not in user:
        raise AuthError(
            error=f"ERROR: {BAD_REQUEST}. Invalid or incomplete user attributes provided for user to be updated. Please retry.", status_code=400,
            debugMsg=f"ERROR: 'sub' not found in user with matching id retrieved from MySQL database!"
        )

    update_user_url = f"{AUTH_MANAGEMENT_API_ID}users/{user['sub']}"
    update_user_body = {}
    update_user_body['client_id'] = CLIENT_ID
    update_user_body['connection'] = AUTH_DB_CONNECTION
    for prop in update_request:
        match prop:
            case "email":
                update_user_body['email'] = update_request['email']
                update_user_body['name'] = update_request['email']
                update_user_body['nickname'] = str(update_request['email'])[:str(update_request['email']).strip().find('@')]
            case "password":
                update_user_body['password'] = update_request['password']
            case _:
                continue
    
    update_user_response = requests.patch(url=update_user_url, json=update_user_body, headers=access_token_headers)
    if update_user_response.status_code != 200:
        raise AuthError(
            error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
            debugMsg=f"ERROR: Update user request failed with status code {update_user_response.status_code}!\n\tUpdate User Request Body: {update_user_body}\n\tUpdate User Response: {update_user_response.json()}"
        )
    


def delete_auth0_user(access_token: str, user: dict) -> None:
    # Build Auth0 Management API request for assigning role to registered Auth0 user with matching ID
    access_token_headers = {
        'content-type': 'application/json', 'Authorization': f"Bearer {access_token}"
    }

    if 'sub' not in user:
        raise AuthError(
            error=f"ERROR: {BAD_REQUEST}. Invalid or incomplete user attributes provided for user to be updated. Please retry.", status_code=400,
            debugMsg=f"ERROR: 'sub' not found in user with matching id retrieved from MySQL database!"
        )

    delete_user_url = f"{AUTH_MANAGEMENT_API_ID}users/{user['sub']}"

    delete_user_response = requests.delete(url=delete_user_url, headers=access_token_headers)
    if delete_user_response.status_code != 204:
        raise AuthError(
            error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
            debugMsg=f"ERROR: Delete user request failed with status code {delete_user_response.status_code}!\n\tDelete User Response: {delete_user_response.json()}"
        )