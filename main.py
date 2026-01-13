from __future__ import annotations

from flask import (Flask, request, send_file, render_template, jsonify,
                   redirect, url_for, session, flash)
from google.cloud import storage
from authlib.integrations.flask_client import OAuth
from google.oauth2.credentials import Credentials
from utils.auth_utils import (
    verify_jwt, AuthError, build_auth_headers,
    authenticate_user, verify_admin_user,
    register_new_auth0_user, retrieve_user_id, get_api_access_token,
    assign_auth0_role, get_auth0_role, check_user, verify_user_credentials,
    update_auth0_user, delete_auth0_user
)
import utils.db_utils as db_op
import io
import requests
import json
import logging
import os


# ========================= APPLICATION CONSTANTS =========================

# Host Machine Constants
HOST_URL = os.environ["HOSTNAME"]
HOST_PORT = os.environ["PORT"]

# Nginx and Vault Address Configuration Settings
PROXY_ADDR = os.environ["PROXY_ADDR"].strip()
APP_ENV = os.environ["APP_ENV"].strip()

# Imported File Constants
COURSES_FILE = 'course_sheet.json'

# URL/table entity constants
USERS = 'users'
COURSES = 'courses'

# Error Message Constants
BAD_REQUEST = 'Invalid request' # 400
UNAUTHORIZED = 'Unauthorized' # 401
FORBIDDEN = "You do not have permission to access this resource" # 403
NOT_FOUND = 'Not found' # 404
CONFLICT = 'Submission data is invalid' # 409

# Flask Server/Application Configuration Settings
app = Flask(__name__)

app.static_folder = 'static'


if APP_ENV != 'deploy' and APP_ENV != 'test':
    VAULT_ADDR = os.environ["VAULT_ADDR"].strip()
    import utils.vc_utils as vc_op
    logger = logging.getLogger()
    vc_data = vc_op.get_secrets()
    app.secret_key = vc_data["APP_SECRET"]

    # Auth0 Client and Server Configuration Constants
    CLIENT_ID = vc_data['CLIENT_ID']
    CLIENT_SECRET = vc_data["CLIENT_SECRET"]
    DOMAIN = vc_data["DOMAIN"]
    ADMIN_ROLE_ID = vc_data["ADMIN_ROLE_ID"]
    STUDENT_ROLE_ID = vc_data["STUDENT_ROLE_ID"]
    INSTRUCTOR_ROLE_ID = vc_data["INSTRUCTOR_ROLE_ID"]

    # Google Cloud Client Library Configuration Constants
    PROJECT_ID = vc_data["PROJECT_ID"]
    AVATAR_BUCKET = vc_data["AVATAR_BUCKET_NAME"]
    ACCESS_TOKEN = str(vc_data["TMP_SERVICE_TOKEN"]).strip()
    credentials = Credentials(ACCESS_TOKEN)
    storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
else:
    app.secret_key = os.environ['APP_SECRET']
    CLIENT_ID = os.environ['CLIENT_ID']
    CLIENT_SECRET = os.environ["CLIENT_SECRET"]
    DOMAIN = os.environ["DOMAIN"]
    ADMIN_ROLE_ID = os.environ["ADMIN_ROLE_ID"]
    STUDENT_ROLE_ID = os.environ["STUDENT_ROLE_ID"]
    INSTRUCTOR_ROLE_ID = os.environ["INSTRUCTOR_ROLE_ID"]

    # Google Cloud Client Library Configuration Constants
    PROJECT_ID = os.environ["PROJECT_ID"]
    AVATAR_BUCKET = os.environ["AVATAR_BUCKET_NAME"]

    if APP_ENV == 'test':
        ACCESS_TOKEN = str(os.environ["TMP_SERVICE_TOKEN"]).strip()
        credentials = Credentials(ACCESS_TOKEN)
        storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
    else:
        storage_client = storage.Client(project=PROJECT_ID)   


# Initialize OAuth
oauth = OAuth(app)

# Register client credentials with oauth
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=DOMAIN,
    access_token_url=DOMAIN + "/oauth/token",
    authorize_url=DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# Establish initial connection to MySQL database instance and create a new connection pool
db_op.init_db()


# ==================================  TODOS ===========================================

# TODO: Address potential occasional pagination issues when dynamically deleting a course and redirecting to courses page
# or potential SQL query ordering conflicts (FUTURE)

# TODO: Address additional potential updates to set secrets files access permissions (FUTURE)

# TODO: Update configuration of course prepopulate features using course_sheet.json and README details (FUTURE)

# TODO: Update authorization middleware to handle optional checking of Auth0-assigned role of a
# given user (FUTURE)

# TODO: Update rotate_vault+credentials rotation script for potential hashing of vault userpass password environment variable (FUTURE)

# TODO: If performant, introduce dual checking of both database user's role AND
# Auth0-assigned role of admin user when assessed by admin-only route guard
# More important when abilities of admin users are expanded (FUTURE)


# ====================== APPLICATION ENDPOINTS/FUNCTIONS ===============================

# Format error output within response body when AuthError exceptions are thrown/raised
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# ======================= GOOGLE STORAGE CLIENT OPERATIONS ============================

# Delete a user's avatar image file from Google Cloud Storage
def delete_avatar(avatar_filename: str) -> None:
    """
    Deletes avatar file with name of `avatar_filename` from specified
    bucket for holding avatar image files on Google Cloud Storage

    Parameters:
        avatar_filename (str): Name of file to be deleted from GCS

    Returns:
        NoneType: None
    """
    # Ensure previous avatar file is safely deleted from avatar bucket
    # using conventions provided by GCP documentation:
    # https://github.com/googleapis/python-storage/blob/main/samples/snippets/storage_delete_file.py
    avatar_bucket = storage_client.get_bucket(AVATAR_BUCKET)
    match_avatar = None
    user_avatar = avatar_bucket.blob(blob_name=avatar_filename)
    user_avatar.reload()
    match_avatar = user_avatar.generation
    user_avatar.delete(if_generation_match=match_avatar)
    return

# ================================== HOMEPAGE ENDPOINT ========================================

# Homepage Route
@app.route('/')
def index():
    # Route guard will clear session data if user fails initial authentication check
    has_creds = 'credentials' in session
    if has_creds:
        # Build request object with authorization header using session token
        ses_request = build_auth_headers(session['credentials'])
        try:
            # Send request to Auth0 for authentication and extract auth sub
            payload = verify_jwt(ses_request)
        except AuthError:
            session.clear()
            return render_template('index.j2', logged_in=False)

        if 'sub' not in payload:
            session.clear()
            return render_template('index.j2', logged_in=False)
        # Retrieve user with matching authenticated subject from database
        match_user = db_op.check_for_user(str(payload['sub']))
        if match_user is None:
            session.clear()
            return render_template('index.j2', logged_in=False)
        
        # Set session variables for referencing authenticated user information
        session['user_id'] = match_user['id']
        session['user_subject'] = str(payload['sub'])
        return render_template('index.j2', logged_in=True, user_id=session['user_id'])

    return render_template('index.j2', logged_in=False)

# ============================ USER ACCOUNT CREATION ENDPOINTS ================================

# Unrestricted GET endpoint for rendering create user account form with fixed user role value of student
@app.route('/create-account/public', methods=['GET'])
def create_student_user_account():
    if 'credentials' in session:
        return redirect(url_for('handle_login_redirect'), code=301)
    return render_template('account_creation_page.j2', is_admin=False, form_type='public')


# Admin-only restricted GET endpoint for rendering create user account form with selectable user roles
@app.route('/create-account/restricted', methods=['GET'])
@verify_admin_user
def create_restricted_account():
    return render_template('account_creation_page.j2', is_admin=True, form_type='restricted')


# Admin-only restricted POST endpoint for user account creations of roles with elevated permissions
@app.route('/create-account/restricted/submit', methods=['POST'])
@verify_admin_user
def register_restricted_user():
    if not request.form.get("create-account"):
        flash(f"ERROR: {BAD_REQUEST}. One or more required login information fields are missing.", category='bad-request-user-error')
        return redirect(url_for('login'), code=301)
    # Receive User POSTed request form data for registering new account with Auth0 application
    email = request.form['email-input']
    password = request.form['password-input']
    role = request.form['role-input']
    role_id = ""
    match role:
        case 'instructor':
            role_id = INSTRUCTOR_ROLE_ID
        case 'admin':
            role_id = ADMIN_ROLE_ID
        case _:
            role_id = STUDENT_ROLE_ID
    username = username = str(email)[:str(email).strip().find('@')]
    try:
        # Use generated Auth0 Management API access token to register new user with main Auth0 application using submitted credentials 
        api_access_token = get_api_access_token()
        register_new_auth0_user(api_access_token, email, password)
         # Submit request to assign specified role to new Auth0 user using Auth0-issued user ID and corresponding role ID
        new_user_id = retrieve_user_id(email, password)
        assign_auth0_role(api_access_token, new_user_id, role, role_id)
        # Retrieve assigned role of newly registered Auth0 user and verify it matches the expected role
        assigned_role = get_auth0_role(api_access_token, new_user_id)
        if (role != assigned_role):
            raise AuthError(error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
                            debugMsg=f"Non-matching roles for new user found!\nAuth0-issued role: {assigned_role}\nRequested role: {role}")
        # Add the new user with mixture of auth0 issued credentials and submitted credentials to MySQL database
        db_op.register_user(new_user_id, username, email, role)
        flash(
            f"New Account sucessfully created! Please login with your submitted username and password.",
            category='new-account-creation-success-msg'
        )
        return redirect(url_for('handle_login_redirect'), code=301)
    
    except AuthError as e:
        # Catch thrown Auth exceptions with proper error messages to display at top of login page
        if APP_ENV == 'dev':
            print(e.debugMsg)
        match e.status_code:
            case 400:
                flash(f"{e.error}", category='bad-request-user-error')
            case 401:
                flash(f"{e.error}", category='unauthorized-user-error')   
            case 403:
                flash(f"{e.error}", category='forbidden-user-error')
            case 404:
                flash(f"{e.error}", category="not-found-user-error")
            case _:
                flash(f"{e.error}", category="unexpected-error")
        return redirect(url_for('login', logged_in=True), code=301)


# Unrestricted POST endpoint for creating a new user account
@app.route('/create-account/public/submit', methods=['POST'])
def register_basic_user():
    # Since no route guards are placed on this endpoint, prevent a logged in user from creating a new account while logged in
    if 'credentials' in session:
        redirect(url_for('handle_login_redirect'), code=301)

    if not request.form.get("create-account"):
        flash(f"ERROR: {BAD_REQUEST}. One or more required login information fields are missing.", category='bad-request-user-error')
        return redirect(url_for('login'), code=301)

    # Receive User POSTed request form data for registering new account with Auth0 application
    email = request.form['email-input'] 
    password = request.form['password-input']
    # Directly set user role value to student for unrestricted endpoint to mitigate direct submissions with manipulated user role
    role = 'student'
    role_id = STUDENT_ROLE_ID
    
    username = str(email)[:str(email).strip().find('@')]
    try:
        # Use generated Auth0 Management API access token to register new user with main Auth0 application using submitted credentials 
        api_access_token = get_api_access_token()
        register_new_auth0_user(api_access_token, email, password)
         # Submit request to assign specified role to new Auth0 user using Auth0-issued user ID and corresponding role ID
        new_user_id = retrieve_user_id(email, password)
        assign_auth0_role(api_access_token, new_user_id, role_id)
        # Retrieve assigned role of newly registered Auth0 user and verify it matches the expected role
        assigned_role = get_auth0_role(api_access_token, new_user_id)
        if (role != assigned_role):
            raise AuthError(error=f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", status_code=401,
                            debugMsg=f"Non-matching roles for new user found!\nAuth0-issued role: {assigned_role}\nRequested role: {role}")
        # Add the new user with mixture of auth0 issued credentials and submitted credentials to MySQL database
        db_op.register_user(new_user_id, username, email, role)
        flash(
            f"New Account sucessfully created! Please login with your submitted username and password.",
            category='new-account-creation-success-msg'
        )
        return redirect(url_for('handle_login_redirect'), code=301)
    
    except AuthError as e:
        # Catch thrown Auth exceptions with proper error messages to display at top of login page
        if APP_ENV == 'dev':
            print(e.debugMsg)
        match e.status_code:
            case 400:
                flash(f"{e.error}", category='bad-request-user-error')
            case 401:
                flash(f"{e.error}", category='unauthorized-user-error')   
            case 403:
                flash(f"{e.error}", category='forbidden-user-error')
            case 404:
                flash(f"{e.error}", category="not-found-user-error")
            case _:
                flash(f"{e.error}", category="unexpected-error")
        return redirect(url_for('login', logged_in=True), code=301)


# # ================================= USER ACTIONS ENDPOINTS ================================

# GET endpoint restricted to authenticated admin users for retrieving list of
# all current registered usrs 
@app.route('/' + USERS, methods=['GET'])
@verify_admin_user
def get_users():
    # Retrieve dictionary of all users' basic information
    users = db_op.get_user_list()
    # Render page with list of existing users and management features
    if APP_ENV == 'dev':
        print(f"Existing list of users: {users}")
    return render_template('user_management.j2', logged_in=True, user_id=session['user_id'], user_list=users)


# GET endpoint restricted to authenticated admin users for requesting a user account update
@app.route('/' + USERS + 'edit/<int:user_id>', methods=['GET'])
@verify_admin_user
def edit_user_account(user_id):
    match_user = db_op.get_user_by_id(user_id)
    if match_user is None:
        flash(f"ERROR: {NOT_FOUND}. User to be edited was not found", category="user-not-found-error")
        # If doesn't exist redirect to user login page
        return redirect(url_for('get_users', logged_in=True), code=301)
    
    if match_user['role'] is not None and match_user['role'] == 'admin':
        flash(f"ERROR: {FORBIDDEN}. Admin user accounts cannot be modified", category='forbidden-user-error')
        return redirect(url_for('get_users', logged_in=True), code=301)
    
    return render_template('edit_user.j2', logged_in=True, edit_user=match_user, user_id=session['user_id'])


# POST endpoint restricted to admin users for modifying the account of a specified user
@app.route('/' + USERS + '/edit/<int:user_id>', methods=['POST'])
@verify_admin_user
def update_user_account(user_id):
    match_user = db_op.get_user_by_id(user_id)
    if match_user is None:
        flash(f"ERROR: {NOT_FOUND}. User to be edited was not found", category="user-not-found-error")
        # If doesn't exist redirect to user login page
        return redirect(url_for('get_users', logged_in=True), code=301)
    if not request.form.get("edit-user"):
        flash(f"ERROR: {BAD_REQUEST}. One or more required user update form fields are missing.", category='bad-request-user-error')
        return redirect(url_for('get_users', logged_in=True), code=301)

    try:
        # Use generated Auth0 Management API access token to register new user with main Auth0 application using submitted credentials 
        api_access_token = get_api_access_token()
        # Receive User POSTed request form data for updating user account with Auth0 application
        request_props = {}
        if request.form['user-password-input'] is not None and len(str(request.form['user-password-input'])) > 0:
            request_props['password'] = request.form['user-password-input']
        else:
            request_props['email'] = request.form['user-email-input']
        
        # Check if JSON body of request is empty
        if len(request_props) == 0:
            # If empty, return original course in response body
            updated_user = match_user
        else:
            if APP_ENV == 'dev':
                print("Attempting to update user with Auth0...")
            update_auth0_user(api_access_token, match_user, request_props)
            if APP_ENV == 'dev':
                print("Attempting to update user with MySQL database...")
            # Verify request is valid, update user, and return result
            updated_user = db_op.update_user(request_props, user_id)
            if APP_ENV == 'dev':
                print(updated_user)
    
    except AuthError as e:
        # Catch thrown Auth exceptions with proper error messages to display at top of login page
        if APP_ENV == 'dev':
            print(e.debugMsg)
        match e.status_code:
            case 400:
                flash(f"{e.error}", category='bad-request-user-error')
            case 401:
                flash(f"{e.error}", category='unauthorized-user-error')   
            case 403:
                flash(f"{e.error}", category='forbidden-user-error')
            case 404:
                flash(f"{e.error}", category="not-found-user-error")
            case _:
                flash(f"{e.error}", category="unexpected-error")
        return redirect(url_for('get_users', logged_in=True), code=301)

    flash("User successfully updated!", category='updated-user-success')
    return redirect(url_for('get_users', logged_in=True), code=301)


# GET endpoint restricted to admin users for deleting the account of a specified user
@app.route('/' + USERS + '/delete/<int:user_id>', methods=['GET'])
@verify_admin_user
def remove_user_account(user_id):
    match_user = db_op.get_user_by_id(user_id)
    if match_user is None:
        flash(f"ERROR: {NOT_FOUND}. User to be edited was not found", category="user-not-found-error")
        # If doesn't exist redirect to user login page
        return redirect(url_for('get_users', logged_in=True), code=301)
    
    if match_user['role'] is not None and match_user['role'] == 'admin':
        flash(f"ERROR: {FORBIDDEN}. Admin user accounts cannot be deleted", category='forbidden-user-error')
        return redirect(url_for('get_users', logged_in=True), code=301)
    return render_template('delete_user.j2', logged_in=True, delete_user=match_user, user_id=session['user_id'])


# POST endpoint restrcted to admin users for deleting the account of a specified user
@app.route('/' + USERS + '/delete/<int:user_id>', methods=['POST'])
@verify_admin_user
def delete_user_account(user_id):
    match_user = db_op.get_user_by_id(user_id)
    if match_user is None:
        flash(f"ERROR: {NOT_FOUND}. User to be edited was not found", category="user-not-found-error")
        # If doesn't exist redirect to user login page
        return redirect(url_for('get_users', logged_in=True), code=301)
    
    if match_user['role'] is not None and match_user['role'] == 'admin':
        flash(f"ERROR: {FORBIDDEN}. Admin user accounts cannot be deleted", category='forbidden-user-error')
        return redirect(url_for('get_users', logged_in=True), code=301)
    try:
        # Use generated Auth0 Management API access token to register new user with main Auth0 application using submitted credentials 
        api_access_token = get_api_access_token()
        delete_auth0_user(api_access_token, match_user)
        db_op.delete_user(user_id)
    
    except AuthError as e:
        # Catch thrown Auth exceptions with proper error messages to display at top of login page
        if APP_ENV == 'dev':
            print(e.debugMsg)
        match e.status_code:
            case 400:
                flash(f"{e.error}", category='bad-request-user-error')
            case 401:
                flash(f"{e.error}", category='unauthorized-user-error')   
            case 403:
                flash(f"{e.error}", category='forbidden-user-error')
            case 404:
                flash(f"{e.error}", category="not-found-user-error")
            case _:
                flash(f"{e.error}", category="unexpected-error")
        return redirect(url_for('get_users', logged_in=True), code=301)

    flash("User successfully deleted!", category='updated-user-success')
    return redirect(url_for('get_users', logged_in=True), code=301)


# GET endpoint for initial login page/form for accepting user login credentials
@app.route('/login', methods=['GET'])
def login():
    return render_template('login.j2', logged_in=False)


# GET endpoint for logging out/clearing current session for a user
@app.route('/logout', methods=['GET'])
def logout_user():
    # Check for login credentials within session and remove them if found
    has_creds = 'credentials' in session
    if has_creds:
        session.clear()
    # Redirect to login page
    flash("You have been sucessfully logged out!", category='user-log-out-success')
    return redirect(url_for('login'), code=301)


# GET endpoint used to handle request redirection from user login page (to profile page or login page)
@app.route('/' + USERS + '/login', methods=['GET'])
def handle_login_redirect():
    # Verify whether user is logged in
    has_creds = 'credentials' in session and len(str(session['credentials']).strip()) > 0
    if has_creds:
        ses_request = build_auth_headers(session['credentials'])
        try:
            payload = verify_jwt(ses_request)
        except AuthError:
            # Retain AuthError output for debugging, return generic msg
            flash(f"ERROR: {UNAUTHORIZED}. Invalid user credentials recieved. Please retry logging in.", category='unauthorized-user-error')
            session.clear()
            return redirect(url_for('login'), code=301)
        
        # Retrieve user with matching authenticated subject from database
        match_user = db_op.check_for_user(str(payload['sub']))
        if match_user is None:
            flash(f"ERROR: {NOT_FOUND}. User with username/email no longer exists. Please login with a different username/email", category="user-not-found-error")
            # If doesn't exist redirect to user login page
            session.clear()
            return redirect(url_for('login'), code=301)
        
        # Generate authorization headers using payload extracted from token
        user_id = match_user['id']
        
        # Use extracted id to redirect page for loading user profile page
        return redirect(url_for('get_matching_user', user_id=user_id), code=301)
        # return redirect(PROXY_ADDR + "/users/" + str(user_id))
    else:
        # If no credentials exist in get request, redirect to login page
        return redirect(url_for('login'), code=301)


# POST endpoint for authenticating login requests using submitted user credentials 
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    # Retrieve submitted 'username' and 'password' values from request
    if request.form.get("Login"):
        username = request.form['username-input']
        password = request.form['password-input']
    # # Verify user provided both username and password values
    else:
        flash(f"ERROR: {BAD_REQUEST}. One or more required information fields are missing.", category='bad-request-user-error')
        return redirect(url_for('login'), code=301)
    # If missing either value, return BAD REQUEST
    # Build request body to Auth0 using retrieved user information
    body = {'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    # Clarify JSON content and set url to request url for Auth0
    headers = {'content-type': 'application/json'}
    url = DOMAIN + '/oauth/token'
    # Retrieve response from Auth0 and return body content as JSON
    r = requests.post(url, json=body, headers=headers).json()
    # Capture token ID and return as token value for valid users
    if 'id_token' in r:
        token = {}
        token['token'] = r['id_token']
        session['credentials'] = token['token']
        # # Send request with authorization headers to Google People API
        # headers = {'Authorization': 'Bearer {}'.format(session['credentials'])}
        find_user = db_op.get_user_by_email(username)
        if find_user is None:
            flash(f"ERROR: {NOT_FOUND}. User with username/email no longer exists. Please login with a different username/email", category="user-not-found-error")
            # If doesn't exist redirect to user login page
            return redirect(url_for('login'), code=301)
        user_id = find_user['id']

        # Use extracted id to redirect page for loading user profile page
        return redirect(url_for('get_matching_user', user_id=user_id), 301)
    else:
        # If user email/password is invalid, return FORBIDDEN
        flash(f"ERROR: {FORBIDDEN}. Invalid password or username. Please retry with different credentials.", category='forbidden-user-error')
        return redirect(url_for('login'), code=301)


# GET endpoint for retrieving an authenticated user's account information and avatar assets
@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
@authenticate_user
def get_matching_user(user_id):
    if 'credentials' not in session or 'user_id' not in session or 'user_subject' not in session:
        flash(
            f"ERROR: {UNAUTHORIZED}. Current user credentials could not be successfully verified. Please retry logging in.",
            category='unauthorized-user-error'
        )
        session.clear()
        return redirect(url_for('login'), code=301)
    # Verify user with matching 'user_id' currently exists in the database
    match_user = db_op.get_authuser_by_id(user_id, session['user_subject'], True)
    if match_user is None:
            flash(f"ERROR: {FORBIDDEN}. User could not be authenticated or does not have permission to access this resource."
                   "Please relogin with an account that is authorized access this resource",
                   category='forbidden-user-error')
            session.clear()
            return redirect(url_for('login'), code=301)
    match_user['user_id'] = user_id
    # Do not include 'avatar_url' if user does not currently have an avatar
    have_avatar = ('has_avatar' in match_user and
                   match_user['has_avatar'])
    if have_avatar:
        match_user['avatar_url'] = ("/" + USERS + '/' + str(user_id) + '/avatar')
    
    # Remove 'courses' if user does not contain courses (admin users)
    has_courses = 'role' in match_user and match_user['role'] != "admin"
    # If user has 'courses' convert array of course ids to course links
    courses = db_op.get_user_courses(user_id)
    if has_courses:
        match_user['courses'] = db_op.get_course_links(courses,
                                                       f"{PROXY_ADDR}/")
    # Omit non-essential properties of User in response
    del match_user['has_avatar']
    instructors = db_op.get_users_by_role('instructor')
    # Render template for displaying user's profile information
    return render_template('user_info.j2', data=match_user,
                            instructors=instructors, logged_in=True)


# GET endpoint for retrieving a user's avatar image from Google Storage's specified bucket
@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['GET'])
def get_user_avatar(user_id):
    # Verify user with matching 'user_id' currently exists in datastore
    avatar_user = db_op.get_authuser_by_id(user_id, session['user_subject'], False)
    if avatar_user is None:
        flash(f"ERROR: {FORBIDDEN}. User could not be authenticated or does not have permission to access this resource."
            "Please relogin with an account that is authorized access this resource", category='forbidden-user-error')
        session.clear()
        return redirect(url_for('login'), code=301)
    # Retrieve storage bucket for user avatars from GCP
    avatar_bucket = storage_client.get_bucket(AVATAR_BUCKET)
    # Set local variable to designated file name format per user
    avatar_filename = f'avatar_{user_id}.png'
    # Create new Blob object with designated name for avatar file in bucket
    avatar_blob = avatar_bucket.blob(blob_name=avatar_filename)
    # Set boolean value to reflect whether user has a current avatar
    avatar_exists = ('has_avatar' in avatar_user and
                     avatar_user['has_avatar'])
    # If request is for retrieving user's current avatar(GET)
    if avatar_exists:
        # Allocate local memory to store file data in a local file object
        file_obj = io.BytesIO()
        # Download the file from Cloud Storage to the file_obj variable
        avatar_blob.download_to_file(file_obj)
        # Position filestream to read from beginning of downloaded file data
        file_obj.seek(0)
        # Send the object as a file in the response with the correct MIME type
        return send_file(file_obj, mimetype='image/x-png',
                         download_name=avatar_filename)
    else:
        # If user does not have an avatar, return NOT FOUND
        flash(f"ERROR: {NOT_FOUND}. You do not currently have an avatar.", category="avatar-not-found-error")
        # If doesn't exist redirect to user login page
        return redirect(url_for('get_matching_user', user_id=user_id), code=301)
    

# POST/DELETE endpoint for Route updating or deleting a user's avatar
@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['POST', 'DELETE'])
@authenticate_user
def update_user_avatar(user_id):
    # Requests that omit file form data in POST routes are immediately rejected
    if request.method == "POST" and 'file' not in request.files:
            flash(f"ERROR: {BAD_REQUEST}. Upload of new avatar file failed. Please try again.", category='bad-request-user-avatar-error')
            return redirect(url_for('get_matching_user', user_id=user_id), code=301)

    # Verify user with matching 'user_id' currently exists in datastore
    avatar_user = db_op.get_authuser_by_id(user_id, session['user_subject'], False)
    if avatar_user is None:
        flash(f"ERROR: {FORBIDDEN}. User could not be authenticated or does not have permission to access this resource."
            "Please relogin with an account that is authorized access this resource", category='forbidden-user-error')
        session.clear()
        return redirect(url_for('login'), code=301)

    # Retrieve storage bucket for user avatars from GCP
    avatar_bucket = storage_client.get_bucket(AVATAR_BUCKET)
    # Set local variable to designated file name format per user
    avatar_filename = f'avatar_{user_id}.png'
    # Create new Blob object with designated name for avatar file in bucket
    avatar_blob = avatar_bucket.blob(blob_name=avatar_filename)
    # Set boolean value to reflect whether user has a current avatar
    avatar_exists = ('has_avatar' in avatar_user and
                     avatar_user['has_avatar'])

    # If request is for adding/replacing user's avatar
    if request.method == "POST":
        # Store file data from request's multipart/form-data in file object
        avatar_file = request.files['file']
        if avatar_exists:
            # If user already has an avatar, delete it before replacing it
            delete_avatar(avatar_filename)
        else:
            # Else, update users entity to indicate it now has an avatar
            db_op.update_user_avatar(user_id, True)
        # Set filestream position to read from beginning of avatar file data
        avatar_file.seek(0)
        # Upload file to GCP to be stored within bucket holding avatar images
        avatar_blob.upload_from_file(avatar_file)
        # Return built url in response body for avatar of user
        user_avatar_url = {}
        # user_avatar_url['avatar_url'] = f"{PROXY_ADDR}/{request.path}"
        user_avatar_url['avatar_url'] = f"{request.base_url}"
        flash("Avatar successfully updated!", category='update-avatar-success')
        # Redirect user to url to reload page to display updated avatar
        return redirect(url_for('get_matching_user', user_id=user_id), code=301)

    # If request is for deleting avatar of user
    if request.method == "DELETE":
        if avatar_exists:
            # If user has an avatar, delete it and clear 'has_avatar'
            delete_avatar(avatar_filename)
            db_op.update_user_avatar(user_id, False)
            return "", 204
        else:
            # If user does not have an avatar to delete, return NOT FOUND
            flash(f"ERROR: {NOT_FOUND}. You do not currently have an avatar to delete.", category="avatar-not-found-error")
            # If doesn't exist redirect to user login page
            return redirect(url_for('get_matching_user', user_id=user_id), code=301)


# ============================ COURSE ROUTES =============================

# Prepopulate Course entities in MySQL database using all courses in 'course_sheet.json'
# Used to quickly register all Course entities
@app.route('/' + COURSES + '/prepopulate')
@verify_admin_user
def prepopulate_courses():
    with open(COURSES_FILE, 'r') as courses_file:
        preset_course_info = dict(json.load(courses_file))
    
    if len(preset_course_info) == 0:
        return {"Error": f"File {COURSES_FILE} does not contain any courses"}, 400

    course_entity_list = []    # Array of Course Entities to Update/Add to MySQL database
    course_entity_dict = {}    # JSON-Compatible Container of Course Entities to return
    for name, course in preset_course_info.items():
        req_attrs = ['subject', 'number', 'title',
                        'term', 'instructor_id']

        # Verify 'instructor_id' refers to an existing instructor
        valid_instructor = db_op.check_instructor(
            course['instructor_id'])
        keys_missing = db_op.verify_request_body(req_attrs, course)
        # If POST is missing required keys or valid instructor, return 400
        if keys_missing or valid_instructor is None:
            error_output = (
                f"Course {course['title']} has one or more invalid/missing attributes" if keys_missing
                else f"Instructor with ID {course['instructor_id']} is not a valid instructor"
            )

            if APP_ENV == 'dev':
                print(error_output)
            continue
        try:
            added_course_entry = db_op.add_course(
                course['subject'],
                course['number'],
                course['title'],
                course['term'],
                course['instructor_id']
            )
            # Generate link to course and include it in response
            course_url = f"{PROXY_ADDR}{request.full_path}".split('/prepopulate')[0]
            added_course_entry['self'] = f"{course_url}/{added_course_entry['id']}"

            # Create 'enrollment' entity to tie instructor to course
            db_op.update_enrollment(valid_instructor['id'],
                                    added_course_entry['id'], False)
        except Exception as e:
            if APP_ENV == 'dev':
            # Catch exceptions raised from invalid request data
                logger.exception(e)
            continue
        if APP_ENV == 'dev':
            print(f"Course {name} successfully prepopulated!")
        course_entity_list.append(added_course_entry)
        course_entity_dict['name'] = course_entity_list

    # IF WISHING TO DISPLAY PREPOPULATED COURSE RAW JSON INFORMATION INSTEAD:
    # return course_entity_dict, 201

    match_user = db_op.check_for_user(session['user_subject'])
    if match_user is None:
        flash(f"ERROR: {FORBIDDEN}. User could not be authenticated or does not have permission to access this resource."
            "Please relogin with an account that is authorized access this resource", category='forbidden-user-error')
        session.clear()
        return redirect(url_for('login'), code=301)
    # Generate authorization headers using payload extracted from token
    user_id = match_user['id']
    headers = {'Authorization': 'Bearer {}'.format(
        session['credentials'])}
    # Use extracted id to redirect page for loading user profile page
    return redirect(url_for('get_matching_user', user_id=user_id), code=301)


# GET endpoint for retrieving courses for all users or add a course (admin only)
@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    # Check request URL for query string arguments
    query_str = request.args
    query_params = query_str.to_dict()
    has_query = len(query_params) > 0 and 'action' not in query_str
    is_action = ('action' in query_str
                    and 'title' in query_str)
    if is_action:
        match query_str['action']:
            case 'delete':
                flash(
                    f"Course {query_str['title']} deleted successfully!",
                    category="delete-course-success"
                )
            case 'add':
                flash(
                    f"Course {query_str['title']} added successfully!",
                    category="add-course-success"
                )
            case _:
                flash(
                    f"ERROR: {BAD_REQUEST}. Course search request is missing one or more required information fields.",
                    category='bad-request-add-course-error'
                )
    # Select appropriate query and update limit/offset if necessary
    offset = int(query_params['offset']) if has_query else int(0)
    limit = int(query_params['limit']) if has_query else int(3)
    # Collect each entry's information and store it
    paged_dict = {}
    # Retrieve list of all requested courses to be displayed on page
    paged_dict[COURSES] = (
        db_op.get_course_page(offset, limit, f"{PROXY_ADDR}{request.path}") if not has_query
        and not is_action
        else db_op.get_course_page(offset, limit, f"{PROXY_ADDR}{request.path}"))
    # Retrieve all page links using set limit value
    course_results = db_op.get_all_courses()
    active = offset // limit + 1
    paged_dict['page_links'] = db_op.get_page_links(
        f"{PROXY_ADDR}{request.path}", course_results, limit, offset
    )
    if APP_ENV == 'dev':
        print(f"Course Entries for request page:\n{paged_dict}")
    # Submit user-specific data for authenticated users to enable restricted features  
    is_verified, user_info = verify_user_credentials()
    if not is_verified:
            return render_template('all_courses_page.j2', data=paged_dict,
                active=active, user={}, logged_in=False)

    return render_template('all_courses_page.j2', data=paged_dict,
                        active=active, user=user_info, logged_in=True)


# POST endpoint for handling addition of a new course (admin-only restricted endpoint)
@app.route('/' + COURSES, methods=['POST'])
@verify_admin_user
def add_course():
    # Verify POSTed data is present in request
    if request.form.get("add-course") is None:
        flash(
            f"ERROR: {BAD_REQUEST}. Request to add a new course is missing one or more required information fields.",
            category='bad-request-add-course-error'
        )
        return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
    # Verify POSTed data contains all required course information field
    course_info = {}
    course_info['subject'] = request.form['course-subject-input']
    course_info['number'] = request.form['course-number-input']
    course_info['title'] = request.form['course-title-input']
    course_info['instructor_id'] = request.form['selected-course-instructor']
    course_info['term'] = request.form['course-term-input']
    req_attrs = [
        'subject', 'number', 'title',
        'term', 'instructor_id'
    ]
    # Verify POSTed 'instructor_id' refers to a valid and existing instructor
    valid_instructor = db_op.check_instructor(course_info['instructor_id'])
    keys_missing = db_op.verify_request_body(req_attrs, course_info)

    # If POST is missing required keys or valid instructor, return 400
    if keys_missing or valid_instructor is None:
        flash(
            f"ERROR: {BAD_REQUEST}. Request to add a new course contains either incomplete or invalid data.",
            category='bad-request-add-course-error'
        )
        return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
    try:
        # Create new course Entity and add it to Datastore
        added_course = db_op.add_course(
            course_info['subject'], course_info['number'],  course_info['title'],
            course_info['term'], course_info['instructor_id']
        )
        # Generate link to course and include it in response
        added_course['self'] = f"{PROXY_ADDR}{request.full_path}/{added_course['id']}"
        # Create 'enrollment' entity to tie instructor to course
        db_op.update_enrollment(valid_instructor['id'], added_course['id'], False)
    except Exception as e:
        # Catch exceptions raised from invalid request data
        if APP_ENV != 'deploy':
            logger.exception(e)
        flash(
            f"ERROR: {BAD_REQUEST}. Request to add a new course is missing one or more required information fields.",
            category='bad-request-add-course-error'
        )
        return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
    return redirect(
        f"/courses?action=add&title={course_info['title']}",
        code=301,
    )


# GET endpoint for retrieving matching course for all users or modifies/deletes for admin
@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
@check_user
def get_matching_course(course_id):

    course_exists = db_op.get_course_by_id(course_id)
    enrollment_link = f"{PROXY_ADDR}{request.full_path}" + '/students'

    # GET requests are unrestricted so first verify requested course exists
    has_query = len(request.args.to_dict()) > 0
    request_url = f"{PROXY_ADDR}{request.path}" if has_query else f"{PROXY_ADDR}{request.full_path}"
    if course_exists is None:
        flash(
            f"ERROR: {NOT_FOUND}. Requested course was not found.",
            category='not-found-course-error'
        )
        return redirect(url_for('get_courses', user_id=session['user_id']), code=301)
    
    # If course exists, include appropriate user data based on whether user is authenticated
    # and whether the user is the instructor of the requested course
    course_exists['self'] = request_url
    instructor = db_op.check_instructor(course_exists['instructor_id'])
    is_verified, user_info = verify_user_credentials()

    is_instructor = False
    instructors = db_op.get_users_by_role('instructor')
    if not is_verified:
        return render_template('course_info.j2', data=course_exists,
                        instructor=instructor,
                        enrollment=enrollment_link,
                        user={}, is_instructor=is_instructor,
                        instructors=instructors, logged_in=False)
    
    
    is_instructor = True if instructor['id'] == user_info['id'] else False
    return render_template('course_info.j2', data=course_exists,
                           instructor=instructor, enrollment=enrollment_link,
                           user=user_info, is_instructor=is_instructor,
                           instructors=instructors, logged_in=True)


# POST endpoint for updating a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['POST'])
@verify_admin_user
def update_course(course_id):
    course_exists = db_op.get_course_by_id(course_id)
    if course_exists is None:
        flash(
            f"ERROR: {NOT_FOUND}. Course to be updated was not found.",
            category='not-found-course-error'
        )
        return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
    
    enrollment_link = f"{PROXY_ADDR}{request.full_path}" + '/students'

    instructors = db_op.get_users_by_role('instructor')
    # If request is verified, handle based on request type
    # Verify PATCH request and selectively update course if verified
    request_props = {}
    if request.form.get("edit-course"):
        request_props['title'] = request.form['course-title-input']
        request_props['subject'] = request.form['course-subject-input']
        request_props['term'] = request.form['course-term-input']
        request_props['number'] = request.form['course-number-input']
        request_props['instructor_id'] = request.form['selected-course-instructor']

    # Check if JSON body of request is empty
    if len(request_props) == 0:
        # If empty, return original course in response body
        updated_course = course_exists
    else:
        try:
            # Verify request is valid, update course, and return result
            updated_course = db_op.update_course(request_props, course_id)
        except Exception as e:
            # Catch exceptions raised from invalid request data
            if APP_ENV != 'deploy':
                logger.exception(e)
            flash(
                f"ERROR: {BAD_REQUEST}. Request to update course is missing one or more required information fields.",
                category='bad-request-update-course-error'
            )
            return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
        if updated_course is None:
            # Return BAD_REQUEST if invalid instructor is used in request
            flash(
                f"ERROR: {BAD_REQUEST}. Request to update course is missing one or more required information fields.",
                category='bad-request-update-course-error'
            )
            return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
        
        # Add course link to response
        is_instructor = False
        match_user = db_op.check_for_user(session['user_subject'])
        instructor = db_op.check_instructor(updated_course['instructor_id'])
        updated_course['self'] = f"{PROXY_ADDR}{request.full_path}"
        if instructor['id'] == match_user['id']:
            is_instructor = True
        
        flash("Course successfully updated!", category='updated-course-success')
        return render_template(
            'course_info.j2', data=updated_course,
            instructor=instructor, enrollment=enrollment_link,
            user=match_user, is_instructor=is_instructor,
            instructors=instructors, logged_in=True
        )
        

# Admin restricted POST endpoint for deleting a specified course
@app.route('/' + COURSES + '/<int:course_id>/delete', methods=['POST'])
@verify_admin_user
def delete_matching_course(course_id):
    # Verify course to be deleted exists
    course_exists = db_op.get_course_by_id(course_id)
    if course_exists is None:
        flash(
            f"ERROR: {NOT_FOUND}. Course to be updated was not found.",
            category='not-found-course-error'
        )
        return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
    # Delete course from database if it exists (cascade deletes student enrollment)
    db_op.delete_course(course_id)
    return redirect(
        f"/courses?action=delete&title={course_exists['title']}",
        code=301
    )


# Route to retrieve matching courses from course search page for all users or modifies/deletes for admin
@app.route('/' + COURSES + '/search', methods=['GET', 'POST'])
def get_course_search():
    if request.method == "POST":
        search_type = ""
        # Collect search type and selected value to pass in redirected query
        if request.form.get("Search By Term"):
            search_val = request.form["selected-search-term"]
            search_type = 'term'
        elif request.form.get("Search By Subject"):
            search_val = request.form['selected-search-subject']
            search_type = 'subject'
        elif request.form.get("Search By Instructor"):
            search_val = request.form['selected-search-instructor']
            search_type = 'instructor_id'
        else:
            flash(
                f"ERROR: {NOT_FOUND}. Course Search Action was not found.",
                category='not-found-course-error'
            )
            return redirect(url_for('get_course_search'), code=301)
        # Redirect to endpoint used for pagination of search results
        return redirect(url_for('get_search_results', search_type=str(search_type), value=str(search_val)))
        # return redirect('/search-courses/' + str(search_type) + '?value='
        #                 + str(search_val))
    # GET requests retrieve all search category values for search request
    data = {}
    instructors = db_op.get_users_by_role('instructor')
    subjects = db_op.get_course_subjects()
    terms = db_op.get_course_terms()
    data['instructors'] = instructors
    data['subjects'] = subjects
    data['terms'] = terms
    return render_template('course_search_page.j2', data=data)


# GET endpoint for displaying returned course search results
@app.route('/search-courses/<search_type>')
def get_search_results(search_type):
    query_str = request.args
    query_params = query_str.to_dict()
    has_query = len(query_params) > 1
    if 'value' not in query_params:
            flash(
                f"ERROR: {BAD_REQUEST}. Course search request is missing one or more required information fields.",
                category='bad-request-update-course-error'
            )
            return redirect(url_for('get_matching_user', user_id=session['user_id']), code=301)
    # Select appropriate query and update limit/offset if necessary
    offset = int(query_params['offset']) if has_query else int(0)
    limit = int(query_params['limit']) if has_query else int(3)
    # Ensure integer coversion if search value is for instructor
    value = (
        int(query_params['value']) if search_type == 'instructor_id'
        else str(query_params['value'])
        )
    # Store categories to be used in generating SQL squeries to retrieve
    # requested sets of search results
    categories = {search_type: value}
    paged_dict = {}
    # Build base url for use in course's self-referencing link
    course_url = f"{PROXY_ADDR}/courses"
    # Retrieve requested set of courses for next page to be rendered
    paged_dict[COURSES] = (
        db_op.get_courses_by_prop(categories, limit=limit,
                                  offset=offset, request_url=course_url))
    # Retrieve list of all courses corresponding to search request
    all_results = db_op.get_courses_by_prop(categories)
    if APP_ENV == 'dev':
        print(f"Course page dictionary :{paged_dict[COURSES]}")
        print(f"All results: {all_results}")
    # Build dictionary with key:pairs where each key is the URL query argument
    target_params = {'value': value}
    active = offset // limit + 1
    # Generate all numbered links and 'next', 'previous' if appropriate
    paged_dict['page_links'] = db_op.get_page_links(
        request.base_url, all_results, limit, offset,
        param_vals=target_params
    )
    if APP_ENV == 'dev':
        print(f"Page links dictionary: {paged_dict['page_links']}")
    is_verified, user_info = verify_user_credentials()
    if not is_verified:
        return render_template('all_courses_page.j2', data=paged_dict,
            active=active, user={}, logged_in=False)
    return render_template('all_courses_page.j2', data=paged_dict,
                        active=active, user=user_info, logged_in=True)


# GET/POST endpoint for retrieving or updating list of course's currently enrolled students
@app.route('/' + COURSES + '/<int:course_id>/students', methods=['GET','POST'])
@authenticate_user
def get_course_enrollment(course_id):
    # If user is authenticated, verify course with matching requested id exists
    match_course = db_op.get_course_by_id(course_id)
    if match_course is None:
        # If course with matching course_id does not exist, return NOT_FOUND
        flash(
            f"ERROR: {NOT_FOUND}. Course to unenroll student from was not found.",
            category='not-found-course-error'
        )
        return redirect(url_for('get_courses', loggedIn=True), code=301)
    
    # If requested course exists, verify user has admin or instructor access
    # Check for admin role
    is_admin = db_op.verify_admin(session['user_subject'])
    # Retrieve requesting user's ID (verified JWT guarantees retrieval success)
    request_user_id = int(db_op.check_for_user(session['user_subject'])['id'])
    # Verify user has either admin access or is instructor of requested course
    if is_admin or request_user_id == int(match_course['instructor_id']):
        # Update course's enrollment if request body's array are validated
        if request.method == "POST" and request.form.get('enroll-student') and request.form['selected-student'] is not None:
            enrolled_student_id = request.form['selected-student']
            if APP_ENV == 'dev':
                print(f"Id of requested student to be enrolled:\n\t{enrolled_student_id}")
            enrolled_student_dict = {
                "add": [ int(enrolled_student_id) ],
                "remove": []
            }

            is_valid = db_op.enroll_students(enrolled_student_dict,
                                             course_id)
            if is_valid is None:
                # If request's 'add' or 'remove' array is invalid, return 409
                flash(
                    f"ERROR: {CONFLICT}. The requested student to be unenrolled from the course is not currently enrolled.",
                    category='student-enrollment-request-conflict-error'
                )
                return redirect(url_for('get_course_enrollment', course_id=match_course['id'], loggedIn=True), code=301)

        enrollment_dict = {}
        # enrollment_dict['enrollment'] is a list of user ids for all students currently enrolled in course
        enrollment_dict['enrollment'] = db_op.get_enrollment_list(course_id)
        if enrollment_dict['enrollment'] is None:
            # Report error if expected course does not exist
            flash(
                f"ERROR: {BAD_REQUEST}. Student unenrollment request contains one or more invalid fields.",
                category='bad-request-update-course-error'
            )
            return redirect(url_for('get_courses', loggedIn=True), code=301)
        # Gather requested course to accept enrollment request
        enrollment_dict['course'] = match_course
        enrolled_students = []
        for student_id in enrollment_dict['enrollment']:
            enrolled_student = db_op.get_user_by_id(student_id)
            if enrolled_student is not None:
                enrolled_students.append(enrolled_student)
        enrollment_dict['enrolled_students'] = enrolled_students
        # Gather list of ALL authenticated student users
        student_users = db_op.get_users_by_role('student')
        if student_users is None:
            student_users = []
        # Gather a list of user IDs for all student users not already enrolled in the course
        eligible_student_ids = set(set([x['id'] for x in student_users])).difference(set(enrollment_dict['enrollment']))
        # Extract
        eligible_students = []
        for id in eligible_student_ids:
            student = db_op.get_user_by_id(id)
            if student is not None:
                eligible_students.append(student)
        # enrollment_dict['students'] is a list of all existing student users
        enrollment_dict['students'] = eligible_students

        if APP_ENV == 'dev':
            print(f"Course to enroll students:\n\t{match_course}")
            print(f"Students not already enrolled in course:\n\t{eligible_students}")
            print(f"Available Students to Register:\n\t{enrollment_dict['students']}")
        if request.method == "POST" and request.form.get('enroll-student'):
            flash(f"Student successfully enrolled to course '{match_course['title']}'", category='updated-course-success')
        return render_template('course_enrollment.j2', user_id=session['user_id'],
                               data=enrollment_dict, is_admin=is_admin, logged_in=True)
        # Return requested course's list IDs for enrolled students for GET
    else:
        # If user not an admin or instructor of requested course, deny access
        flash(f"ERROR: {FORBIDDEN}. User could not be authenticated or does not have permission to access this resource."
            "Please relogin with an account that is authorized access this resource", category='forbidden-user-error')
        session.clear()
        return redirect(url_for('login', loggedIn=False), code=301)


# GET endpoint for unenrolling a currently enrolled student from a specified course
@app.route('/' + COURSES + '/<int:course_id>/students/<int:student_id>/unenroll')
@authenticate_user
def unenroll_student(course_id, student_id):
    # If user is authenticated, verify course with matching requested id exists
    match_course = db_op.get_course_by_id(course_id)
    if match_course is None:
        # If course with matching course_id does not exist, return NOT FOUND
        flash(
            f"ERROR: {NOT_FOUND}. Course to unenroll student from was not found.",
            category='not-found-course-error'
        )
        return redirect(url_for('get_courses', loggedIn=True), code=301)

    match_student = db_op.get_user_by_id(student_id)
    if match_student is None:
        # Report error if expected student user to be unenrolled from course does not exist
        flash(
            f"ERROR: {NOT_FOUND}. Student to unenroll from course was not found.",
            category='user-not-found-error'
        )
        return redirect(url_for('get_courses', loggedIn=True), code=301)
    
    # If requested course exists, verify user has admin or instructor access
    # Check for admin role
    is_admin = db_op.verify_admin(session['user_subject'])
    # Retrieve requesting user's ID (verified JWT guarantees retrieval success)
    request_user_id = int(db_op.check_for_user(session['user_subject'])['id'])
    # Verify user has either admin access or is instructor of requested course
    if is_admin or request_user_id == int(match_course['instructor_id']):
        enrolled_student_dict = {
            "add": [  ],
            "remove": [int(student_id)]
        }
        is_valid = db_op.enroll_students(enrolled_student_dict,
                                             course_id)
        if is_valid is None:
            # If request's 'add' or 'remove' array is invalid, return 409
            flash(
                f"ERROR: {CONFLICT}. The requested student to be unenrolled from the course is not currently enrolled.",
                category='student-enrollment-request-conflict-error'
            )
            return redirect(url_for('get_course_enrollment', course_id=match_course['id'], loggedIn=True), code=301)
        
        enrollment_dict = {}
        # enrollment_dict['enrollment'] is a list of user ids for all students currently enrolled in course
        enrollment_dict['enrollment'] = db_op.get_enrollment_list(course_id)
        if enrollment_dict['enrollment'] is None:
            # Report error if expected course does not exist
            flash(
                f"ERROR: {BAD_REQUEST}. Student unenrollment request contains one or more invalid fields.",
                category='bad-request-update-course-error'
            )
            return redirect(url_for('get_courses', loggedIn=True), code=301)
        
        enrollment_dict['course'] = match_course
        enrolled_students = []
        for student_id in enrollment_dict['enrollment']:
            enrolled_student = db_op.get_user_by_id(student_id)
            if enrolled_student is not None:
                enrolled_students.append(enrolled_student)
        enrollment_dict['enrolled_students'] = enrolled_students

        # Gather list of ALL authenticated student users
        student_users = db_op.get_users_by_role('student')
        if student_users is None:
            student_users = []
        # Gather a list of user IDs for all student users not already enrolled in the course
        eligible_student_ids = set(set([x['id'] for x in student_users])).difference(set(enrollment_dict['enrollment']))

        eligible_students = []
        for id in eligible_student_ids:
            student = db_op.get_user_by_id(id)
            if student is not None:
                eligible_students.append(student)
        # enrollment_dict['students'] is a list of all existing student users
        enrollment_dict['students'] = eligible_students
        flash(f"Student successfully unenrolled from course '{match_course['title']}'", category='updated-course-success')
        return redirect(url_for('get_course_enrollment', course_id=match_course['id'], user_id=session['user_id'], logged_in=True), code=301)
        # Return requested course's list IDs for enrolled students for GET
    else:
        # If user not an admin or instructor of requested course, deny access
        flash(f"ERROR: {FORBIDDEN}. User could not be authenticated or does not have permission to access this resource."
                "Please relogin with an account that is authorized access this resource", category='forbidden-user-error')
        session.clear()
        return redirect(url_for('login', loggedIn=False), code=301)


if __name__ == '__main__':
    if APP_ENV == 'dev':
        print(f"MAIN: Listening on {HOST_URL}:{HOST_PORT}...")
    app.run(host=HOST_URL, port=HOST_PORT,debug=True if APP_ENV == 'dev' else False)
