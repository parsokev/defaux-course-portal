from .db_connector import connect_with_connector

import sqlalchemy
import os

APP_ENV = os.environ["APP_ENV"]

if APP_ENV != 'deploy' and APP_ENV != 'test':
    from . import vc_utils as vc_op
    vc_data = vc_op.get_secrets()
    INSTANCE_CONNECTION_NAME = vc_data["INSTANCE_CONNECTION_NAME"]
else:
    INSTANCE_CONNECTION_NAME = os.environ["INSTANCE_CONNECTION_NAME"]

# ======================= DB CONNECTION AND TABLE CREATION ====================

# Sets up connection pool for the app
def init_connection_pool() -> sqlalchemy.engine.base.Engine:
    
    if INSTANCE_CONNECTION_NAME:
    # if os.environ.get('INSTANCE_CONNECTION_NAME'):
        return connect_with_connector()

    raise ValueError(
        'Missing database connection type. Please define'
        'INSTANCE_CONNECTION_NAME'
    )
# This global variable is declared with a value of `None`
db = None

# Initiates connection to database and creates SQL tables
def init_db():
    global db
    db = init_connection_pool()
    create_user(db)
    create_course(db)
    create_enrollment(db)

# Create 'users' table in MySQL database if it does not already exist
def create_user(db: sqlalchemy.engine.base.Engine) -> None:
    with db.connect() as conn:
        conn.execute(
            sqlalchemy.text(
                "CREATE TABLE IF NOT EXISTS users "
                "(id INT NOT NULL AUTO_INCREMENT, "
                "email VARCHAR(50) NOT NULL, "
                "name VARCHAR(50) NOT NULL, "
                "role ENUM('admin', 'instructor', 'student') NOT NULL, "
                "sub VARCHAR(100) NOT NULL, "
                "has_avatar BOOL NOT NULL, "
                "UNIQUE (email), "
                "UNIQUE (sub), "
                "PRIMARY KEY (id) );"
            )
        )
        conn.commit()

# Create 'courses' table in MySQL database if it does not already exist
def create_course(db: sqlalchemy.engine.base.Engine) -> None:
    with db.connect() as conn:
        conn.execute(
            sqlalchemy.text(
                'CREATE TABLE IF NOT EXISTS courses '
                '(id INT NOT NULL AUTO_INCREMENT, '
                'subject VARCHAR(5) NOT NULL, '
                'number INT(3) NOT NULL, '
                'title VARCHAR(100) NOT NULL, '
                'term VARCHAR(20) NOT NULL, '
                'instructor_id INT, '
                'CONSTRAINT FOREIGN KEY (instructor_id) REFERENCES users '
                '(id), '
                'UNIQUE KEY (id, instructor_id) );'
            )
        )
        conn.commit()


# Create 'enrollment' intersection table in MySQL database if doesn't exist
def create_enrollment(db: sqlalchemy.engine.base.Engine) -> None:
    with db.connect() as conn:
        conn.execute(
            sqlalchemy.text(
                'CREATE TABLE IF NOT EXISTS enrollment '
                '(id INT NOT NULL AUTO_INCREMENT, '
                'course_id INT, '
                'user_id INT, '
                'CONSTRAINT FOREIGN KEY (course_id) REFERENCES courses '
                '(id) '
                'ON DELETE CASCADE,'
                'CONSTRAINT FOREIGN KEY (user_id) REFERENCES users '
                '(id), '
                'PRIMARY KEY (id) );'
            )
        )
        conn.commit()

# ========================= USERS TABLE OPERATIONS ============================

def get_user_by_email(email: str) -> dict | None:
    with db.connect() as conn:
        email_query = sqlalchemy.text(
            'SELECT * FROM users WHERE email=:user_email'
        )
        user_exists = conn.execute(email_query, parameters={
            'user_email': email
        }).one_or_none()
        if user_exists is None:
            return None
        return user_exists._asdict()


def register_user(auth_sub: str, username: str, email: str, role: str = 'student') -> dict:
    with db.connect() as conn:
        # Verify authorized user is not already in users table
        user_query = sqlalchemy.text(
            'SELECT * FROM users WHERE sub=:sub'
        )
        user_exists = conn.execute(user_query, parameters={
            'sub': auth_sub
        }).one_or_none()

        match user_exists:
            # If user does not exist, add to users table
            case None:
                create_query = sqlalchemy.text(
                    'INSERT INTO users(name, email, sub, role, '
                    'has_avatar) VALUES (:name, :email, :sub, :role, '
                    ':has_avatar)'
                    )
                # Build query using request information to add new user
                conn.execute(
                    create_query, parameters={
                        'name': username,
                        'email': email,
                        'sub': auth_sub,
                        'role': role,
                        'has_avatar': False}
                    )
                conn.commit()
                # Store value of new ID generated by database for user
                get_id_query = sqlalchemy.text(
                    'SELECT last_insert_id()'
                    )
                new_id = conn.execute(get_id_query).scalar()
                get_user_query = sqlalchemy.text(
                    'SELECT * FROM users WHERE id=:id'
                    )
                new_user = conn.execute(get_user_query, parameters={
                    'id': new_id
                }).one_or_none()
                user_entry = new_user._asdict()
            case _:
                # If user exists, return user information and avoid duplication
                if APP_ENV == 'dev':
                    print(f"{username} already has a registered account!")
                user_entry = user_exists._asdict()
    return user_entry


# Retrieve user Entity with matching token/user ID if it exists in mySQL db
def check_for_user(auth_sub: str) -> dict | None:
    """
    Verifies whether user with matching token/user ID of `auth_sub` exists
    and returns this user (if found)

    Parameters:
        auth_sub (str): subject/user ID extracted from JWT payload

    Returns:
        dict: matching user as a dictionary if exists or `None`
    """
    with db.connect() as conn:
        # Determine if user's token ID already exists in database
        user_query = sqlalchemy.text(
            'SELECT * FROM users WHERE sub=:sub'
        )
        match_user = conn.execute(user_query, parameters={
            'sub': auth_sub
        }).one_or_none()
        # Value of 'auth_sub' should be unique to a single user
        if match_user is None:
            return None
    # If user is authorized, return user
    return match_user._asdict()


# Verify whether user exists in database and has role of admin
def verify_admin(auth_sub: str) -> bool:
    """
    Verifies whether user has an existing profile with administrator role
    and returns this user (if found)

    Parameters:
        auth_sub (str): subject/user ID extracted from JWT payload

    Returns:
        bool: `True` if JWT of user indicates user is an administrator,
               else `False`
    """
    # Confirm user's token ID exists in mySQL database and has admin role
    with db.connect() as conn:
        user_query = sqlalchemy.text(
            'SELECT * FROM users WHERE sub=:sub AND role=:role'
        )
        admin_user = conn.execute(user_query, parameters={
            'sub': auth_sub,
            'role': 'admin'
        }).one_or_none()
    # Return True if a registered user with admin access, else False
    return True if admin_user is not None else False


# Verify 'instructor_id' refers to an existing user with instructor role
def check_instructor(instructor_id: int) -> dict | None:
    """
    Verifies if `instructor_id` refers to an existing profile of an instructor
    and returns this user (if found)

    Parameters:
        instructor_id (int): 'users' table ID of user to be verified

    Returns:
        dict: Matching user if valid instructor else `None`
    """
    with db.connect() as conn:
        # Determine user exists in database and checks for role
        user_query = sqlalchemy.text(
            'SELECT * FROM users WHERE id=:id AND role=:role'
        )
        # Verify user has role of instructor
        match_user = conn.execute(user_query, parameters={
            'id': int(instructor_id),
            'role': 'instructor'
        }).one_or_none()
        if match_user is None:
            return None
    # If user is a valid instructor return user, else None
    return match_user._asdict()


# Verify request contains all required table properties
def verify_request_body(required_keys: list, request_props: dict) -> bool:
    """
    Assesses whether one or more keys listed within `required_keys` are missing
    from the keys held in the `request_props` dictionary

    Parameters:
        required_keys (list): Array of all required key names
        request_props (dict): Map with keys to be found within `required_keys`

    Returns:
        bool: True if `request_props` is missing key(s) held in `required_keys`
              , else `False`
    """
    missing_reqs = False
    for i in range(0, len(required_keys)):
        if required_keys[i] not in request_props.keys():
            missing_reqs = True
            break
    return missing_reqs


# Retrieve basic information for all users
def get_user_list() -> list:
    # Retrieve all users in MySQL database
    with db.connect() as conn:
        user_query = sqlalchemy.text(
            'SELECT users.id AS "User ID", users.name AS Name, users.email as Email, '
            'users.role AS Role, users.has_avatar AS "Existing Avatar?" FROM users ORDER BY users.name ASC'
        )
        all_users = conn.execute(user_query)
    users = []
    #
    for user in all_users:
        next_user = user._asdict()
        # Remove non-essential user properties
        if 'sub' in next_user:
            del next_user['sub']
        users.append(next_user)
    return users


# Selectively update properties of user Enitities for PATCH requests
def update_user(user_request: dict, user_id: int) -> dict | None:
    """
    Updates requested course entity with matching courses table
    ID of `user_id` using the property value(s) listed within the
    submitted information held in `user_request`.

    Parameters:
        user_request (dict): Map of requested properties/values to be changed
        user_id (int): users table ID for user entity to be updated

    Returns:
        dict: Dictionary representation of updated user entity if submitted
        if verified to be existing
        , else None
    """
    user = get_user_by_id(user_id)
    # Catch any unexpected failures to retrieve requested course
    if user is None:
        return None

    # Selectively update user with only properties found in request
    for prop in user_request:
        match prop:
            case "email":
                user['email'] = user_request['email']
                user['name'] = str(user_request['email'])[:str(user_request['email']).strip().find('@')]
            case _:
                # Account for inclusion of miscellaneous additions
                continue
    # Update user entity properties with request props in user table
    with db.connect() as conn:
        update_query = sqlalchemy.text(
            'UPDATE users SET email=:email, name=:name '
            'WHERE id=:user_id'
        )

        conn.execute(update_query, parameters={
            'email': user['email'],
            'name': user['name'],
            'user_id': user_id
        })
        conn.commit()
    # Return dictionary conversion of user Entity for use in response
    return user


# Delete an existing course entity from courses table
def delete_user(user_id: int) -> None:
    """
    Deletes existing user entity with users table ID of `user_id`

    Parameters:
        user_id (int): users table ID for user Entity to be deleted

    Returns:
        NoneType: None
    """
    # Delete the requested userafter verifying requesting user is authorized 
    with db.connect() as conn:
        delete_query = sqlalchemy.text(
            'DELETE FROM users WHERE id=:user_id'
        )
        conn.execute(delete_query, parameters={
            'user_id': user_id
        })
        conn.commit()
    return


# Retrieve list of courses by ID associated with a user
def get_user_courses(user_id: int) -> list:
    course_list = []
    with db.connect() as conn:
        course_query = sqlalchemy.text(
            'SELECT courses.id, courses.title FROM courses'
            ' INNER JOIN enrollment ON '
            'courses.id=enrollment.course_id WHERE enrollment.user_id=:user_id'
        )
        # Retrieve IDs of all courses associated with user
        all_courses = conn.execute(course_query, parameters={
            'user_id': user_id
        })
        for course in all_courses:
            add_course = course._asdict()
            course_list.append(add_course)

    # Return list of all course IDs tied to user
    return course_list


def get_user_by_id(user_id: str) -> dict | None:

    with db.connect() as conn:
        # Retrieve dictionary conversion of user row from database
        user_query = sqlalchemy.text(
            'SELECT * FROM users WHERE id=:user_id'
        )
        user_result = conn.execute(user_query, parameters={
            'user_id': user_id
        }).one_or_none()
        if user_result is None:
            return None
    return user_result._asdict()


def get_users_by_role(role: str) -> list | None:
    with db.connect() as conn:
        user_query = sqlalchemy.text(
            'SELECT * FROM users WHERE role=:role'
        )
        try:
            match_users = conn.execute(user_query, parameters={
                'role': role
            })
        except Exception as e:
            # Print exception information for debugging
            if APP_ENV == 'dev':
                print(e.args)
            # Silently return if role is not recognized
            return None
        user_list = []
        for users in match_users:
            user = users._asdict()
            user_list.append(user)
        return user_list


def get_course_terms() -> list:
    with db.connect() as conn:
        term_query = sqlalchemy.text(
            'SELECT DISTINCT term FROM courses'
        )
        match_users = conn.execute(term_query).scalars().all()
        return list(match_users)


def get_course_subjects() -> list:
    with db.connect() as conn:
        subject_query = sqlalchemy.text(
            'SELECT DISTINCT subject FROM courses'
        )
        match_subjects = conn.execute(subject_query).scalars().all()
        return list(match_subjects)


# Retrieve user from 'users' table if it exists (filter with admin access)
def get_authuser_by_id(user_id: str, auth_sub: str | None,
                       admin_access: bool) -> dict | None:
    """
    Verifies whether user with table ID of `user_id` matches the
    user associated with the JWT payload subject/user ID of `auth_sub`. If
    `admin_access` is set to True, JWTs of users who are verified as
    admininstrators will not be compared to the JWT of the requested user.

    Parameters:
        user_id (str): table ID of requested user from 'users' table
        auth_sub (str): JWT payload's 'sub' value found in request
        admin_access (bool): boolean to indicate if admin user's JWT is ignored

    Returns:
        dict: Matching requested user if exists and user has admin access
        and/or is the same user as requested user, else `None`
    """
    # Verify user is admin if 'admin_access' indicates admin has direct access
    is_admin = False if not admin_access else verify_admin(auth_sub)
    param_dict = {}
    match is_admin:
        case 0:
            # Ensure user's JWT matches that associated with requested user
            id_query = sqlalchemy.text(
                'SELECT * FROM users WHERE id=:id AND sub=:sub'
            )
            param_dict['sub'] = auth_sub
        case _:
            # If user is verified as admin or admins do not have direct access,
            # adjust query to only ensure user with requested 'user_id' exists
            id_query = sqlalchemy.text(
                'SELECT * FROM users WHERE id=:id'
                )
    # Determine whether user exists according to required id and/or role
    param_dict['id'] = int(user_id)
    with db.connect() as conn:
        match_user = conn.execute(id_query,
                                  parameters=param_dict).one_or_none()
    # Return user information if user is verified and requested user exists
    if match_user is None:
        return None
    return match_user._asdict()


# Update user's 'has_avatar' value when avatar is modified
def update_user_avatar(user_id: int, has_avatar: bool) -> None:
    with db.connect() as conn:
        # Build query to directly update user with passed bool value of avatar
        user_query = sqlalchemy.text(
            'UPDATE users SET has_avatar=:avatar_state WHERE id=:id'
        )
        conn.execute(user_query, parameters={
            'avatar_state': has_avatar,
            'id': user_id
        })
        conn.commit()
    return

# ======================= COURSES TABLE OPERATIONS ============================

# Retrieve course Entity from mySQL database using combination of properties
def get_course_by_prop(subj: str, number: int, title, term: str,
                       inst_id: int) -> dict | None:
    """
    Verifies course entity with matching combination of properties values for
    `subj`, `number`, `title`, `title`, `term`, and `inst_id` exists and
    returns this course (if found)

    Parameters:
        subj (str): `subject` property value for requested course
        number (int): `number` property value for requested course
        title (str): `title` property value for requested course
        term (str): `term` property value for requested course
        inst_id (int): `instructor_id` property value for requested course

    Returns:
        dict: Dictionary of matching course entity if found, else `None`
    """
    # Check for unique combination match using all properties for precision
    with db.connect() as conn:
        course_query = sqlalchemy.text(
            'SELECT * FROM courses WHERE subject=:subject AND '
            'number=:number AND term=:term AND title=:title AND '
            'instructor_id=:instructor_id'
        )
        # Verify course with matching properties exists
        match_course = conn.execute(course_query, parameters={
            'subject': subj,
            'number': int(number),
            'term': term,
            'title': title,
            'instructor_id': int(inst_id)
        }).one_or_none()
        # Return existing course if it exists, else None
        if match_course is None:
            return None
        return match_course._asdict()


def get_page_links(request_url: str, retrieved_courses: list, page_limit: int,
                   offset: int, param_vals: dict | None = None) -> list:
    """
    Generates sets of numbered links corresponding to individual sets of
    `page_limit` sized courses, starting with the course set corresponding to
    the offset value of `offset` within all of the courses provided in the
    `retrieved_courses` array. If the `param_vals` variable is provided,
    its key:value pairs are added to the ends of each link as query string
    parameters

    Parameters:
        request_url (str): base url link to be filled with query parameters
        retrieved_courses (list): array of all courses to be included within
        the generated links via pagination
        page_limit (int): Maximum number of courses to include per link(page)
        offset (int): Index position of starting course within the array of
        all courses to be included in link pages, `retrieved_courses`
        param_vals (dict): Optional parameter value for a dictionary containing
        all required parameters to be subsequently added as part of each link's
        query string arguments

    Returns:
        (list): An array of all link that separate the contents of the
        `retrieved_courses` array into `page_limit`-sized pages that start
        from the value found at the index position of `offset` in the array
    """
    page_results = 0
    page_num_links = []
    has_params = param_vals is not None
    # If results for page are not the first set, generate link to previous
    # and add it as the first link
    if offset - page_limit >= 0:
        prev_link = {'page_number': 'prev'}
        prev_link['page_link'] = (f"{request_url}?"
                                  f"offset={offset - page_limit}"
                                  f"&limit={page_limit}")
        prev_link['offset'] = offset - page_limit
        prev_link['limit'] = page_limit
        # Add any additional requested arguments to add to URL query string
        if has_params:
            for key, val in param_vals.items():
                prev_link['page_link'] += f"&{key}={val}"

        page_num_links.append(prev_link)

    for entry in retrieved_courses:
        # Track number of results in page
        page_results += 1
        # Separate numbered page links by as many limit-sized sets per link
        if page_results % page_limit == 0:
            number = {'page_number': page_results // page_limit}
            number['page_link'] = (f"{request_url}?"
                                   f"offset={page_results - page_limit}"
                                   f"&limit={page_limit}")
            number['offset'] = page_results - page_limit
            number['limit'] = page_limit
            # Add any additional requested arguments to add to URL query string
            if has_params:
                for key, val in param_vals.items():
                    number['page_link'] += f"&{key}={val}"
            page_num_links.append(number)
    # If there are remaining pages excluded from last limit-sized set,
    # gather remaining results in last page
    if page_results % page_limit != 0:
        last_page = {'page_number': page_results // page_limit + 1}
        last_page['page_link'] = (
            f"{request_url}?offset="
            f"{page_results - (page_results % page_limit)}"
            f"&limit={page_limit}"
            )
        last_page['offset'] = page_results - (page_results % page_limit)
        last_page['limit'] = page_limit
        # Add any additional requested arguments to add to URL query string
        if has_params:
            for key, val in param_vals.items():
                last_page['page_link'] += f"&{key}={val}"
        page_num_links.append(last_page)

    # If results for page are not the last set, generate link to next set
    if (offset + page_limit) < page_results:
        next_link = {'page_number': 'next'}
        next_link['page_link'] = (
            f"{request_url}?offset={offset + page_limit}"
            f"&limit={page_limit}"
        )
        next_link['offset'] = offset + page_limit
        next_link['limit'] = page_limit
        # Add any additional requested arguments to add to URL query string
        if has_params:
            for key, val in param_vals.items():
                next_link['page_link'] += f"&{key}={val}"

        page_num_links.append(next_link)

    return page_num_links


# Retrieve course Entity from mySQL database using combination of properties
def get_courses_by_prop(search_categories: dict, limit: int | None = None,
                        offset: int | None = None,
                        request_url: str | None = None) -> list | None:
    """
    Selectively searches for courses with one or more matching combination of
    properties values for `subj`, `number`, `title`, `title`, `term`, and
    `inst_id` found within array of `search_categories` and returns the
    selection of courses with matching properties (if found)

    Parameters:
        search_category (dict): dictionary containing all search_type : value
        pairs
        limit (int): Optional parameter value for page limit for results
        offset (int): Optional parameter value for page offset for results
        request_url (str): Optional paramater value for the base url string.
        If included, each course's self-referencing link will be built using
        the provided value of `request_url` and added as the corresponding
        value for each course's 'self' key (and adding its assigned ID number)

    Returns:
        dict: Array of all matching course entities found, else `None`
    """
    # Check for unique combination match using all properties for precision
    with db.connect() as conn:
        categories = dict(search_categories)
        # Eliminate redundant properties
        length = len(categories)
        # If offset or limit is found, ensure both are present or return None
        has_limit = limit is not None
        has_offset = offset is not None
        is_page = has_limit and has_offset
        if (not has_limit and has_offset) or (has_limit and not has_offset):
            return None

        # Ensure at least pagination and/or search categories are used
        if length == 0 and not is_page:
            return None

        if is_page and length == 0:
            query_string = "SELECT * FROM courses "
        else:
            query_string = "SELECT * FROM courses WHERE "

        index = 0
        # Build query in matching key:value pair sequence order
        for keys in categories:
            match keys:
                case 'subject':
                    query_string += ("subject=:subject" if index == length - 1
                                     else "subject=:subject AND ")
                case 'term':
                    query_string += ("term=:term" if index == length - 1
                                     else "term=:term AND ")
                case 'number':
                    query_string += ("number=:number" if index == length - 1
                                     else "number=:number AND ")
                case 'instructor_id':
                    query_string += ("instructor_id=:instructor_id"
                                     if index == length - 1
                                     else "instructor_id=:instructor_id AND ")
                case 'title':
                    query_string += ("title=:title" if
                                     index == length - 1
                                     else "title=:title AND ")
                case _:
                    # Ignore unexpected keys
                    index += 1
                    continue
            index += 1
        # Place limit and order values at end of query if provided
        if offset is not None and limit is not None:
            query_string += " LIMIT :limit OFFSET :offset"
            categories['limit'] = int(limit)
            categories['offset'] = int(offset)
        course_query = sqlalchemy.text(
            query_string
        )
        # Return courses with matching criteria if existing, else None
        match_course = conn.execute(course_query, parameters=categories)

        if match_course is None:
            return None
        # Convert each entity into a dictionary and fill list to return
        course_list = []
        for item in match_course:
            course = item._asdict()
            course['number'] = int(course['number'])
            course['instructor_id'] = int(course['instructor_id'])
            if request_url is not None:
                course['self'] = f"{request_url}/{course['id']}"
            course_list.append(course)
        return course_list


# Retrieve course entity from mySQL database using its unique ID
def get_course_by_id(course_id: int) -> dict | None:
    """
    Verfies course Entity with matching Datastore-assigned ID `course_id`
    exists and returns this course Entity (if found)

    Parameters:
        course_id (int): Datastore-specific ID for requested course Entity

    Returns:
        dict: Dictionary of Matching course entity if exists, else `None`
    """
    # Verify course with provided ID exists in courses table
    with db.connect() as conn:
        course_query = sqlalchemy.text(
            'SELECT * FROM courses WHERE id=:course_id'
        )
        # Course ID should be unique to course and return a single course
        match_course = conn.execute(course_query, parameters={
            'course_id': course_id
        }).one_or_none()
        # Return existing course if it exists, else None
        if match_course is None:
            return None
    return match_course._asdict()


# Retrieve page(s) of all course Entites held in Datastore
def get_course_page(offset: int, limit: int, request_url: str) -> list:
    """
    Retrieves requested list of all course Entities currently
    stored within Datastore according to set of course Entities
    held within the page with offset of `offset` and limit of `limit`

    Parameters:
        offset (int): page `offset` value (starting number of first course)
        limit (int): page `limit` value (max number of courses/page)
        request_url (str): url of request to provide appropriate link to course

    Returns:
        list: Array of all course Entities held on page with offset value of
        `offset` and limit value of `limit`
    """
    courses = []
    with db.connect() as conn:
        # Query for requested page of course results
        query = sqlalchemy.text(
            'SELECT * FROM courses ORDER BY courses.subject LIMIT :limit '
            'OFFSET :offset'
        )
        course_page = conn.execute(query, parameters={'limit': int(limit),
                                                      'offset': int(offset)})

        for item in course_page:
            course = item._asdict()
            course['number'] = int(course['number'])
            course['instructor_id'] = int(course['instructor_id'])
            course['self'] = f"{request_url}/{course['id']}"
            courses.append(course)
    return courses


# Retrieve page(s) of all course Entites held in Datastore
def get_all_courses() -> list:
    """
    Retrieves requested list of all course Entities currently
    stored within Datastore according to set of course Entities
    held within the page with offset of `offset` and limit of `limit`

    Parameters:
        offset (int): page `offset` value (starting number of first course)
        limit (int): page `limit` value (max number of courses/page)

    Returns:
        list: Array of all course Entities held on page with offset value of
        `offset` and limit value of `limit`
    """
    with db.connect() as conn:
        query = sqlalchemy.text(
            'SELECT * FROM courses ORDER BY courses.subject'
        )
        course_page = conn.execute(query)
        courses = []
        for item in course_page:
            course = item._asdict()
            course['number'] = int(course['number'])
            course['instructor_id'] = int(course['instructor_id'])
            courses.append(course)
    return courses


def get_course_links(course_list: list, host_url: str) -> list:
    """
    Converts contents of array holding course IDs `course_list` into the
    correctly-formatted link to each course corresponding to the ID using
    the hosting machine's url/address `host_url` to construct the url link

    Parameters:
        course_list (list): List of IDs from `courses` table
        host_url (str): Hosting machine's url/address

    Returns:
        list: Array whose IDs are now replaced by the url link to the
        course corresponding to the given course ID from `courses` table
    """
    # Perform in-place conversion of course ids to course links
    for i in range(0, len(course_list)):
        course_list[i]['link'] = (str(host_url) + 'courses/'
                                  + str(course_list[i]['id']))
    return course_list


# Add new course entity to mySQL database table if complete
def add_course(subj: str, number: int, title: str, term: str,
               inst_id: int) -> dict:
    """
    Adds new course Entity to courses table with passed property values for
    subject, number, title, term, and instructor_id

    Parameters:
        subj (str): Value for course's `subject` property
        number (int): Value for course's `number` property
        title (str): Value for course's `title` property
        term (str): Value for course's `term` property
        inst_id (int): Value for course's `instructor_id` property

    Returns:
        dict: Dictionary of added or updated course entity
    """
    # Check for pre-existing course based on submitted course properties
    course_result = get_course_by_prop(subj, number, title, term, inst_id)
    with db.connect() as conn:
        match course_result:
            case None:
                # If no course is found add it to courses table
                course_query = sqlalchemy.text(
                    'INSERT INTO courses(subject, number, title, term, '
                    'instructor_id) VALUES(:subject, :number, :title, :term, '
                    ':instructor_id)'
                )
                conn.execute(course_query, parameters={
                    'subject': subj,
                    'number': number,
                    'title': title,
                    'term': term,
                    'instructor_id': inst_id
                })
                conn.commit()
                # Retrieve value of new ID generated by database for course
                get_id_query = sqlalchemy.text(
                    'SELECT last_insert_id()'
                    )
                course_id = conn.execute(get_id_query).scalar()

            case _:
                # If course already exists just retrieve course
                course_id = course_result['id']

        added_query = sqlalchemy.text(
            'SELECT * from courses WHERE id=:id'
        )
        new_course = conn.execute(added_query, parameters={
            'id': course_id
        }).one_or_none()
    # Add created/overwritten course entity to courses table
    return new_course._asdict()


# Selectively update properties of course Enitities for PATCH requests
def update_course(course_request: dict, course_id: int) -> dict | None:
    """
    Updates requested course entity with matching courses table
    ID of `course_id` using the property value(s) listed within the
    submitted information held in `course_request`.

    Parameters:
        course_request (dict): Map of requested properties/values to be changed
        course_id (int): courses table ID for course entity to be updated

    Returns:
        dict: Dictionary representation of updated course entity if submitted
        instructor ID value of `inst_id` was verified to be a valid instructor
        , else None
    """
    course = get_course_by_id(course_id)
    # Catch any unexpected failures to retrieve requested course
    if course is None:
        return None
    # Check if request is attempting to change the course instructor
    includes_instructor = 'instructor_id' in course_request
    changes_instructor = (int(course_request['instructor_id']) !=
                          int(course['instructor_id']))
    if includes_instructor and changes_instructor:
        # Only initiate verification process if request changes instructor
        new_ins = check_instructor(int(course_request['instructor_id']))
        if new_ins is None:
            # Prevent changing course Entity if new instructor is invalid
            return None
        # If new instructor verified, add course id to instructor's courses
        update_enrollment(int(course_request['instructor_id']),
                          course_id,
                          remove_op=False)
        # Remove course id from previous instructor's courses
        update_enrollment(int(course['instructor_id']),
                          course_id,
                          remove_op=True)

    # Selectively update course with only properties found in request
    for prop in course_request:
        match prop:
            case "subject":
                course['subject'] = course_request['subject']
            case "number":
                course['number'] = int(course_request['number'])
            case "title":
                course['title'] = course_request['title']
            case "term":
                course['term'] = course_request['term']
            case "instructor_id":
                course['instructor_id'] = int(course_request['instructor_id'])
            case _:
                # Account for inclusion of miscellaneous additions
                continue
    # Update course entity properties with request props in course table
    with db.connect() as conn:
        update_query = sqlalchemy.text(
            'UPDATE courses SET subject=:subject, number=:number, '
            'title=:title, term=:term, instructor_id=:instructor_id '
            'WHERE id=:course_id'
        )
        conn.execute(update_query, parameters={
            'subject': course['subject'],
            'number': course['number'],
            'title': course['title'],
            'term': course['term'],
            'instructor_id': course['instructor_id'],
            'course_id': course_id
        })
        conn.commit()
    # Return dictionary conversion of course Entity for use in response
    return course


# Delete an existing course entity from courses table
def delete_course(course_id: int) -> None:
    """
    Deletes existing course entity with courses table ID of `course_id`

    Parameters:
        course_id (int): courses table ID for course Entity to be deleted

    Returns:
        NoneType: None
    """
    # Delete the course which will induce cascading deletion
    with db.connect() as conn:
        # Cascade deletion will automatically remove all enrollment
        # entities that associate enrolled students and instructor to
        # the deleted course
        delete_query = sqlalchemy.text(
            'DELETE FROM courses WHERE id=:course_id'
        )
        conn.execute(delete_query, parameters={
            'course_id': course_id
        })
        conn.commit()
    return


# ======================= ENROLLMENT TABLE OPERATIONS =========================

# Retrieves list of enrolled student user IDs for course
def get_enrollment_list(course_id: int) -> list | None:
    with db.connect() as conn:
        # Ensure course exists
        course_query = sqlalchemy.text(
            'SELECT * FROM courses WHERE id=:course_id'
        )
        enroll_course = conn.execute(course_query, parameters={
            'course_id': course_id
        }).one_or_none()

        if enroll_course is None:
            # Report error if course does not exist
            return None
        enroll_course = enroll_course._asdict()
        # Retrieve list of student users associated with course
        student_query = sqlalchemy.text(
            "SELECT enrollment.user_id FROM enrollment "
            "INNER JOIN courses ON "
            "enrollment.course_id=courses.id "
            "INNER JOIN users ON "
            "enrollment.user_id=users.id WHERE users.role='student' "
            "AND courses.id=:course_id"
        )
        id_list = conn.execute(student_query, parameters={
            'course_id': course_id
        }).scalars().all()
        # Return list of enrolled students for course
        student_list = []
        match len(id_list):
            case 0:
                return student_list
            case _:
                # Ensure id's retain integer type value
                student_list = [int(id) for id in id_list]
        return student_list


def update_enrollment(user_id: int, course_id: int, remove_op: bool) -> None:
    with db.connect() as conn:
        # Verify existing user is associated with course
        user_course_query = sqlalchemy.text(
            'SELECT id FROM enrollment WHERE user_id=:uid AND '
            'course_id=:cid'
            )
        match_course = conn.execute(user_course_query, parameters={
            'uid': int(user_id),
            'cid': int(course_id)
        }).one_or_none()
        # Branch execution based on whether request id for removal or addition
        match remove_op:
            case 1:
                # If course is not associated with user, return
                if match_course is None:
                    return
                # If user is to be removed from course, use DELETE query
                op_query = sqlalchemy.text(
                    'DELETE FROM enrollment WHERE user_id=:user_id AND '
                    'course_id=:course_id'
                    )
            case _:
                # If association between course and user already exists, return
                if match_course is not None:
                    return
                # If user is to be added to course, use INSERT query
                op_query = sqlalchemy.text(
                    'INSERT INTO enrollment(user_id, course_id) '
                    'VALUES (:user_id, :course_id)'
                )
        # Add or remove row associated with matching user and course
        conn.execute(op_query, parameters={
            'user_id': user_id,
            'course_id': course_id
        })
        conn.commit()
    # Return upon completion of updating enrollment table
    return


# Modify all entities in enrollment table with matching course_id value
def enroll_students(enroll_request: dict, course_id: int) -> list | None:
    """
    Modifies entities of enrollment table whose course_id matches the
    courses table ID of `course_id` and by adding new entities with
    matching course_id of `course_id` with user_id of those held in 'add'
    property of `enroll_request` and removing those entities with matching
    user_ids held in 'remove' property of `enroll_request` that have matching
    course_id of `course_id`

    Parameters:
        enroll_request (dict): Map holding arrays of IDs to remove/add from the
          the enrollment table (list of user_id values for users with role of
          student)
        course_id (int): course_id for enrollment table entities to be altered

    Returns:
        list: Updated array of all existing entities of enrollment table that
        with course_id of `course_id` and user_id that has role of student, if
        contents of `enroll_request` were valid, else `None`
    """
    if 'add' not in enroll_request.keys() or 'remove' not in enroll_request.keys():
        # Catch request errors due to absence of either id array
        if APP_ENV == 'dev':
            print("enroll_students: NEITHER 'add' nor 'remove' was detected!")
        return None

    # Get list of all integer ids for student users enrolled in course
    enroll_list = get_enrollment_list(course_id)
    if enroll_list is None:
        if APP_ENV == 'dev':
            print("enroll_students: Enrollment list NOT returned")
        # Report error if expected course is not located
        return None

    # Copy extracted student users' IDs into separate list for verification
    with db.connect() as conn:
        student_query = sqlalchemy.text(
            "SELECT id FROM users WHERE role=:role"
        )
        all_studentIDs = conn.execute(student_query, parameters={
            'role': 'student'
        }).scalars().all()
    student_list = list([int(id) for id in all_studentIDs])

    # Verify request is valid and formatted correctly before modification
    valid_request = verify_enroll_request(enroll_request, student_list)
    if not valid_request:
        if APP_ENV == 'dev':
            print("enroll_students: Failed to verify enrollment request")
        # If invalid request report error
        return None
    # Gather all ids to add from 'add' list that are not already in enrollment
    add_ids = set(
        enroll_request['add']).difference(enroll_list)
    # Gather all ids to remove from 'remove' that are present in enrollment
    remove_ids = set(
        enroll_request['remove']).intersection(enroll_list)

    # Directly modify course's list of enrolled students with gathered ids
    [enroll_list.append(id) for id in add_ids]
    [enroll_list.append(id) for id in remove_ids]

    # Add entities with corresponding user_id, course_id to enroll
    for id in add_ids:
        update_enrollment(id, course_id, False)
    # Remove entities with corresponding user_id, course_id to disenroll
    for id in remove_ids:
        update_enrollment(id, course_id, True)
    return enroll_list


# Verify 'add' and 'remove' lists in enrollment request are valid
def verify_enroll_request(enroll_request: dict, id_list: list) -> bool:
    """
    Assesses whether `remove` and `add` property arrays of `enroll_request`
    contain valid collections of student ID values

    Parameters:
        enroll_request (dict): Map containing arrays of student user IDs to be
          validated
        id_list (list): List of all IDs of verified student users

    Returns:
        bool: `True` if both `add` and `remove` arrays are considered to be
          valid, else `False`
    """
    # Condition #1: Request is invalid if any ID in 'remove' or 'add' list does
    # not match a verified user who is a student

    # If both 'remove' and 'add' arrays contain only validated IDs of students,
    # they will both be subsets of the extracted array of all valid student IDs
    valid_ids = (set(enroll_request['add']).issubset(id_list) and
                 set(enroll_request['remove']).issubset(id_list))
    if not valid_ids:
        return False

    # Condition #2: Request is invalid if any ID is found in both 'add' and
    # 'remove' lists

    # Convert both 'remove' and 'add' lists to sets and find any id values
    # shared between them by checking if any are found in their intersection
    overlap = bool(
        set(enroll_request['add']).intersection(enroll_request['remove'])
        )
    if overlap:
        return False
    return True
