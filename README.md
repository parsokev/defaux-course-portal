# Project Description

This project leverages the use of the Google Cloud Platform (GCP) to provide a deployable cloud-based application that serves as a mock
college course managment portal. Its current main functionalities include:

  - Customizable user account profiles that display the full list of all user-associated courses and
    a personalized avatar image that can be updated by uploading a new local image file
    (stored using a dedicated Google Cloud Storage Bucket).

  - A course catalog that can be viewed via a central table holding all current or past courses logged with the application

  - A course search feature for quickly locating a course by its year, semester, or assigned instructor

  - A course registration page to be used by course instructors and adminstrators to enroll a student into a specified course

  - Addition/modification/removal of any course logged with the application by adminstrators

  - Creation of new user accounts by any visting user who does not already have an existing account

  - User account management by administrators


This application was designed with the intention to:

 1. Serve as a template and potential resource for developing web-based applications within a production-hardened environment
    that allows for the safe management of sensitive application data.
    
 2. Provide a pre-built, user-friendly development environment that allows for quickly alternating between different environment
    configurations (such as development, production, and deployment), and automation of local application setup and
    maintenance.
  
 3. Deliver an application that can be readily deployed as a cloud-based service in a secure and production-ready state using
    Google Cloud Platform's (GCP) Cloud Run API without requiring the outright purchase of any subscription-based or starting service costs
    (completely free for any user able to create a new Google Cloud Platform account or less than $10 for any user with an existing account).


## Project Overview

This is a web-based application that utilizes:

   - Docker Compose and GNU Make to configure the environment and execution settings of the following containerized services
     within an internal Docker network when locally hosting the application:

       1. A Flask API server that is executed using Gunicorn for optimizing server performance and potential scalability for use
          when locally hosting and, more importantly, when hosted by Google Cloud Run as a deployed service.


       2. A HashiCorp Vault server that is used to store application credentials and provide runtime encryption/decryption services when
          application is hosted on local machine


       3. A Nginx reverse-proxy server to handle redirection of external HTTP requests to the appropriate containerized application service
          over TLS-secured HTTPS endpoints and provide load balancing when application is hosted on a local machine.

   - Relatively modern production-hardening practices when hosting the application on a local machine to mitigate potential exposure of
     sensitive application data necessary for application functionality, such as Google Cloud authentication credentials including:

      - Short-lived Google OAuth2.0 service tokens and Auth0 OpenID Connect (OIDC) tokens for integrating authorization/authentication
        practices appropriate for cloud-based applications
      
      - Open source data encryption tools, including SOPS, PGP, and GnuPG for securely managing sensitive data on local machine

      - Docker images that use multi-stage build processes with final stage ensuring container is run using a non-root user with scoped permissions


   - Google Cloud SQL API for management of a MySQL database that stores application resources, such as course, user, and course-associated
     enrollment/registration data  

   - Google Cloud Storage API for fine-grained bucket storage of uploaded user avatar image files

   - Google Cloud Platform's Artifact Registry for managing deployed application images to the project-specific repository.

   - Google Cloud Platform's Cloud Run API, a serverless application management platform, to allow for running a deployed application container image
     within an externally accessible GCP-managed container.

   - Google Cloud Platform's Secret Manager for injection of application secrets as environment variables into deployed service environment at runtime

   - Shell scripts for automating local environment setup, initial vault configuration, secure application credential and vault key shard rotation,
     file encryption/decryption, and other utility services.


## Expansion on Included Production Environment Features and Hardening Measures

Since this application was designed to be an externally accessible cloud-based application to be deployed using the
Google Cloud Run API service, production hardening was introduced to this application through the following concepts:

 - Application credentials are stored within an external HashiCorp Vault service and can be accessed as in-memory variables
   at application runtime when hosted on a local machine

 - Sensitive data held within files required for use by the application at runtime are encrypted using PGP keys.

    - The contents of these files are accessed via SOPS-mediated injection of the encrypted file's contents into the process
      executing the application as decrypted environment variable values. The decrypted values are inaccessible outside of this
      process, allowing the file to remain encrypted while its contents can be safely consumed by the application.

 - Local shell scripts are provided to automate regular rotation of both the Flask application credentials and Vault credentials
   in order to minimize the risk of bad actors gaining unauthorized access using compromised credentials.
   
   - Rotation of Flask application's session secret key that is utilized as the private key for session data encryption
   
   - Rekeying of Vault server's unseal key shards and rotation of the master key upon successful rekey verification

   - Reissuing of policy-based vault service token for userpass authentication and revoking of the previously active token

   - Strict issuance of root vault token for root-required vault tasks with immediate token revokation upon completion of required task

   - Reissuing of short-lived Google OAuth2.0 Service Tokens used by application to authenticate to Google Cloud API services

      - Use of a GCP Workload Identity Pool (form of Workload Federated Identity) that utilizes Auth0 as an external OIDC pool provider to
        produce short-lived Google Auth2.0 service tokens implemented via REST HTTP API or Gcloud CLI tool without requiring direct inclusion
        of an ADC credentials file within the deployed (or locally-hosted container) application. 

 - Upon completion of recommended project setup, two distinct sets of PGP keys can be used to alternate PGP key encryption for each vault
   unseal key shard and service token. This is easily managed using SOPS and GnuPG

 - The application supports the use of Vault Transit encryption keys for runtime encryption/decryption of sensitive application data 

 - User authentication is jointly enforced by an Auth0-managed database and a Google Cloud SQL-managed MySQL database. 
 
 - Application-scope (Google Cloud API services) authentication/authorization is enforced with short-lived Google OAuth2.0 service tokens generated from the 
   workload federated identity (WIF) tied to the authenticated GCP service account (Auth0 is serves as the external OIDC provider)


> [!NOTE]
> This project is currently considered to be in an unfinished state and no longer under active development. There are several
> planned (currently incomplete) additions such as local testing suites, Google's Artifact Registry-compatible CI/CD workflows,
> and other conventional application development features found in traditional development environments that are currently absent.
> This would also extend to quality-of-life improvements such as more responsive UI elements and additional UX/accessibility features.
> It is still planned to resume development at a future time and date when possible.


# Project Setup Overview

This project requires an active Google Cloud Platform (GCP) account with access to:

 - GCP's Artifact Registry if wishing to deploy the application as a Docker image built from the provided Dockerfile

 - GCP's Cloud Run if wishing to have the running application hosted over an external IP address (instead of locally-hosting) 
   and have access to a running instance of a MySQL database using Cloud SQL

For first-time GCP users creating a GCP account, $300 of credit will be awarded to mitigate operation costs for first several months.


This project also requires additional GCP account setup steps to be completed in order to enable use of both Google's Cloud Run and Artifact Registry
by the application which can accomplished by following the linked guides:

 - [Setting up the application using GCP's Cloud Run](https://docs.cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service)

 - [Deploying the application Docker image to GCP's Artifact Registry](https://cloud.google.com/artifact-registry/docs/docker/pushing-and-pulling)

 - [Running the deployed application image using GCP's Cloud Run](https://cloud.google.com/run/docs/quickstarts/deploy-container)

 - [Configure and Establishing a Connection to a MySQL database instance using Cloud SQL](http://cloud.google.com/sql/docs/mysql/connect-app-engine-standard)

As a final required configuration step, the user must generate and store several sets of credential and environment variables
for request verification/authorization purposes, connection authorization purposes, and Container image environment setup purposes.


# Setting up Google Cloud Account, Project, and Required Cloud API Services

## Setting up Google Cloud Account and Application-Dedicated Project

> [!CAUTION]
> ***The outlined project setup utilizes the most basic configuration settings available in order to reduce the total operational costs***
> ***of running the application and is NOT intended for use in active production***.
> 1. Additional time will be required to complete startup and shutdown of all databases and virtual machine instances utilized to run the application.
> 2. It will also reduce data storage capacity and disables data backup protection.
> 3. While the instance connection security configurations outlined by this project setup are sufficient for development purposes, many additional
>    security measures/services recommended for production are not enabled or fully utilized. It is recommended to introduce additional security
>    measures/services suggested by GCP to harden connection security and mitigate potential compromise of authentication credentials.  


1. Create new account (billing must be enabled)

2. Create a new project with a chosen name (use hyphens in place of spaces for naming)

3. Enable the following APIs for the project:
  - Compute Engine API
  - Cloud SQL API
  - Google People API
  - Cloud Storage API
  - Cloud SQL Admin API
  - Artifact Registry API
  - Identity and Access Management (IAM) API
  - Identity-Aware Proxy API
  - Identity Platform API
  - Cloud Resource Manager API
  - IAM Service Account Credentials API
  - Security Token Service API
  - Secret Manager API


## Setting up Required Google Cloud App Services

After the initial Google Cloud account and project have been successfully created/configured, you can now begin the initial setup
of the two main Google Cloud API services utilized by the application:

1. [Google Cloud SQL using MySQL](https://docs.cloud.google.com/sql/docs/mysql?_gl=1*zy5sux*_up*MQ..&gclid=EAIaIQobChMIgYiihe_AkQMVzCFECB1LlQO2EAAYASAAEgJzKvD_BwE&gclsrc=aw.ds)

2. [Google Cloud Storage](https://docs.cloud.google.com/storage/docs/introduction?_gl=1*uls7zb*_up*MQ..&gclid=EAIaIQobChMIgYiihe_AkQMVzCFECB1LlQO2EAAYASAAEgJzKvD_BwE&gclsrc=aw.ds)

3. [Google Secret Manager](https://docs.cloud.google.com/secret-manager/docs/overview)


### Creating a MySQL Database instance using Cloud SQL

The application utilizes a MySQL database instance that is managed by Google Cloud SQL to store user, course and enrollment/registration data.

If wishing to manually set up your instance with a desired configuraton in mind, follow steps listed [here](https://docs.cloud.google.com/sql/docs/mysql/create-manage-databases)

Otherwise, you may follow the steps listed below to create and properly configure the MySQL database for use by the local application.

> [!IMPORTANT]
> The steps detailed below will create a new MySQL database instance **that has the minimum overall operational cost but may also require**
> **up to or possibly exceeding 20 minutes to be created by Google Cloud SQL**. 

1. Navigate to `Cloud SQL` within the left-hand navigation bar and set up a new MySQL database instance to manage connections to the Flask application server

    1. Navigate to `Create a MySQL instance` page from the `Google Cloud SQL` page, begin by providing an instance ID and password

    2. Select `MySQL 8.0`  from `Database version` section

    3. Select `Enterprise` under the `Choose a Cloud SQL edition` section
    
    4. Select `Sandbox` under the `Edition preset` section
    
    5. Select the closest region to your local address and select `Single Zone` under Zonal Availability
    
    6. Click on `Show Configuration Options` under `Customize your instance`:
        - Click on `Machine Configuration` and select `Shared Core` and `1vCPU, 0.614 GB` options
    
    7. Click on `Data Protection` and uncheck any all checked options
        - ***NOTE: This step should be completed only if stored data is unimportant and is used for testing or demonstration purposes***
    
    8. Click the `Create Instance` button at the bottom of the page to start the creation of a new Cloud SQL database instance that manages MySQL database instances.


    9. After the Cloud SQL instance has been created, the connection name displayed displayed under the `Connect to this instance` section should follow the syntax of
       `<your-project-id>:<selected-region-zone>:<your-instance-id>`. **Write the name of the instance connection to the temporary text file mentioned at the start**
       **of the top-level project setup section. This will be assigned value of the KV secret `INSTANCE_CONNECTION_NAME`.** 

2. Next, create a new MySQL database instance that is managed by the Cloud SQL instance.

   1. Click on `Databases` item from left-hand navigation bar (if this is not visible ensure the created Cloud SQL instance was clicked on after its creation)

   2. Click `Create Database` and enter a name for the new MySQL database instance that will store course, user, enrollment (registration) entities

   3. Click `Create` to complete the creation of the MySQL database instance.

   4. **Write the name of the created MySQL database instance to the temporary text file as the assigned value for the `DB_NAME` of the KV secret.**

3. Finally, it is good practice to create a dedicated service account for authenticating to the MySQL database (created in a later section)
   and a database-specific user with built-in authentication for accessing the MySQL database instance.

   1. Click on the newly created MySQL database instance name/ID from the `All Instances` page and then click on the `Users` item from Side Navigation bar

   2. Click on the `Add user account` button -> Ensure `Built-in authentication` is selected.

   3. Enter a username and password to be used as the new user's MySQL login credentials. **Ensure these are different from those of the root user to avoid potential confusion!**

   4. Ensure `Allow any host` is selected, then click `Add` to add the user to the created MySQL instance. The database can now be actively queried by accessing
      `Cloud SQL Studio` using the user's name and password to directly add schema definitions or test validity of queries over your preferred browser client.
   
   5. **Write the username and password of the added user to the temporary text file as the assigned values for the `DB_USER` and `DB_PASS` KV secrets, respectively**


### Setting Up and Configuring Google Cloud Storage

The application utilizes Google Cloud Storage to store uploaded images for use as user profile images.

These are stored within a dedicated bucket for holding user profile images whose name will be the assigned value of the `AVATAR_BUCKET_NAME` KV secret.

This can be configured by completing the following steps:

 1. Navigate to the Cloud Storage page by clicking on the `Cloud Storage` from within the project main side navigation bar

 2. Click `Create a bucket` and enter the desired name of the bucket. **Write this name down in the temporary text file for the `AVATAR_BUCKET_NAME`**
 
 3. Select `Region` and select the closest region to your physical address. **Write this name down in the temporary text file for the `REGION` KV secret**
 
 4. Click `Continue` -> Ensure `Set a default class` and `Standard` are selected -> Click `Continue`
 
 5. Under `Prevent public access`, uncheck `Enforce public access prevention on this bucket` (this bucket's data must be accessible when web hosting)
 
 6. Under `Access Control`, ensure `Uniform` is selected -> Click `Continue`
 
 7. Click `Create` to create the bucket for use in project


## Creating a New Non-Root Service Account for Authenticating to Google Cloud

It is recommended to create a separate non-root service account for connecting/authenticating to the Google Cloud API clients utilized by the
project application.

Primarily, this service account will be utilized for authenticating to the now configured Google Cloud Storage and Google Cloud SQL clients.

This can be accomplished by completing the following steps:

1. Select the "IAM & Admin" from the Side Navigation Bar after navigating back to the projects Dashboard page

2. Select the `Service Accounts` item from the Navigation Bar on the left hand side

3. Click on `Create Service Account`

4. Enter the desired service account user's name/ID (this will assign email address of `<id>@<project-id>.iam.gserviceaccount.com`)

5. Click `Create and Continue` to proceed to `Permissions`

6. Select and add the roles of:
    - Storage Admin
    - Storage Object Viewer
    - Cloud SQL Client
    - Cloud SQL Admin
    - Cloud Run Admin
    - Cloud Run Developer
    - Logs Viewer
    - Service Account Token Creator
    - Service Usage Admin IAM
    - Secret Manager Admin
    - Secret Manager Secret Accessor


7. Click `Continue` and then `Done` to complete creation of the new user service account


> [!IMPORTANT]
> **Steps 8-10 are only required if wishing to exclusively use gcloud CLI tool to authenticate to the Google Cloud services**
> If wishing to not rely on a locally-referenced service account credentials file, a REST API-based option is available for this purpose.
> You also have the option to encrypt the generated service account credentials file using PGP encryption. This will be discussed in later sections.
> **The service account credentials file will NOT be directly placed within the application. It will be referenced for the creation**
> **of temporary token-based credentials that are passed to the different Google Cloud Service API clients**


8. After navigating back to `Service Accounts` page for project, click `Manage Keys` from `Actions` dropdown menu of row for new service account

9. Under `Keys`, click `Add key` -> `Create New Key` -> `JSON` -> `Create` to download a JSON file containing a new private key and 
   other required service account credentials to your local machine's default downloads directory.

10. Store this file in a secure location, then delete any copies of this file from both your local machine's and your browser client's downloaded files
    directories. If on Windows OS, you should also ensure to empty the Recycle Bin after ensuring the file has been transferred to a known location.
    **Ensure you know the local path from this file to the project root directory as this will be required if wishing to run this application securely on your local machine**


## Setting up Local Environment on Host Machine

There are several basic but fundamental software and command line tools that are required to both complete
application setup and execution. **Of particular note, the application was developed to be utilized within** 
**POSIX-compliant shell environments and utilizes bash shell scripts to automate major steps of the setup process**.


**Windows Users:**
If working on machine that utilizes Windows OS, it is strongly recommended to install [Microsoft Visual Studio Code editor](https://code.visualstudio.com/docs) with
[Windows Linux Subsystem](https://learn.microsoft.com/en-us/windows/wsl/about) (WSL) in order to properly utilize this application. **After completing the**
**initial WSL installation and setup process, complete all of the steps listed in the remainder of this section and beyond within WSL.**


**MacOS Users:**
If your local machine utilizes MacOS, you can install [Homebrew](https://brew.sh/) and change the shebang operators located on the first line of each shell script
from `#!/usr/bin/env bash` to `#!/opt/homebrew/bin/bash` to successfully execute the shell scripts within a separate bash shell


**Non-Debian/Non-Ubuntu Linux Distribution Users:**
In order to ensure widespread compatibility, bash shell commands used by the shell scripts use Debian Linux commands. While the majority
of commands should be compatible with most Linux distributions, each of the scripts should be reviewed before executing them to ensure one or more
incompatible commands result in failure (if you are using other Linux distributions, the shell scripts will most likely be considered fairly straightforward
and easy to adjust where necessary)


### Installing Globally Required Application Dependencies 

This application utilizes an internally networked suite of Docker container services utilizing Docker Compose
to coordinate the full application startup sequence.

To streamline the application startup process, the application utilizes a Makefile to allow a user to launch the
full application under environment configurations using preset commands defined within this Makefile.

Finally, this application utilizes Python3 to create a virtual environment and install application dependencies
within this virtual environment for use by shell scripts that automate the local application setup process.

This requires the installation of the following on your local machine:

  1. [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  2. [GNU Make](https://www.gnu.org/software/make/)

After these are installed, the final local environment setup step is installing Google Cloud Platform's dedicated CLI tool, `gcloud`


### Install and Configuring Google Cloud Platform's gcloud CLI tool

In order to be able to locally host or deploy the application, the `gcloud` CLI tool must be installed and properly
configured on your local machine. 

1. Follow the OS-specific steps for setting up your local python enviroment listed [here](https://docs.cloud.google.com/python/docs/setup#linux)

    - Ensure you have setup and activated the local virtual environment within the project root directory to isolate Python application dependencies
      that are installed locally by the application


2. Install `gcloud CLI` using pip installer as listed [here](https://docs.cloud.google.com/sdk/docs/install-sdk#deb)


3. Initialize and configure gcloud CLI by entering `gcloud init` into the terminal.

    1. Wait for request link to appear in console output and open link in a new browser client window

    2. Confirm gmail account associated with GCP account and set all acceptable permission settings for Google CLI SDK

    3. If confirmed successfully, you should be automatically redirected to page announcing gcloud CLI authorization success and
     the console output should indicate successful login using the selected gmail account address

    4. Enter the numerical value corresponding to the previously created project from list of projects


4. Setup local authentication credentials for the GCP account by entering `gcloud auth application-default login` into the terminal

    1. Wait for request link to appear in console output and open link in a new browser client window

    2. Confirm gmail account associated with GCP account and set all acceptable permission settings for Google Auth Library (GoogleAuth2.0)

    3. If confirmed successfully, you should be automatically redirected to page announcing gcloud CLI authorization success


5. Set the project to be be hosted/deployed as your quote project by entering `gcloud auth application-default set-quota-project`


## Creating Application Auth0 Client and User Credentials

The Flask server utilizes [Auth0](https://auth0.com/docs) for user authentication and support role-based authorization to MySQL database
resources (not to be confused with application-wide authorization enforced by Google OAuth2.0).

If unfamiliar with Auth0, there is a brief overview of how Auth0 can be used to register the web application using the Auth0 Dashboard
[here](https://auth0.com/docs/get-started/auth0-overview/create-applications/regular-web-apps).


The following steps must be completed in order to ensure both the application and a default admin user are registered properly with Auth0:

1. Login to an existing or newly created Auth0 account and then click on `Applications` -> `Create Application`.

2. Select "Regular Web Applications" for Application Type and assign a name to the application -> Click `Create`.

3. **Write the `Domain`, `Client ID` and `Client Secret` values displayed under `Settings` -> `Basic Information` to the temporary**
   **text file as these will be the assigned values for the `DOMAIN`, `CLIENT_ID`, and `CLIENT_SECRET` KV secrets, respectively.**

4. While still within `Applications` -> `Your Application Name` -> `Settings`, scroll down to the bottom of the page
   and click on `Advanced Settings` -> `Grant Types`. Ensure `Password` is checked and check it if it is not.

5. Define an email address and password value for a default admin user to guarantee initial access to application features

6. Create a default admin user account to be registered with the application over Auth0 to guarantee initial access to application features.

    1. Click on `User Management` on the left-hand side of your Auth0 account page -> Click `Users` -> Click `Create User`.

    2. Enter an email address and password value for the default admin user 
   
    3. Ensure the default admin user is registered with the correct email and corresponding password value.
    
    4. **Write the entered the default admin user's email (shown under Name) and password (not shown) to the temporary text file as** 
       **these will be the assigned values for the `DEFAULT_ADMIN_USERNAME` and `DEFAULT_ADMIN_PASS` KV secrets, respectively.**

    5. **Write the displayed Auth0 database connection name (shown under Connection) to the temporary text file as this will be**
       **the assigned value for the `AUTH_DB_CONNECTION` KV secret.**

> [!NOTE]
> **This is the only time direct manual entry of a user to Auth0 or the MySQL database is required. All future user accounts are**
> **expected to be created via direct interaction with the running application over the preferred browser client**.
> The required manual addition of a default admin account was deemed necessary to mitigate the potential security risks
> introduced by an unrestricted endpoint that would otherwise be needed to create the default admin user account.


7. Create the three key roles used be distinguish what MySQL database resources a user is authorized to access:

   - `admin` - Administrator with access to ALL MySQL database resources

   - `instructor` - Course Instructor with access to MySQL database resources associated with courses they instruct and personal profile

   - `student` - Student with access to only MySQL database resources associated with personal profile
   
   1. Click on `User Management` -> `Roles` -> `Create Role` 
   
   2. Enter each of the three provided shorthand role values (i.e., `admin`, `instructor`, `student`) as the `Name` value -> Click `Create`


8. Assign the appropriate role of `admin` to your created default admin user.

   1. Select the created `admin` role under `Roles`

   2. Click the `Users` tab within the selected `admin` role's page, then click `Add Users` and type in the default admin user's email

   3. Select the default admin user from the populated list, then click `Assign` to assign the `admin` role to the default admin user.


9. With the three distinct roles defined within Auth0, **write the Auth0-issued role IDs for the `admin`, `instructor`, and `student`roles**
   **to the temporary text file as the assigned values for the `ADMIN_ROLE_ID`, `INSTRUCTOR_ROLE_ID`, and `STUDENT_ROLE_ID` KV secrets, respectively.**
   

10. Since this application utilizes Resource Owner Password Flow (ROPC), the OAuth 2.0 authorization server must be manually
    configured to utilize the application's default Auth0 database connection for authenticating the registered users.

    1. Navigate to your Auth0 account's tenant settings by clicking the profile dropdown element in the top left-hand corner
       and then clicking on the `Settings` item.

    2. Scroll down to the `Api Authorization Settings` section and locate the `Default Directory` subsection

    3. Click on the dropdown element under `Default Directory` and select the name of the database connection
      associated with the application. This is usually `Username-Password-Authentication` by default.

    4. Click `Save` within the `Api Authorization Settings` section.


11. In order to access information on users registered with Auth0, requests must be placed to endpoints secured by the Auth0 Management API.
    This requires a separately retrieved access token that has a set of scoped permissions that can be managed within the Auth0 Dashboard.

    1. Navigate back to within the main Dashboard page and click on `Applications` -> Select your application -> Click on the `APIs` tab

    2. Within the opened `APIs` tab, the `Auth0 Management API` should be displayed with slide toggle button to the right of its name.
       If the toggle is slid to the left and does not display `Authorized`, click on it to toggle it to the right and now display
       `Authorized`
   
    3. After setting the `Auth0 Management API` to `Authorized` for the application, click on the expand icon displayed to the right of the
       slide toogle button to reveal additional permissions/scoping settings that can be granted to the Auth0 Management API.

    4. **Write the URL value displayed to the right of `Identifier` into the temporary text file as the assigned value of `AUTH_MANAGEMENT_API_ID`**
       **KV secret.**

    5. Under `Permission` subsection, check/select the following permissions/scopes:
       - `read:users`
       - `update:users`
       - `create:users`
       - `read:roles`
       - `read:role_members`
       - `create:role_members`
       - `update:users`
       - `update:users_app_metadata`
       - `update:current_user_metadata`
       - `delete:users`
      
    6. Click `Update` to update app permissions.

    These scopes/permissions will now be granted to the access token retrieved from the Auth0 Management API and can then be passed within
    requests to gain authorized access to user data at Auth0 Managment API secured endpoints.

    To learn more you may visit the official REST API documentation for Auth0 Auth Management API:
      [Get User Roles in using Auth0 Management API endpoint](https://auth0.com/docs/api/management/v2/users/get-user-roles#scopes)
      [Using Client Credentials Flow for Authenticating to Auth0 Management API](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow/call-your-api-using-the-client-credentials-flow)
      [Using User Roles for User Authentication using Auth0 Management API](https://auth0.com/docs/get-started/apis/enable-role-based-access-control-for-apis)


12. To complete the registration of the default admin user, several key identifiers for the default admin user must also be directly added
    to the MySQL database. This will ensure the admin user can be successfully authenticated by the Auth0 Application and 
    authorized to access all resources held within the MySQL database.
     
     1. From the created project dashboard, click on `Cloud SQL` from within the left-hand side navigation bar.

     2. Click on the created Cloud SQL database instance for managing the MySQL database storing the application data.

     3. On the left hand side, click on `Cloud SQL Studio`. A dialog requesting login credentials should now appear.

     4. Select the MySQL database instance for the dropdown selection menu and enter the credentials of the database user with built-in authentication
        that was previously created to log in to your created MySQL database
   
     5. Click on the `Untitled Query` tab to access an empty SQL console that can send direct SQL queries to the MySQL database instance.

     6. As the application has not been executed yet, the users table does not yet exist so this must first be created by entering the following SQL
        command:
         ```SQL
               CREATE TABLE IF NOT EXISTS users 
                (id INT NOT NULL AUTO_INCREMENT, 
                email VARCHAR(50) NOT NULL, 
                name VARCHAR(50) NOT NULL, 
                role ENUM('admin', 'instructor', 'student') NOT NULL, 
                sub VARCHAR(100) NOT NULL, 
                has_avatar BOOL NOT NULL, 
                UNIQUE (email), 
                UNIQUE (sub), 
                PRIMARY KEY (id) );
         ```
      7. Ensure this executed successfully then you must add the default admin user to the table using the following SQL query template:
         ```SQL
               INSERT INTO users(name, email, sub, role, 
               has_avatar) VALUES (:name, :email, :sub, :role, 
               :has_avatar)
         ```
         - Replace `:name` with the value preceding the @ symbol of your default admin user's email address
         - Replace `:email` with your default admin user's full email address
         - Replace `:sub` with Auth0-issued User ID for the default admin user (located within the `Users` subsection of the Auth0 `Users Management` section)
         - Replace `:role` with the default admin user's Auth0-assigned role, `admin`
         - Replace `:has_avatar` with `False`
   
      8. Submit the query and ensure the default admin user has been successfully added to the users table of the MySQL database:
         ```SQL
               SELECT * FROM users
         ```

   Once these steps have been completed, the default admin user can be used to login into the application upon locally executing it
   for the first time and utilize admin-restricted endpoints to populate courses, create additional users of various roles, assign
   course instructors, enroll students in courses, and other restricted application features.


## Creating a GCP Workload Identity Pool for Service Account Impersonation

While Google Cloud Platform provides users with option to authenticate to Google Cloud API services using a local default ADC file,
it is considered better practice to use a project-dedicated (or service-dedicated) service account for authentication.

However, authenticating using a service account by default still requires the use of local JSON file containing the service account 
credentials, which typically contains sensitive data such as private keys that must be also copied within the running container.

This is can serve as a potential source for gaining entry to the service account if extracted from the container, especially if being
deployed.


### Configuring an OIDC-based Workload Identity Federation (WIF) for Google Cloud

Creating a Workload Identity Federation (WIF) via Google Cloud's Workload Identity Pool provides a more secure way of authenticating
to Google Cloud by allowing a Google OAuth2.0 Service access token to impersonate an authorized Google Cloud service account.
This token can then be provided in place of the service account credentials file for authenticating to any all Google Cloud API services.

Due to complicated and in-depth nature of configuring a new workload identity pool with Auth0,
the step-by-step instructions for this setup are not explicitly outlined here but rather deferred to instructions
listed within this [gist post by Wilfred van der Deijl](https://gist.github.com/wvanderdeijl/95f511d4f2749b8b6ad38c26f27da251#preparation)
as they are were found to be impressively concise and straightforward in describing the necessary steps involved.


It is also recommended to visit the [official Google Cloud documentation](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers#impersonation) if encountering any issues in completing the steps.


Ensure you complete the steps listed by Wilfred van der Deijl with the following differences in mind:

 - For the step involving the creation of a new service account, you should be using previously created non-root service account
   instead of creating a brand new service account

 - You do not need to complete any steps outside of those listed within the `Preparation` section. All steps detailed
   in latter sections will be handled by shell scripts detailed in later sections.


If you have followed the steps as described in the linked gist post, you should now:

 - Have a Workload Identity Pool that utilizes Auth0 as the registered OIDC (OpenID Connect) Identity Provider (IdP)

 - Have the previously created non-root GCP service account to be impersonated having an assigned principal for the
   `Service Token Creator` role that identifies with the external Auth0 API

 - Have a new Auth0 API associated with your original Tenant domain that has the registered Identifier associated with
   the created workload pool (principal for use in service account impersonation). This will produce the OIDC access token
   in the response sent back to the original external requesting authorized host and serve as the authorization endpoint that
   manages access to the Auth0 access token endpoint.

 - Have a new Auth0 Machine-To-Machine Application associated with your original Tenant domain that has registered Client ID
   associated with workload pool and manages the client credentials exchange itself. This will handle forwarding of authorized
   external Auth0 OIDC access token requests to the Auth0 API and serves as OIDC access token endpoint.

While not required, it is recommended to complete the steps listed in the 'Getting a Google token with Auth0 client credentials'
section of the gist post by Wilfred van der Deijl to verify the workload identity pool is correctly setup to use the service account.

**If confident in the creation of the workload identity pool, the last required step is to write the WIF-associated vault secret values**
**to the temporary text file with their appropriately assigned values as follows**:

```bash
PROJECT_NUMBER=your-gcp-project-number # if not already added to the temporary text file yet
WIF_POOL_ID=your-created-workload-identity-pool-id
WIF_PROVIDER_ID=your-created-workload-provider-id-or-name
MTM_CLIENT_ID=your-auth0-machine-to-machine-applications-client-id
MTM_CLIENT_SECRET=your-auth0-machine-to-machine-applications-client-secret

# Substitute in the appropriate values listed above in as the final value
WIF_AUDIENCE=//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/providers/${WIF_PROVIDER_ID}
GCP_SERVICE_ACCOUNT=the-full-email-address-of-the-non-root-gcp-service-account
```


# Setting up GnuPG, SOPS, and HashiCorp Vault for Securely Managing Application Secrets

To bolster application credentials security, the following tools/software are utilized by the application:

1. [GnuPG CLI Tool](https://www.gnupg.org/software/index.html)

2. [Mozilla's SOPS CLI Tool](https://getsops.io/docs/)

3. [HashiCorp Vault](https://developer.hashicorp.com/vault)


**These must be installed and properly setup on your local machine prior to running the application in order to ensure**
**the application operates as intended.**


## Installation and Setup of Required Data Encryption/Decryption Tools 

[PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) (Pretty Good Privacy) is utilized by the application
to encrypt both individual application credential values and files containing them.

[GPG](https://www.gnupg.org/) (GnuPG) is the command line tool utilized by the application to manage any/all local 
PGP encryption keys actively used for data encryption/decryption.

[SOPS](https://getsops.io/)(Secrets OPerationS) is utilized by the application to manage PGP and vault transit encryption/decryption
operations performed by the application through its use as a command line tool.


Both of these must be properly installed and setup in your local machine prior to running the application.


### Configure the GnuPG (GPG) command line tool for local data encryption/decryption using PGP keys

1. Install [GnuPG](https://www.gnupg.org/software/index.html)

```bash
   # Install GnuPG via CLI command
   sudo apt-get install gnupg
```

2. Create two sets of PGP keys (8 in total) using GnuPG, assigning a unique identifier and brief description to each created PGP key

This is intended to mirror the application of 3 separate public-private key pairs associated with 3 different users. The three required unseal keys
are encrypted using a different PGP key that is unique to one of the three users. Only when two of the three decrypted unseal keys are provided to the
intialized vault will the vault be unsealed. For use by one user, three different PGP keys within the same user's keyring are used in instead.

The fourth key is intended to be used to encrypt the initial root token that can used to access the unsealed vault as the root user (admin-level access)

This prevents logging of these key or the root token values as naked plaintext value over STDOUT upon completing the initialization process.
Instead, the base64-encoded PGP-encrypted values are written over STDOUT, requiring access to the private keys of all four PGP keys to gain
full access to the vault data if this output was intercepted.

While not required, it is recommended to generate a second set of four PGP keys that can be used for periodically alternating between

```bash
   gpg --batch --full-generate-key <<EOF
   %no-protection
   Key-Type: 1
   Key-Length: 4096
   Subkey-Type: 1
   Subkey-Length: 4096
   Expire-Date: 0
   Name-Comment: "your-unique-key-comment"
   Name-Real: "your-username-or-full-name"
   EOF
```

3. View and capture the unique fingerprint of each PGP key from your keyring

```bash
   gpg --list-keys
```

4. Export each generated PGP key's public key as a base64-encoded file using each PGP key's unique fingerprint (.b64.gpg)

https://developer.hashicorp.com/vault/docs/concepts/pgp-gpg-keybase#initializing-with-pgp

These will be passed to the vault within the vault initialization command, specifying the relative path to
the public key file of the desired PGP key to encrypt the specified unseal key or vault token value.


```bash
   # Example command for exporting as a base64 encoded file
   gpg --export "<PGP-key1-fingerprint>" | base64 > output-file-with-public-key1.b64.gpg
```


5. Export the public and private pgp keys for later use in SOPS-mediated GPG encryption/decryption operations

In order to use PGP encryption keys within the running application and Docker container it will be running within,
the private and public keys of each PGP encryption key must be exported as seperate files that can then be imported
within the WSGI Flask server container at runtime.

This is absolutely necessary for the main set of PGP keys used to safely inject the decrypted the unseal keys and vault token
values as environment variables to be accessible by the application at runtime.

These files should be directly exported to the `/pgp_config/img_keys` subdirectory that is mounted to the WSGI container
You are free to change this file path but ensure you change the mounted path accordingly if choosing to do so.

The code snippets listed below can be used to complete this process, with each PGP fingerprint placeholder being replaced with the fingerprint
of the desired PGP key generated on your local machine.

```bash
   # Export the public key of the local pgp keypair to be imported by the container for decryption of files encrypted with the pgp key
   gpg --output ./pgp_config/img_keys/pgppkEVK1A.asc --armor --export pgp-fingerprint-for-encrypting-vault-credentials-file

   # Export the private key of the local pgp keypair to be imported by the container for decryption of files encrypted with the pgp key
   gpg --output ./pgp_config/img_keys/pgppkEVK1B.asc --armor --export-secret-keys pgp-fingerprint-for-encrypting-vault-credentials-file

   # Use different PGP keys for each unseal key to be encrypted with using an ordered file naming pattern to avoid confusion
   gpg --output ./pgp_config/img_keys/pgppkSK1A.asc --armor --export pgp-fingerprint-for-encrypting-first-unseal-key
   gpg --output ./pgp_config/img_keys/pgppkSK1B.asc --armor --export-secret-keys pgp-fingerprint-for-encrypting-first-unseal-key

   gpg --output ./pgp_config/img_keys/pgppkSK2A.asc --armor --export pgp-fingerprint-for-encrypting-second-unseal-key
   gpg --output ./pgp_config/img_keys/pgppkSK2B.asc --armor --export-secret-keys pgp-fingerprint-for-encrypting-second-unseal-key

   gpg --output ./pgp_config/img_keys/pgppkSK3A.asc --armor --export pgp-fingerprint-for-encrypting-third-unseal-key
   gpg --output ./pgp_config/img_keys/pgppkSK3B.asc --armor --export-secret-keys pgp-fingerprint-for-encrypting-third-unseal-key

   gpg --output ./pgp_config/img_keys/pgppkRK1A.asc --armor --export pgp-fingerprint-for-encrypting-vault-token
   gpg --output ./pgp_config/img_keys/pgppkRK1B.asc --armor --export-secret-keys pgp-fingerprint-for-encrypting-vault-token

   # Repeat the process with the creation of second alternative set of PGP keys: 
   gpg --output ./pgp_config/img_keys/pgppkAltEVKA.asc --armor --export alt-pgp-fingerprint-for-encrypting-vault-credentials-file
   gpg --output ./pgp_config/img_keys/pgppkAltEVKB.asc --armor --export-secret-keys alt-pgp-fingerprint-for-encrypting-vault-credentials-file

   gpg --output ./pgp_config/img_keys/pgppkAltSK1A.asc --armor --export alt-pgp-fingerprint-for-encrypting-first-unseal-key
   gpg --output ./pgp_config/img_keys/pgppkAltSK1B.asc --armor --export-secret-keys alt-pgp-fingerprint-for-encrypting-first-unseal-key

   gpg --output ./pgp_config/img_keys/pgppkAltSK2A.asc --armor --export alt-pgp-fingerprint-for-encrypting-second-unseal-key
   gpg --output ./pgp_config/img_keys/pgppkAltSK2B.asc --armor --export-secret-keys alt-pgp-fingerprint-for-encrypting-second-unseal-key

   gpg --output ./pgp_config/img_keys/pgppkAltSK3A.asc --armor --export alt-pgp-fingerprint-for-encrypting-third-unseal-key
   gpg --output ./pgp_config/img_keys/pgppkAltSK3B.asc --armor --export-secret-keys alt-pgp-fingerprint-for-encrypting-third-unseal-key

   gpg --output ./pgp_config/img_keys/pgppkAltRK1A.asc --armor --export alt-pgp-fingerprint-for-encrypting-vault-token
   gpg --output ./pgp_config/img_keys/pgppkAltRK1B.asc --armor --export-secret-keys alt-pgp-fingerprint-for-encrypting-vault-token
```

If you view any of the `./scripts/app/start_app.*.template.sh` shell scripts, these files are imported by GPG
before executing the application as a python module as displayed in below example code snippet:

```bash
gpg --import ./pgp_config/img_keys/pgppkEVK1A.asc # PGP Key used to originally encrypt extended vault keys file
gpg --import ./pgp_config/img_keys/pgppkEVK1B.asc
 
gpg --import ./pgp_config/img_keys/pgppkSK1A.asc # PGP Key used to originally encrypt first unseal key
gpg --import ./pgp_config/img_keys/pgppkSK1B.asc

gpg --import ./pgp_config/img_keys/pgppkSK2A.asc # PGP Key used to originally encrypt second unseal key
gpg --import ./pgp_config/img_keys/pgppkSK2B.asc

gpg --import ./pgp_config/img_keys/pgppkSK3A.asc # PGP Key used to originally encrypt third unseal key
gpg --import ./pgp_config/img_keys/pgppkSK3B.asc

gpg --import ./pgp_config/img_keys/pgppkRK1A.asc # PGP Key used to originally encrypt vault token
gpg --import ./pgp_config/img_keys/pgppkRK1B.asc

gpg --import ./pgp_config/img_keys/pgppkAltEVKA.asc # Alternate PGP Key to encrypt extended vault keys file
gpg --import ./pgp_config/img_keys/pgppkAltEVKB.asc

gpg --import ./pgp_config/img_keys/pgppkAltSK1A.asc # Alternate PGP Key to encrypt first unseal key
gpg --import ./pgp_config/img_keys/pgppkAltSK1B.asc

gpg --import ./pgp_config/img_keys/pgppkAltSK2A.asc # Alternate PGP Key to encrypt second unseal key
gpg --import ./pgp_config/img_keys/pgppkAltSK2B.asc

gpg --import ./pgp_config/img_keys/pgppkAltSK3A.asc # Alternate PGP Key to encrypt thrid unseal key
gpg --import ./pgp_config/img_keys/pgppkAltSK3B.asc

gpg --import ./pgp_config/img_keys/pgppkAltRK1A.asc # Alternate PGP Key for encrypting vault token 
gpg --import ./pgp_config/img_keys/pgppkAltRK1B.asc
```


### Configure SOPS for local data encryption/decryption management

In addition to GnuPG, [SOPS](https://getsops.io/docs/) is also required to be locally installed and configured.

In coordination with GnuPG, SOPS enables integration of PGP and other data encryption methods
with a [HashiCorp Vault server](https://developer.hashicorp.com/vault/tutorials/get-started/why-use-vault)
to manage the storage, encryption, and secure access of sensitive application data. 

SOPS can be quickly installed locally by following the steps outlined [here](https://github.com/getsops/sops/releases)

For instance, installing on Linux distributions using AMD64 architecture can be completed by entering the following
sequence of CLI commands into a bash shell terminal:

```bash
   # Download the binary
   curl -LO https://github.com/getsops/sops/releases/download/v3.11.0/sops-v3.11.0.linux.amd64

   # Move the binary in to your PATH
   mv sops-v3.11.0.linux.amd64 /usr/local/bin/sops

   # Make the binary executable
   chmod +x /usr/local/bin/sops

   # Download the checksums file, certificate and signature
   curl -LO https://github.com/getsops/sops/releases/download/v3.11.0/sops-v3.11.0.checksums.txt
   curl -LO https://github.com/getsops/sops/releases/download/v3.11.0/sops-v3.11.0.checksums.pem
   curl -LO https://github.com/getsops/sops/releases/download/v3.11.0/sops-v3.11.0.checksums.sig

   # Verify the checksums file
   cosign verify-blob sops-v3.11.0.checksums.txt \
   --certificate sops-v3.11.0.checksums.pem \
   --signature sops-v3.11.0.checksums.sig \
   --certificate-identity-regexp=https://github.com/getsops \
   --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

Upon completing the installation of SOPS, you should now generate a new SOPS configuration file within the  `sops` directory.

This can quickly completed through the following steps:

1. Locate the `./sops/populate_sops_vars.example.sh` file, rename it to `populate_sops_vars.sh`, and open it.

2. Update the assigned environment variable values for each environment variable described within the table below:

| Variable | Value |
| --- | --- |
| `EXTERNAL_HOST` | External hostname of Nginx reverse-proxy server |
| `EXTERNAL_PORT` | External port number of Nginx reverse-proxy server|
| `PGP_KEY_1_FINGERPRINT` | Fingerprint associated with PGP key #1 (order does not matter as these form an unordered map) |
| `PGP_KEY_2_FINGERPRINT` | Fingerprint associated with PGP key #2 |
| `PGP_KEY_3_FINGERPRINT` | Fingerprint associated with PGP key #3 |
| `PGP_KEY_4_FINGERPRINT` | Fingerprint associated with PGP key #4 |
| `PGP_KEY_5_FINGERPRINT` | Fingerprint associated with PGP key #5 |
| `PGP_KEY_6_FINGERPRINT` | Fingerprint associated with PGP key #6 |
| `SOPS_CONFIG_FILENAME` | Filename of SOPS configuration file (traditional filename is '.sops.yaml'. **Ensure file extension is '.yaml'**) |

> [!NOTE]
> The `destination_rules` rule with the generated SOPS configuration file utilizes the example values provided in the Vault Transit
> and Vault KV Secrets configuration sections. These can be updated with the chosen values afterward.


3. Execute `./sops/populate_sops_vars.sh` to generate a new SOPS configuration file at `./sops/${SOPS_CONFIG_FILENAME}`.
   **This entire filepath should be the assigned value of all `SOPS_CONFIG_FILE` environment variables listed in later sections**

4. Rename the `makefile.example.mk` file to `Makefile` to ensure GNU Make uses this makefile and its predefined rules when calling `make` commands

5. Update the following environment variable definitions within the renamed Makefile to ensure the predefined make rules use the appropriate assigned values

> [!NOTE]
> It is expected that one or more of the variables may appear unclear or confusing at this point of the setup process. This is intended to be referenced
> throughout the setup process so that you may update these values throughout the process.


Flask Server Configuration Variables

| Variable | Value |
| --- | --- |
| `REGION` | Region in which your gcp project is using |
| `PROJECT_ID` | Assigned GCP project ID |
| `REPOSITORY_NAME` | Name of repository to be used for storing pushed Docker images of flask server for use by Google Artifact Registry |
| `APPLICATION_NAME` | Name of application to be used for identifying Docker images of flask server for use by Google Artifact Registry |
| `APPLICATION_VERSION` | Application version used for tagging the image with its corresponding version for use by Google Artifact Registry |
| `APP_PORT` | Port number on which your Flask application server is listening |
| `HOSTNAME` | Internal hostname of Flask service container (defaults to '0.0.0.0') |
| `RUN_SCRIPT` | Path from project root directory to shell script file to launch the Flask service (should be within `./scripts/app/`) |
| `APP_ENV` | Environment configuration to execute the application under (preset to either 'prod', 'dev', or 'deploy' by default) |


Vault Server Configuration Variables
| Variable | Value |
| --- | --- |
| `VAULT_PORT` | Internal port number of Vault service's API node (defaults to 8200) |
| `VAULT_CLUSTER_PORT` | Internal port number of Vault service's cluster node (defaults to 8201) |
| `VAULT_SKIP_VERIFY` | set to false when running full application |
| `VAULT_HOSTNAME` | Internal hostname of Vault service (defaults to 'vault-store') |
| `VAULT_ADDR` | Full internal address of Vault service container (defaults to value constructed from pre-provided default values) |
| `VAULT_ADDRESS` | Full internal address of Vault service container (defaults to value constructed from pre-provided default values) |
| `VAULT_API_ADDR` | Full internal address of Vault service container (defaults to value constructed from pre-provided default values) |
| `VAULT_CERT_FILENAME` | Filename of Vault SSL certificate file |
| `VAULT_CERT_KEY_FILENAME` | Filename of Vault SSL certificate's private key file |
| `VAULT_CREDS_FILENAME` | Filename of SOPS-encrypted Vault credentials env file |


Nginx Server Configuration Variables

| Variable | Value |
| --- | --- |
| `EXTERNAL_PROXY_PORT` | External port number on which Nginx reverse-proxy server is listening on for external requests (defaults to 8800) |
| `INTERNAL_PROXY_PORT` | Internal port number on which Nginx reverse-proxy server is listening on for internal redirection of external requests. **This should ALWAYS BE port 80 by standard HTTP conventions** |


Local User Permissions Configuration Variables

| Variable | Value |
| --- | --- |
| `USER` | Local machine's set username |
| `GROUP` | Local machine's set group name (if exists) or fake user group value (for container file permissions settings) |
| `USER_ID` | Local machine's set ID for the local active user (automatically extracted using shell command) |
| `GROUP_ID` | Local machine's set ID for the local active group (automatically extracted using shell command) |


You may also need to update `VAULT_PORT`, `VAULT_CLUSTER_PORT`, `EXTERNAL_PROXY_PORT`, and/or `INTERNAL_PROXY_PORT` if wishing to use port numbers
other than default assigned port numbers


6. Locate the `./nginx/update_nginx_files.sh` file and open it.

7. Update the assigned port numbers of `APP_PORT` and `VAULT_PORT` to match those assigned within the Makefile

8. Execute the `./nginx/update_nginx_files.sh` file to generate all of the updated Nginx configuration files to be used by the different Docker Compose files


## Configure HashiCorp Vault server for secure external storage of application secrets

A HashiCorp Vault server instance is utilized to securely store and manage sensitive application data, such as authorization/authentication
tokens or various types of credentials. 

1. Install the [free version of Vault](https://developer.hashicorp.com/vault/tutorials/get-started/install-binary) on your local machine using
   the provided link.


2. Ensure the `vault` directory is located within the project root directory and adheres to the following file hierarchy:

```shell
   . --/ (project root directory)
      vault --/
         certs --/
            your-vault-ssl-certificate-filename.pem (created in next section for use in full application configuration)
            your-vault-ssl-certificate-private-key-filename.pem  (created in next section for use in full application configuration)
         config --/
            config.template.hcl
         data --/
         local --/
            certs --/
               your-vault-ssl-certificate-filename.pem (created in next section for use in standalone vault configuration)
               your-vault-ssl-certificate-private-key-filename.pem (created in next section for use in standalone vault configuration)
            config --/
               config.template.hcl
         logs --/ (optional) 
         file --/ (optional)
```

### Generating a Self-Signed Certificate to Enable TLS (non-CA-CERT)

In order to enable use of TLS encrypted connections between the Flask server, Nginx reverse-proxy server,
and the Vault server when locally-hosting the application, a self-signed certicate and key can be provided
in place of an official certificate issued by the Certificate Authority (CA).

This article by Brad Touesnard for a [great overview of SSL certificates](https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/)

1. Generate the Self-Signed Certificate using 4096-bit RSA algorithm encryption to generate X509 certificate
   that can be used for locally hosting the application over HTTPS

```bash
   # Generate a self-signed certificate that should be placed directly within the '/vault/certs' subdirectory
   # This is intended to be used for full application configuration utilized within the 'docker-compose.local.yml' file
   openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
      -nodes -keyout /vault/certs/your-vault-ssl-certificate-filename.pem -out /vault/certs/your-vault-ssl-certificate-private-key-filename.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName1=DNS.1:localhost,DNS.2:vault-store,IP.1:127.0.0.1"

   # Generate a self-signed certificatee that should be placed directly within the '/vault/local/certs' subdirectory
   # This is intended to be used for the standalone vault configuration utilized within the 'docker-compose.vault.yml' file
   openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
   -nodes -keyout /vault/local/certs/your-vault-ssl-certificate-filename.pem -out /vault/local/certs/your-vault-ssl-certificate-private-key-filename.pem \
   -subj "/CN=localhost" \
   -addext "subjectAltName=DNS.1:localhost,DNS.2:vault-store,IP.1:127.0.0.1, IP.2:0.0.0.0"
```

2. Verify your generated certificate file and private key files are placed within the appropriate file directories for different Docker Compose files:

    - Within the `docker-compose.init.yml` file under the `vault-store` service's `volumes` section:

       - The local file path to your self-signed certificate file should be `./vault/local/certs/your-vault-ssl-certificate-filename.pem`
      
       - The local file path to your self-signed certificate's private key file should be `./vault/local/certs/your-vault-ssl-certificate-private-key-filename.pem` 

       - The local file path to your initialized vault's mounted `data` directory should be `./vault/local/data`

       - The local file path to your initialized vault's mounted `config` directory should be `./vault/local/config`


    - Within the `docker-compose.vault.yml` file under the `vault-store` service's `volumes` section:

       - The local file path to your self-signed certificate file should be `./vault/local/certs/your-vault-ssl-certificate-filename.pem`
      
       - The local file path to your self-signed certificate's private key file should be `./vault/local/certs/your-vault-ssl-certificate-private-key-filename.pem`

       - The local file path to your mounted `config` directory should be `./vault/config`


    - Within the `docker-compose.local.yml` under the `vault-store` service's `volumes` section:

       - The local file path to your self-signed certificate file should be `./vault/certs/your-vault-ssl-certificate-filename.pem`

       - The local file path to your self-signed certificate's private key file should be `./vault/certs/your-vault-ssl-certificate-private-key-filename.pem`

       - The local file path to your mounted `config` directory should be `./vault/config`


3. Ensure these paths are also reflected by the vault's defined tsl key and certificate file paths within vault configuration file, `./vault/config/config.hcl`

```py
   # Section of './vault/config/config.hcl' file to verify
   listener "tcp": {
      tls_cert_file = "/certs/your-vault-ssl-certificate-filename.pem"
      tls_key_file  = "/certs/your-vault-ssl-certificate-private-key-filename.pem"
      ...
   }
```


### Initializing the HashiCorp Vault Server

While the application is primarily intended to communicate to a containerized HashiCorp Vault instance over an internalized network,
**running the Hashicrop Vault instance within a Docker container prevents the importing of local encoded PGP public key files into the**
**container directly.**

In order to intialize the Vault instance so that it provides the unseal key and root token values in their PGP-encrypted form,
the Vault instance needs to be run within a local shell outside a container during the intialization process.

This will allow the Vault instance to access the intended local PGP encryption key files and apply the respective encryption(s) to each unseal key
and/or root token.


To better streamline this process, a series of provided shell scripts can be executed to complete this process in a secure manner.


1. Ensure you have activated your virtual environment.


2. Locate the `populate_init_vars.example.sh` shell script within the `scripts/initialize` directory, rename it to `populate_init_vars.sh`, then open it.


3. Within: `./scripts/initialize/populate_init_vars.sh`, update the assigned value for each of the exported environment variables
   located at the top of the script file. A brief description of each environment variable is outlined below:

Vault Configuration Variables

| Variable | Value |
| --- | --- |
| `VAULT_PORT` | Port number on which Vault server is listening (defaults to 8200) |
| `VAULT_CLUSTER_PORT` | Port number on which Vault cluster is listening (defaults to 8100) |
| `VAULT_HOSTNAME` | Host Address on which Vault server is listening (defaults to localhost) |
| `VAULT_CLUSTER_ADDR` | Full address of runnin Vault server cluster (defaults to https://your-vault-hostname:your-vault-cluster-port-number) |
| `VAULT_ADDR` | Full address of running Vault server node (defaults to https://your-vault-hostname:your-vault-port-number) |
| `VAULT_SKIP_VERIFY` | Set to true when running initialization process, otherwise ensure this is set to false after initialization (prevent MIM attacks) |
| `VAULT_TEXT_FILE` | Path from project root directory to text file containing the provided encrypted plaintext values of the unseal keys and root user token |
| `VAULT_JSON_FILE` | Path from project root directory to JSON file containing temporarily store the JSON objects holding the encrypted plaintext vault keys/tokens |
| `VAULT_ENV_FILE` |  Path from project root directory to env file containing SOPS-encrypted unseal keys and root user token values |
| `VAULT_CERT_FILENAME` | Filename of generated self-signed Vault SSL certificate |
| `VAULT_CERT_KEY_FILENAME` | Filename of generated self-signed Vault SSL certificate's private key |


> [!IMPORTANT]
> Ensure you have `VAULT_SKIP_VERIFY` explicitly set to `true` when initializing the Vault and completing its preliminary setup (Steps 1-15 of this section).
> This is due to the need to either open a shell directly within the running Vault container or running the Vault server as a local process (instead of within
> an internally networked container). In both of these situations, the SSL verification process will be unable to properly certify the SSL certificates so this
> must be disabled for these operations.
> However, after completion of these steps, all future use of Vault will be executed using `make run-vault-service` or `make run-local-app-services`, which
> will set `VAULT_SKIP_VERIFY` set to `false` and properly enforces SSL certificate verification. If this fails, ensure you have properly configured
> your SSL certificate paths and properly set the address extensions when creating the certificate and private key files.


SOPS Configuration Variables

| Variable | Value |
| --- | --- |
| `TMP_FILE` | Asigned name for temporary file (introduces additional randomness to naming of temporary file used in env values during reencryption operations) |
| `SOPS_CONFIG_FILE` | Path from project root directory to desired sops configuration file  |

PGP Encryption Configuration Variables

| Variable | Value |
| --- | --- |
| `PGP_KEY_1_FILE` | Path from project root directory to binary or base64 encoded pgp key for encrypting first vault unseal key |
| `PGP_KEY_2_FILE` | Path from project root directory to binary or base64 encoded pgp key for encrypting second vault unseal key |
| `PGP_KEY_3_FILE` | Path from project root directory to binary or base64 encoded pgp key for encrypting third vault unseal key |
| `PGP_KEY_4_FILE` | Path from project root directory to binary or base64 encoded pgp key for encrypting initial root token |

| `ENV_ENC_FINGERPRINT` | Fingerprint of PGP key to be used for encryption of env file containing SOPS-encrypted unseal keys and root user token values |


Ensure each of these are satisfactorily assigned an appropriate value before proceeding further.
If unsure about the application of the PGP key files see the Vault documentation describing this [process](#installconfigure-gnupg-gpg-for-data-encryptiondecryption-using-pgp-keys)


4. Execute `./scripts/initialize/populate_init_vars.sh` to generate the following script files with the assigned environment variables now properly
   defined throughout these files:

    - `./scripts/initialize/initialize_vault.sh`

    - `./scripts/initialize/startup_vault.sh`

    - `./vault/local/config/config.start.sh`

    - `./vault/local/config/config.init.sh`


   Anytime you wish to change one or more environment variable values simply repeat steps 3 and 4 to automatically update the scripts with the new values.

> [!NOTE]
> These scripts are intended to operate within a bash shell by default. The shebang of these files may need to be changed depending on your OS
> This will use the pre-provided config file and integrated backend storage to enable persistent data storage on your local machine.
> If the vault initialization process fails, please refer to the official [documentation](https://developer.hashicorp.com/vault/tutorials/get-started/setup)
> to ensure you have properly completed the Vault setup and initialization process.


5. Execute the `./scripts/initialize/vault_startup.sh` shell script to startup the Vault Server within a local shell on your machine.

```bash
   # For example, on most Linux distributions this can be executed from the project root directory using the command:
   bash ./scripts/initialize/vault_startup.sh # Startup the vault server at https://localhost:${VAULT_PORT}
```

6. Open a separate shell terminal and ensure the the vault server is still streaming log data to the the first terminal.


> [!IMPORTANT]
> Before proceeding to Step 7, ensure you have completed the setup of GnuPG and SOPS detailed within the 
> [GnuPG setup section](#installconfigure-gnupg-gpg-for-data-encryptiondecryption-using-pgp-keys) and
> [SOPS setup section](#installconfigure-sops-for-data-encryptiondecryption-management)!
> **Executing `initialize_vault.sh`, before properly completing steps outlined in the listed previous section**
> **may result in improper parsing and/or encryption of the unseal keys and root token required to access the vault**
> If this happens, you will need to delete any files within the `/vault/data` directory and then restart the vault initialization process.


7. Execute the `./scripts/initialize/initialize_vault.sh` shell script to:
   
    - Intialize the vault

    - Write the entire provided vault initialization response (including the encrypted unseal keys and root token) to the file defined by `VAULT_TEXT_FILE`

    - Extract the three PGP-encrypted unseal key and root token values from `VAULT_TEXT_FILE` and perform isolated decryption/reencrpytion
      of these values to generate a new PGP-encrypted environment file, `VAULT_ENV_FILE` with metadata that allows SOPS to securely extract
      the decrypted values whenever the vault needs to be unsealed.


8. After confirming the `initialize_vault.sh` has successfully finished its execution, ensure the file `VAULT_ENV_FILE` now exists
   and has been reencrypted by SOPS, which will have file data written to the file.


9. Shutdown the locally running instance of the Vault server by entering `Ctrl-C` or the appropriate key binding for sending the `SIGINT` signal
   to the running process within the terminal.   

10. Ensure Docker Engine is running (should automatically start when first opening Docker Desktop application)

11. Build and run the Docker Vault server image within a new container with locally mounted volumes corresponding to those used for integrated storage
    by the previous initialized Vault instance (different pathing configuration but accesses same data as initialized vault server).
   
    To do this, enter the predefined Make command `make run-initial-vault-service` into the terminal.
    This will also build and run a Nginx reverse-proxy server within a separate container over the same internal network to enable external access to the
    Vault container over HTTPS. Ensure startup of both containers is completed successfully before proceeding. Any errors encountered by either service
    during their intial startup should be printed to the terminal.


12. Open a second terminal, ***(do not close and kill the running process in the first)***, and execute a new shell within the running
    Vault container by entering the following command into the second terminal:

   `docker exec -it vault-store /bin/sh`


13. Open a third terminal ***(do not close or kill the running processes in either the first or the second terminals)***, and enter the command listed
    below to spawn a new child process within which the decrypted unseal keys and root tokens can be securely accessed as environment variables using SOPS
    (this is made possible due to the metadata written to the SOPS encrypted file `VAULT_ENV_FILE` generated in step 3).

    `sops -config $SOPS_CONFIG_FILE exec-env $VAULT_ENV_FILE /bin/sh`

    You should now be able to print the decrypted value of any environment variable defined in `VAULT_ENV_FILE` directly into the console
    without having to decrypt the file itself (i.e. `echo $UNSEAL_KEY_1` -> `<decrypted value corresponding to the actual value of vault's unseal key 1>`).

    These decrypted values can only be accessed within this specific shell environment/process and will be unaccessible after this process is 
    terminated via the `exit` command.


14. Within the second terminal (the shell process running directly within the running Vault container instance), enter `vault operator unseal`
    to trigger a prompt to enter one of two decrypted unseal key values required to unseal the vault server.  
    Copy two of the three decrypted unseal key values from the third terminal and enter them into the second terminal to complete the unsealng
    process.


15. You may enter `vault status` into the second terminal to verify each unseal key was approved or rejected by the vault server with the displayed
    `sealed` status changing from `true` to `false` upon successful unsealing of the vault.


16. Upon successful unsealing of the vault, enter `vault login` into the second terminal to be prompted for the decrypted initial root token required
    to gain access to the vault's stored contents. After providing the decrypted root token value, a message notifying successful authentication should
    now be displayed along with the token's associated user information and associated vault policies ("root")

    If login fails, ensure the `VAULT_ADDR` value within the terminal matches that assigned to `VAULT_ADDR` in the `intialize_vault.sh` script and 
    the `VAULT_SKIP_VERIFY` is set to true both within the terminal and the `docker-compose.vault.yml` file.

> [!IMPORTANT]
> **SERVER SHUTDOWN AND CLEANUP PROCEDURE**
> Whenever wishing to safely end the current vault session, you can do so by first closing the shell session within the running vault instance by
> entering `pkill vault` into the shell terminal (shell being used to unseal and login to vault server). Within the same terminal and any other terminals
> used to access the vault, unset the `VAULT_ADDR`, `VAULT_SKIP_VERIFY`, and if utilized, `VAULT_TOKEN` variables and then enter `exit` to kill the running
> shell process. If running the application servers within container instances, shutdown these services by entering `Ctrl-C` into the terminal used to execute the services.


Upon completing the initialization of the vault server, you can now exclusively interact with the intialized vault service from within
the Docker containerized service via the Vault UI over the browser client or from within a executed shell within the running vault service's Docker container

In order to provide more secure control over the vault service's initial user configuration and policy setup, this process is
covered utilizing the Vault CLI exclusively.


### Adding A New User and a New Policy with Scoped Permissions

It is strongly recommended to create a new user whose access to the Vault server is explicitly defined
by a custom-built Vault ACL (access control list) policy that is then associated with the created user.
This limits the user's access and allowed capabilities to only those outlined in the ACL policy.


1. To begin, login to a local running container instance of the unsealed Vault server as the root user.


2. First, a new user authentication method must be defined in order for the Vault to issue a fine-grained
   access token to the user upon successful authentication with the Vault server.

In this case, the `userpass` method is utilized which requires submission of a username and password
for user login/authentication with the Vault server:

   ```bash
      # Create new username and password authorization method to authenticate to Vault server and
      # later extract a secret value

      vault auth enable userpass

      # Userpass method will be now created within the Vault path of `/auth/userpass`
   ```

> [!NOTE]
> When enabling new paths to new resources, such as secrets or transit, you must be logged in as root user


3. Next, enable several resource paths for use by new user including:

    - A resource path to key:value pairs of secrets associated with application authorization/authentication credentials
      utilizing the Vault secrets engine's `kv` (key/value)
      
    - A resource path to the Vault secrets engine's `transit` used for encrypting in-transit data using SOPS encryption tool

      ```bash
         # Login as root user to have sufficient permissions to create both secret resources
         vault login

         # Enable new instance of version 2 key/value secrets engine which is vault's secrets engine to enable policy output
         # at the specified path of `dev-secrets`
         vault secrets enable -path=dev-secrets -version=2 kv

         # Now, create a new transit engine for use by sops at path `sops/`
         vault secrets enable -path=sops transit
      ```

3. Next, generate the new user's ACL policy for access to secrets files at a specified path using the
   username password (userpass) credentials authorization
   
   Within the Vault server, policies dictate user capabilities and access to any specific Vault resources by addressing
   the path to the specific Vault resource and defining the permitted capabilities for this user.

   While the paths can and probably should be updated to match the desired naming for each resource path, the following can
   be used to create an ACL policy for the user intended to access resources associated with three different encryption keys and
   secret key:value pairs utilized by the application for authorization/authentication purposes.

```bash
# Create a new ACL (access control list) policy for path "dev-secrets/+/creds" and "sops/keys" (+ = any)

vault policy write dev-secrets-vault-policy - << EOF

path "sops/keys/crypt-key1" {
   capabilities = ["create", "read"]
}

path "sops/keys/crypt-key2" {
   capabilities = ["create", "read"]
}

path "sops/keys/crypt-key3" {
   capabilities = ["create", "read"]
}

path "sops/encrypt/crypt-key2" {
   capabilities = ["create", "update", "read"]
}

path "sops/encrypt/crypt-key1" {
   capabilities = ["create", "update", "read"]
}

path "sops/encrypt/crypt-key3" {
   capabilities = ["create", "update", "read"]
} 

path "sops/decrypt/crypt-key1" {
   capabilities = ["create", "update", "read"]
}

path "sops/decrypt/crypt-key2" {
   capabilities = ["create", "update", "read"]
}

path "sops/decrypt/crypt-key3" {
   capabilities = ["create", "update", "read"]
}

path "dev-secrets/+/creds" {
   capabilities = ["create", "list", "read", "update"]
}
EOF
```

4. To finish the user creation process, define the user with a username, a password value, and add the created ACL policy to the
   user's assigned policies

```bash
   # Apply created policy for updated access to new user with username of 'your-vault-username' and password of 'your-password' as credentials for
   # vault authentication using the userpass auth method (user authentication required for policy access)
   vault write /auth/userpass/users/your-vault-username password='your-password' policies=dev-secrets-vault-policy
```

5. Authenticate with Vault server as new user using defined username and password. After successful login, the user
   token data, policies, and username data should be displayed.

```bash
   # Login using username/password credentials in place of root token to limit access to specified Vault resources

   vault login -method=userpass username=your-vault-username

   # Can also provide password in login request to remove required entry of password

   vault login -no-print -method=userpass username=your-vault-username password='your-password'

   # Now root token is no longer used by default in login requests, limiting permissions scope of utilized access token
```

This user can now be used in all future logins to directly limit resource access to those being used by the user
and preventing access to all other vault resources.


### Generating Secrets for storing Application Credentials

***It is now time to finally use all of those key value pairs you've writing to that temporary text file! (And then promptly delete it)***

Use Vault Secrets key/value engine `kv` to generate and store key:value pairs that can be utilized in same manner as environment variables

```bash
   ## Create secrets in the secrets engine at the policy path using logged in user with ACL read/write permissions policy

   # Add key=value pairs to enabled KV secrets path of 'dev-secrets' but ensure all keys you wish to add are done in single entry (see NOTE).
   # NOTE: YOU MUST ADD ALL KEYS YOU WISH TO STORE WHEN USING 'PUT'. ANY KEYS ADDED IN PREVIOUS VERSION THAT ARE NOT INCLUDED IN KEYS
   #       OF NEXT VERSION WILL BE DELETED/REMOVED UPON SUBMITTING 'PUT'. TLDR: DOES NOT APPEND NEW KEYS, SIMPLY REPLACES THEM

   # Use these key names for your assigned value as these will be used to access the secret values from Vault by the Flask application at runtime
   vault kv put /dev-secrets/creds DOMAIN=auth0-app-domain CLIENT_ID=auth0-app-client-id \
      CLIENT_SECRET=auth0-app-client-secret AUTH_MANAGEMENT_API_ID=auth0-management-api-identifier \
      ADMIN_ROLE_ID=auth0-admin-role-id INSTRUCTOR_ROLE_ID=auth0-instructor-role-id \
      INSTANCE_CONNECTION_NAME=gcp-project-id:gcp-project-region:gcp-mysql-database-instance-id DB_NAME=gcp-mysql-database-name \
      DB_USER=gcp-mysql-database-user-name DB_PASS=gcp-mysql-database-user-password PROJECT_ID=gcp-project-id \
      AVATAR_BUCKET_NAME=gcp-cloud-storage-bucket-name PROJECT_NUMBER=gcp-project-number WIF_POOL_ID=workload-identity-pool-id \
      WIF_PROVIDER_ID=workload-identity-provider-id MTM_CLIENT_ID=auth0-machine-to-machine-app-client-id \
      MTM_CLIENT_SECRET=auth0-machine-to-machine-app-client-secret \
      WIF_AUDIENCE=auth0-api-identifier GCP_SERVICE_ACCOUNT=gcp-service-account-email-to-be-used \
      GCP_SERVICE_ACCOUNT=gcp-service-account-email-to-impersonate \
      DEFAULT_ADMIN_USERNAME=email-of-default-admin-user-for-auth0-app DEFAULT_ADMIN_PASS=password-of-default-admin-for-auth0-app \
      AUTH_DB_CONNECTION=name-of-auth0-managed-database-for-holding-registered-users

   # Retrieve the all key/value pairs existing in dev-secrets secret using the get command
   vault kv get dev-secrets/creds
```

> [!IMPORTANT]
> The list of key/values are the sum total of ALL of key/value secrets utilized by the application. Do not attempt to fill these values now.
> Each of these key/value pairs will be explained in further detail in later sections. However, this can be utilized as a template when
> reassigned or replacing the entire set of K/Vs as may be required during later process steps.


### Intializing Vault Transit Secrets Engine for encrypting in-transit data using SOPS encryption tool (Optional)

The Vault [Secrets Transit Engine](https://developer.hashicorp.com/vault/docs/secrets/transit) can be used to encrypt transmitted data using generated encryption keys.

> [!IMPORTANT]
> **The use of the Vault Secrets Transit Engine for data encryption is not used as the primary means of transit/rest or runtime data encryption.**
> **Instead, it provides a suite of built-in methods that server as available alternatives to the use of locally generated PGP encryption keys that**
> **the application is preconfigured to use by default. Its use is supported but purely optional so you may skip this section if you wish to do so.**


For additional understanding of possible applications of the Vault Transit, view [the official Vault Documentation](https://simplico.net/2024/10/23/securing-django-applications-with-hashicorp-vault-hvac-concepts-and-practical-examples/).

In concert with SOPS, this can be used to encrypt and decrypt sensitive application data imported from external storage source's that may be
printed over publicly visible elements. This is ideal for encrypting user credentials before saving them to an external database using the Vault's
transit encryption keys and then using the same encryption key to decrypt it when needing to be displayed to the user.

SOPS can be reconfigured to use a specified vault transit key when provided and the `utils/vault_utils.py` file includes functions that can be called
to perform runtime encryption/decryption operations with a specified transit secret encryption key.

To configure SOPS to utilize an encryption key housed within Vault server:

1. Ensure all containerized services are running and login as the **root** user within a new shell within the Vault container

2. Within the shell executed within the Vault container that is now authenticated as the **root user**, create three new 4096-bit RSA encrpytion keys
   within the `sops` transit secret with the path of `sops/keys/crypt-key1`, `sops/keys/crypt-key2`, and `sops/keys/crypt-key3`

```bash
   # Ensure you are logged in as the root user as non-root user has permission to read the encryption keys created within the sops transit secret
   # but NOT actually create the keys themselves

   # OPTIONAL: For editing or creating new files to encrypt using SOPS you can assign the text editor using `EDITOR` variable
   export EDITOR=code --wait # for enabling use of primary text editor as VSCODE

   # Create three new encyption key within SOPS-specific transit engine for use by SOPS
   vault write sops/keys/crypt-key1 type=rsa-4096
   vault write sops/keys/crypt-key2 type=rsa-4096
   vault write sops/keys/crypt-key3 type=rsa-4096

   # Login as authenticated non-root user to confirm user has read access to the encryption keys as this will be necessary
   # for enacting file encryption/decryption using SOPS as a non-root user
   vault read sops/keys/crypt-key1
   vault read sops/keys/crypt-key2
   vault read sops/keys/crypt-key3
```

3. Check the defined paths within the SOPS configuration file `./sops/.sops.yaml` to verify the proper URL path to the
   created encryption keys are properly declared for the encryption keys now generated within the Vault
   sops transit secret. These can be tested to ensure these are properly configured by SOPS.

4. To ensure each of three encryption keys held within the Vault servers `sops` transit secret are accessible to the non-root user,
   you can enter the following set of commands to generate an environment file to test encryption/decryption using each encryption key:

```bash
# Securely pass the decrypted environment variables of the .extended-vault-keys.enc.env` file within a new shell process
sops exec-env $EXTENDED_VAULT_ENV_FILE 'bin/sh'

# Export all environment variables with appropriate values required for authenticating to the running Vault server
export VAULT_TOKEN=$USER_TOKEN # Decrypted non-root user token value

export VAULT_ADDR="http://your-domain:your-port" # External address on which Nginx reverse-proxy is listening (redirects to Vault over HTTPS)

export VAULT_SKIP_VERIFY=your-skip-verify-value # False if you can point to the CA_CERT_BUNDLE, else use true if unable to properly authenticate

# Generate an env file with generic env variables to encrypt using SOPS and selective in-place encryption/decryption
cat > myEnvFile.env << EOF
USER_PRIVATE_KEY=MyLittleSecretPrivateKey
USER_PUBLIC_KEY=MyLittleSecretPublicKey
USER_NAME=MyNameIS
USER_PASS=LetMeGuess
EOF

# Test that file uses all default encryption key(s) associated with file's path regex (any env/json/yaml file)
sops encrypt cryptKey1.env --in-place

# Test that file uses encryption key 'crypt-key1' when addressed by its URI using SOPS 
sops encrypt --hc-vault-transit $VAULT_ADDR/v1/sops/keys/crypt-key1 myEnvFile.env --in-place
sops decrypt myEnvFile.env --in-place

# Test that file uses encryption key 'crypt-key2' when addressed by its URI using SOPS
sops encrypt --hc-vault-transit $VAULT_ADDR/v1/sops/keys/crypt-key2 myEnvFile.env --in-place
sops decrypt myEnvFile.env --in-place

# Test that file uses encryption key 'crypt-key3' when addressed by its URI using SOPS
sops encrypt --hc-vault-transit $VAULT_ADDR/v1/sops/keys/crypt-key3 myEnvFile.env --in-place
sops decrypt myEnvFile.env --in-place

# Ensure you terminate the running shell process to ensure all exported variables are erased
exit
```

> [!NOTE]
> Unsetting the exported variables within the shell process before exiting the shell above is considered optional.
> The shell environment opened using SOPS is isolated from other processes and so any exported environment variables
> will not be written to disk nor be reachable by any other process, including the parent process.


### Securely Updating the Encrypted Vault Credentials File (Replacement of Root User Token with Non-Root User Token)

Retaining an active root token value, encrypted or not, serves a potential security liability if accidentally exposed.
It is best to instead replace this token value with the non-root user token for all future authentication with the vault
server to mitigate risk of bad actors gaining root access to the vault server.

1. Relogin as non-root user and copy the plaintext non-root user token displayed under the user's metadata upon successful
   authentication with the vault server.

```bash
   # Login with username and password credentials for non-root user without using '-no-print' flag to print the user's metadata
   # including the non-root user's vault-issued access token
   vault login -method=userpass username=your-non-root-user-username password='YournonrootuserPassword'
   # OR
   vault login -> Enter non-root user token directly
```

2. Locate the `./scripts/update/populate_update_vars.example.sh` script, rename it to `populate_update_vars.sh`,
   update the assigned environment variable values, and then execute it in order to generate a new script file `./scripts/update/update_user_settings.sh`
   that is prepopulated with the updated values for each environment variable. A general description of the required environment variables is provided below:

| Variable |  Purpose |
| --- | --- |
| `VAULT_ADDR` | IP/Domain Address and Port Number of running Vault server (this will be the external address and port of the Nginx reverse-proxy server) |
| `VAULT_SKIP_VERIFY` | Set to true when running initialization process, otherwise ensure this is set to false after initialization (prevent MIM attacks) |
| `ORIGINAL_VAULT_ENV_FILE` |  Path from project root directory to env file containing SOPS-encrypted unseal keys and root user token values |
| `EXTENDED_VAULT_ENV_FILE` | Path from project root directory to env file containing SOPS-encrypted unseal keys, root user token, AND non-root user token values |
| `EXTENDED_ENV_ENC_FINGERPRINT` | Fingerprint of PGP key to be used for encryption of env file now updated with additional value of non-root user token value |


3. Manually copy the decrypted non-root user token value and replace its placeholder within the now generated `./scripts/update/update_user_settings.sh`
   script.

   Manual replacement of the non-root user token placeholder value (instead of direct substitution), mitigates its potential exposure during the process of exporting it to the new shell process.

```bash
   # Within the './scripts/update/update_tokens.sh' file, replace 'your-non-root-users-token' with your non root user token
   echo 'USER_TOKEN=your-non-root-users-token' >> $TMPFILE
```


4. Execute the `./scripts/update/update_user_settings.sh` script to generate an updated environment file, `EXTENDED_VAULT_ENV_FILE`,
   which now contains the encrypted user token value assigned to the `USER_TOKEN` environment variable as well as the encrypted root token and unseal keys,
   under their same environment variable names.

```bash
   # Example execution from project root directory using bash
   bash ./scripts/update/update_user_settings.sh
```

   The generated environment file `EXTENDED_VAULT_ENV_FILE` will now contain the encrypted user token value assigned to the `USER_TOKEN` environment variable.
   This file will also contain the encrypted root token and unseal keys, utilizing the same environment variable names as before. This file can now be passed to
   a separate shell process using SOPS to safely extract the decrypted value of any desired environment variable for use in unsealing or authenticating with the Vault server. 


### Setting up Automated Management of Application Credentials

While utilization of data encryption tools provides a crucial layer of protection against accidental leaking of sensitive data,
it is also equally important to:

1. Avoid keeping an active root vault token, generating a root token only when required and then immediately revoking it once it is
   no longer required.

2. Regularly rotate authentication credentials to combat possibility of compromised data providing access to the vault or the application.

3. When externally hosting the application (deployed application), utilize the hosting cloud platform's specialized secrets manager to inject
   the required authentication credentials as environment variable secrets at runtime.

While it is possible to complete these tasks manually, several shell scripts have been provided that can be executed on your
local machine to automatically handle the completion of these tasks. However, this requires some initial changes to be made to one
or more of the application files in order for these scripts to complete their tasks properly.


#### Revoking Initial Root User Token (in favor of as-needed root token issuance)

Once you are satisfied that you have completed vault configuration and have confirmed your non-root user token can complete the required
tasks without requiring the use of the root token, it is recommended to revoke your initially issued root token.

As long as your non-root user's token has been granted sufficient permissions to sufficiently access the secrets required by the application,
this root token is no longer necessary and only serves as a potential security risk if accidentally exposed.

Utilizing the vault CLI commands or the appropriate REST API endpoints, a new temporary root token can be generated when needed, by providing the
decrypted/decoded unseal key shards and encryption method (PGP key or OTP) to be applied to the new root token before providing it the user.


> [!TIP]
> The application includes the `utils/vc_utils.py` python module that provides various functions for interacting with the vault via the
> [Python client for HashiCorp Vault (HVAC)](https://python-hvac.org/en/stable/overview.html), including generation of a root token when required and
> automatically revoking it upon completion of the task.
>
> Additionally, the appropriate shell scripts that requires this functionality will ensure the generated root token only exists in memory, is never
> written to the disk and is automatically revoked upon finishing execution.
>
> Visit the following links if wishing to know more:
> [Generating a New Vault Root Token using Vault CLI](https://developer.hashicorp.com/vault/docs/commands/operator/generate-root) 
> [Troubleshooting Vault Root Token Regeneration](https://developer.hashicorp.com/vault/docs/troubleshoot/generate-root-token)


The following code snippet provided below is an example of how to revoke the initial root token via the standalone vault configuration
and the vault CLI:

```bash
   # Startup standalone vault instance configured via appropriate Docker Compose file
   make run-vault-service

   # Execute bash script that unseals the running the vault instance using SOPS-facilitated injection of encrypted file contents into an isolated process
   # These will only exist within memory and are inaccessible outside this shell's process
   bash ./scripts/vault/unseal_vault.sh

   # Open a new terminal and inject decrypted vault credentials as environment variables with a separate shell process
   sops -config $SOPS_CONFIG_FILE exec-env $EXTENDED_VAULT_ENV_FILE /bin/bash

   # Capture the decrypted output of the initial vault root token (shell log history is cleared upon exiting shell process)
   echo $INTIAL_ROOT_TOKEN

   # Open a third terminal and exec into the running vault service
   docker exec -it vault-store /bin/sh

   # Within the third terminal, login using the root token
   vault login $INITIAL_ROOT_TOKEN # standin for actual value

   # Complete the root-required task within the running vault instance

   # When finished completing the root required task, revoke the token while logged in as the root user (Self)
   vault token revoke -self

   # Attempting to relogin as root user using revoked token should now fail with 403 response
   vault login $INITIAL_ROOT_TOKEN
```

It is not necessary to delete the `INIIAL_ROOT_TOKEN` env variable from your file unless you wish to decrypt and reencrypt its contents into a new file.
Directly deleting it from the file while it is encrypted will generate SOPS errors when using the file after its alteration otherwise.

This will be be automatically removed by scripts utilized in later sections so attempting to manually remove this value is unnecessary.


#### Updating Scripts for Automating Rotation of Application Credentials

While there are many services available for automatically managing both vault and Google Cloud credentials, including their rotation, many
of these services are either considered incompatible with the scope of this application, or require a paid monthly subscription.

As one of the main goals of this application was for it to be utilized without requiring any outright monetary investment, several shell scripts
were created to handle this process when executed locally.

After updating each of the assigned placeholder values for the key environment variables required by the shell scripts, calling the appropriate script
will securely perform the intended credential rotation process.

- The `./scripts/rotate/rotate_vault_credentials.sh` shell script will automate the rotation of the vault's current unseal keys and
  the current vault token being used to authenticate to the vault.


- The `./scripts/rotate/rotate_app_credentials.sh` shell script will automate the rotation of the WSGI Flask application's session secret
  key and the short-lived Google OAuth2.0 access token for authenticating to Google Cloud API services (impersonates an authorized Google
  Cloud Platform service account with a Workload Federated Identity (WIF)).

- Remember the mentioning of the required use of Google Cloud's Secret Manager in earlier sections? If so, you must be wondering when
  its setup process would be described. Well, it starts and ends with the execution of the `./scripts/rotate/update_gcp_secrets.sh` script (assuming
  you enabled the `Secret Manager API` and assigned the specified roles to the non-root GCP service account). When the `update_gcp_secrets.sh`
  script is executed, it will gather all of the Vault service's KV secrets and create/update the corresponding KV secrets within GCP's
  equivalent service, `Secret Manager`. GCP's `Secret Manager` API service will effectively replace the functions of the HashiCorp Vault service
  when the application is being externally hosted by GCP's Cloud Run API service.


It is recommended to call these scripts immediately before restarting the application. **By default, the**
**generated Google OAuth2.0 access token has a set time-to-live of one hour, so you will need to call the `./scripts/rotate/rotate_app_credentials.sh`**
**shell script if the app has not been restarted after over one hour from the last time the access token was issued.**


The table below provides a brief description of all environment variables that must be manually updated for all three shell scripts to be executed:

Vault Configuration Variables

| Variable |  Value |
| --- | --- |
| `VAULT_ADDR` | The internal host address and port number of the running vault server container (i.e. https://0.0.0.0:your-vault-port-number) |
| `VAULT_PROXY_ADDR` | The external host address and port number of the Nginx reverse-proxy server (i.e. http://127.0.0.1:your-port-number) |
| `VAULT_SKIP_VERIFY` | Set to true when running initialization process, otherwise ensure this is set to false after initialization (prevent MIM attacks) |
| `VAULT_CERT_PATH`| Path from project root directory to SSL certificate for standalone vault configuration (i.e. ./vault/local/certs/your-vault-cert-filename) |
| `VAULT_CERT_KEY_PATH` | Path from project root directory to SSL private key for standalone vault configuration (i.e. ./vault/local/certs/vault-key-filename) |
| `GPG_HOME` | Path from project root directory to local machine's GnuPG directory (i.e. default for Linux OS: ~/.gnupg) |

PGP Encryption Variables

> [!NOTE]
> For examples of how to properly provide 'raw' base64-encoded values for the PGP public keys listed below, 
> view the example code provided in step #2 listed below

| Variable |  Value |
| --- | --- |
| `UNSEAL_CRYPT_KEY1` | Raw base64-encoded public key of PGP encryption key for original encryption of first unseal key |
| `UNSEAL_CRYPT_KEY2` | Raw base64-encoded public key of PGP encryption key for original encryption of second unseal key |
| `UNSEAL_CRYPT_KEY3` | Raw base64-encoded public key of PGP encryption key for original encryption of third unseal key |
| `TOKEN_CRYPT_KEY` | Raw base64-encoded public key of PGP encryption key for original encryption of vault token |
| `ALT_UNSEAL_CRYPT_KEY1` | Raw base64-encoded public key of PGP encryption key for alternate encryption of first unseal key |
| `ALT_UNSEAL_CRYPT_KEY2` | Raw base64-encoded public key of PGP encryption key for alternate encryption of second unseal key |
| `ALT_UNSEAL_CRYPT_KEY3` | Raw base64-encoded public key of PGP encryption key for alternate encryption of third unseal key |
| `ALT_TOKEN_CRYPT_KEY` | Raw base64-encoded public key of PGP encryption key for alternate encryption of vault token |
| `PGP_FINGERPRINT` | Fingerprint of PGP encryption key to be used for reencrypting the main vault credentials file |

Vault KV Secrets Variables

| Variable |  Value |
| --- | --- |
| `SECRET_MOUNT_PATH` | Mounted path used by enabled vault KV secret containing desired k/v secrets to be accessed |
| `SECRET_PATH` | Internal path to k/v secret containing desired map of k/v secret values to be accessed |


Vault Transit Secrets Variables

| Variable |  Value |
| --- | --- |
| `TRANSIT_MOUNT_PATH` |  Mounted path used by enabled vault transit secret containing SOPS encryption keys to be used for runtime encryption/decryption |
| `TRANSIT_PATH` | Internal path to transit secret containing SOPS encryption keys from the mounted path |


Global File Variables

| Variable |  Value |
| --- | --- |
| `ORIGINAL_ENV_FILE` | Path from project root directory to env file containing SOPS-encrypted unseal keys and non-root user token values |
| `SOPS_CONFIG_FILE` | Path from project root directory to sops.yaml configuration file to be used by SOPS for encryption (default is `./sops/.sops.yaml`) |


Temporary File Variables specific to `rotate_vault_credentials.sh` script

| Variable | Value |
| --- | --- |
| `TEMP_TEXT_FILE` | Path from project root directory to temporary .txt file holding initially returned base64-encoded and PGP-encrypted plaintext new unseal key, non-root vault user token, and userpass credentials values (can be any valid path)  |
| `TEMP_ENV_FILE` | Path from project root directory to temporary SOPS-encrypted .env file holding the new unseal key, non-root vault user token, and userpass credentials values (can be any valid path) |
| `VAULT_JSON_FILE` | Path from project root directory to temporary JSON file containing the parsed base64-encoded and PGP-encrypted plaintext values of newly returned unseal keys, non-root vault user token, and userpass credentials as JSON objects (can be any valid path) |


Userpass Credentials Variables specific to `rotate_vault_credentials.sh` script

| Variable |  Value |
| --- | --- |
| `USERNAME` | Username of vault user to be used to authenticate to the vault server |
| `PASS` | Password of vault user to be used to authenticate to the vault server |


File Variables specific to `rotate_app_credentials.sh` and `update_gcp_secrets.sh` script

| Variable | Value |
| --- | --- |
| `CRED_FILE` | Path from project root directory to to Google Cloud service account credentials file (not required if using REST API method) |

If using the gcloud CLI method, **do NOT mount or copy this file within any of the containers and ensure it is securely stored** 


Related Resources/Documentation:

[Intitiating Vault Rekeying Process](https://python-hvac.org/en/stable/usage/system_backend/key.html#start-rekey)

[Rekeying Vault Unseal Keys](https://developer.hashicorp.com/vault/docs/concepts/seal#rekeying)


The following steps listed below can be completed in order to configure credential rotation scripts:

1. Open the shell scripts, `./scripts/rotate/rotate_app_credentials.example.sh`, `./scripts/rotate/update_gcp_secrets.example.sh`, and
   `./scripts/rotate/rotate_vault_credentials.example.sh`. Update the assigned values of each environment variable found at the top of
   each script file according to the details provided in the above tables.


2. Rename these shell script filenames to `rotate_app_credentials.sh`, `update_gcp_secrets.sh`, and `rotate_vault_credentials.sh`,
   respectively.


3. For each PGP key to be utilized for either encrypting the new unseal key shards or for decrypting the original unseal key shards,
   generate a new file containing the 'raw' base64-encoded public key associated with that key ('Raw' means no use of line wrapping).

   The file contents of these files will be provided to the `./scripts/rotate/rotate_vault_credentials.sh` shell script as the assigned
   values to separate environment variables to be consumed by GnuPG for use by HVAC client in passing these PGP keys to the vault server
   for encrypting the returned plaintext values of rekeyed unseal keys.
   
   The code snippet listed below provides example implementations of how this can be achieved within the script:


```bash
   # Export the desired PGP key's public key into a new file as a raw base64 encoded string without newline characters or armoring
   gpg --export you-pgp-keys-fingerprint | base64 -w 0  > ./local/path/to/pgp/public/key/file.asc

   # PGP Key used to originally encrypt extended vault keys file
   gpg --export fingerprint-for-vault-env-file-encryption | base64 -w 0 > ./pgp_config/img_keys/pbkpEVK1.b64.asc

   # PGP Key used to originally encrypt first unseal key
   gpg --export fingerprint-for-vault-unseal-key1 | base64 -w 0 > ./pgp_config/img_keys/pbpkSK1.b64.asc 

   # PGP Key used to originally encrypt second unseal key
   gpg --export fingerprint-for-vault-unseal-key2 | base64 -w 0 > ./pgp_config/img_keys/pbkpSK2.b64.asc 

   # PGP Key used to originally encrypt third unseal key
   gpg --export fingerprint-for-vault-unseal-key3 | base64 -w 0 > ./pgp_config/img_keys/pbkpSK3.b64.asc 

   # PGP Key used to originally encrypt initial root/vault token
   gpg --export fingerprint-for-vault-token | base64 -w 0 > ./pgp_config/img_keys/pbkpRK1.b64.asc 
   ...

   # Provide it as the assigned value for the 'TOKEN_CRYPT_KEY' environment variable passed to the flask application at runtime
   TOKEN_CRYPT_KEY=$(cat ./local/path/to/pgp/public/key/file.b64.asc)

   # PGP Encryption key set #1
   UNSEAL_CRYPT_KEY1=$(cat ./pgp_config/img_keys/pbkpSK1.b64.asc)
   UNSEAL_CRYPT_KEY2=$(cat ./pgp_config/img_keys/pbkpSK2.b64.asc)
   UNSEAL_CRYPT_KEY3=$(cat ./pgp_config/img_keys/pbkpSK3.b64.asc)
   TOKEN_CRYPT_KEY=$(cat ./pgp_config/img_keys/pbkpRK1.b64.asc)

   # PGP Encryption key set #2
   ALT_UNSEAL_CRYPT_KEY1=$(cat ./pgp_config/img_keys/pbkpAltSK1.b64.asc)
   ALT_UNSEAL_CRYPT_KEY2=$(cat ./pgp_config/img_keys/pbkpAltSK2.b64.asc)
   ALT_UNSEAL_CRYPT_KEY3=$(cat ./pgp_config/img_keys/pbkpAltSK3.b64.asc)
   ALT_TOKEN_CRYPT_KEY=$(cat ./pgp_config/img_keys/pbkpAltRK1.b64.asc)
   ...
   # Repeat these for up to three additional PGP keys and ensure these are imported to the application container at runtime

   # Actual PGP keyring should be imported within the container at runtime so it can then be utilized for decryption of the vault credentials
```

4. Before running the application locally for the first time, ensure you run the `./scripts/rotate/update_gcp_secrets.sh` file after you have
   finished adding all necessary KV secrets to the Vault, then run the `./scripts/rotate/rotate_app_credentials.sh` file to update both the
   Vault and GCP Secret Manager with the rotated temporary Google OAuth service token and Flask session private key values.

```bash
   # Startup standalone vault service running behind the Nginx server
   make run-vault-service

   # Open a second bash shell in a separate terminal for executing bash shell scripts

   # Execute the update_gcp_secrets.sh script to add all Vault KV secrets to GCP Secret Manager (this should be only be called once instead of regularly)
   bash ./scripts/rotate/update_gcp_secrets.sh

   # Execute the rotate_app_credentials.sh script to update both Vault and GCP secrets for short-lived access token and Flask session private key 
   bash ./scripts/rotate/rotate_app_credentials.sh

   # Shutdown running vault and nginx containers
   Ctrl+C or OS equivalent of sending SIGINT signal
``` 


### Setting Up Autmomated Application Execution and Environment Configuration

The complete suite of internally networked containerized services that make up the full application can be hosted
on your local machine or can be externally hosted by the Google Cloud Platform (GCP) using the Cloud Run API service.

Under both conditions, key environment variables must be exported and made available to the Flask server at runtime
in order to ensure all required credentials can be utilized to establish secure connections with the MySQL database,
external IdP (Auth0) authorization/authentication servers, and GCP API services.

This will be primarily handled by the execution of the appropriate shell script immediately before execution of the
Flask server itself.

There are three main shell scripts responsible for both supplying the appropriate environment variable values for each of the different
environment configurations to the Flask server and initiating its execution.

1. `./scripts/app/start_app.local.dev.sh` for executing the application under `development` environment

2. `./scripts/app/start_app.local.prod.sh` for executing the application under `production` environment

3. `./scripts/app/start_app.deploy.sh` for executing the application after it has been deployed to the GCP Artifact Registry

> [!CAUTION]
> There is a fourth shell script, `./scripts/app/start_app.test.sh`, that is also made available for local use.
> However, this script is not intended to be utilized at ALL, if possible. **This shell script is intended for**
> **use as a last resort for detecting/diagnosing deployed container instance startup errors that cannot otherwise**
> **be determined from logs provided by Cloud Run! This will be further discussed in a later section** 

To complete the setup, the `./scripts/app/populate_app_startup_vars.example.sh` file has been provided, along with the appropriate template files
for each of the different configuration scripts that can be used to programatically produce these scripts using environment variable
substitution in a similar manner as that used in Step #4 of the [Initializing the HashiCorp Vault Server Section](#initializing-the-hashicorp-vault-server)


The tables provided below indicate the expected values for each environment variable within the `./scripts/app/populate_app_startup_vars.example.sh` file:

Supplementary Variables (used to breakup larger environment variable values)

| Variable |  Value |
| --- | --- |
| `VAULT_HOSTNAME` | Internal hostname of Vault service (i.e. name of the service, defaults to 'vault-store') |
| `VAULT_PORT` | | Internal port number of Vault service (defaults to '8200') |
| `EXTERNAL_PORT` | External port number listened on by Nginx reverse-proxy server (defaults to '8800') |
| `EXTERNAL_HOSTNAME` | External hostname of address listened on by Nginx server |
| `VAULT_CERT_FILENAME` | Name of the file containing the SSL certificate utilized by Vault service |
| `VAULT_CERT_KEY_FILENAME` | Name of the file containing the Vault's SSL certificate's private key |
| `UNSEAL_CRYPT_KEY1_FILE` | Path from project root directory to public key of PGP encryption key for original encryption of first unseal key |
| `UNSEAL_CRYPT_KEY2_FILE` | Path from project root directory to public key of PGP encryption key for original encryption of second unseal key |
| `UNSEAL_CRYPT_KEY3_FILE` | Path from project root directory to public key of PGP encryption key for original encryption of third unseal key |
| `TOKEN_CRYPT_KEY_FILE` | Path from project root directory to public key of PGP encryption key for original encryption of vault token |
| `ALT_UNSEAL_CRYPT_KEY1_FILE` | Path from project root directory to public key of PGP encryption key for alternate encryption of first unseal key |
| `ALT_UNSEAL_CRYPT_KEY2_FILE` | Path from project root directory to public key of PGP encryption key for alternate encryption of second unseal key |
| `ALT_UNSEAL_CRYPT_KEY3_FILE` | Path from project root directory to public key of PGP encryption key for alternate encryption of third unseal key |
| `ALT_TOKEN_CRYPT_KEY_FILE` | Path from project root directory to public key of PGP encryption key for alternate encryption of vault token |


Flask Server Configuration Variables

| Variable | Value |
| --- | --- |
| `HOSTNAME` | Internal hostname of Flask service (defaults to '0.0.0.0') | 
| `PORT` |  Internal port number on which Flask service is listening (defaults to '8500')  |


Vault Configuration Variables

| Variable | Value |
| --- | --- |
| `VAULT_ADDR` | The full internal host address and port number of the HashiCorp Vault container (i.e. https://vault-store:your-vault-port-number) |
| `VAULT_PROXY_ADDR` | The external host address and port number of the Nginx reverse-proxy server (i.e. http://127.0.0.1:your-external-port-number) |
| `VAULT_SKIP_VERIFY` | Ensure this is set to 'false' when executing the full application (prevent MIM attacks) |
| `VAULT_CERT_PATH`| Path from project root directory to the file containing the SSL certificate utilized by Vault service (i.e. ./vault/certs/your-ssl-certificate-filename) |
| `VAULT_CERT_KEY_PATH` | Path from project root directory to the file containing the Vault's SSL certificate's private key (i.e. ./vault/certs/your-ssl-certificate-private-key-filename) |


Nginx Server Configuration Variables

| Variable | Value |
| --- | --- |
|`PROXY_ADDR` | Full external address on which Nginx reverse-proxy server is listening for external requests |


PGP Encryption Variables (raw values are automatically provided using supplementary PGP filename variable values)

| Variable |  Value |
| --- | --- |
| `UNSEAL_CRYPT_KEY1` | Raw base64-encoded public key of PGP encryption key for original encryption of first unseal key |
| `UNSEAL_CRYPT_KEY2` | Raw base64-encoded public key of PGP encryption key for original encryption of second unseal key |
| `UNSEAL_CRYPT_KEY3` | Raw base64-encoded public key of PGP encryption key for original encryption of third unseal key |
| `TOKEN_CRYPT_KEY` | Raw base64-encoded public key of PGP encryption key for original encryption of vault token |
| `ALT_UNSEAL_CRYPT_KEY1` | Raw base64-encoded public key of PGP encryption key for alternate encryption of first unseal key |
| `ALT_UNSEAL_CRYPT_KEY2` | Raw base64-encoded public key of PGP encryption key for alternate encryption of second unseal key |
| `ALT_UNSEAL_CRYPT_KEY3` | Raw base64-encoded public key of PGP encryption key for alternate encryption of third unseal key |
| `ALT_TOKEN_CRYPT_KEY` | Raw base64-encoded public key of PGP encryption key for alternate encryption of vault token |
| `PGP_FINGERPRINT` | Fingerprint of PGP encryption key to be used for reencrypting the main vault credentials file |
| `GPG_HOME` | Path from project root directory to Flask service container's default location for GnuPG directory (i.e. /root/.gnupg) |


Vault KV Secrets Variables

| Variable |  Value |
| --- | --- |
| `SECRET_MOUNT_PATH` | Mounted path used by enabled vault KV secret containing desired k/v secrets to be accessed |
| `SECRET_PATH` | Internal path to k/v secret containing desired map of k/v secret values to be accessed |


Vault Transit Secrets Variables

| Variable |  Value |
| --- | --- |
| `TRANSIT_MOUNT_PATH` |  Mounted path used by enabled vault transit secret containing SOPS encryption keys to be used for runtime encryption/decryption |
| `TRANSIT_PATH` | Internal path to transit secret containing SOPS encryption keys from the mounted path |


Global File Variables

| Variable |  Value |
| --- | --- |
| `ORIGINAL_ENV_FILE` | Path from project root directory to env file containing SOPS-encrypted unseal keys and non-root user token values |
| `SOPS_CONFIG_FILE` | Path from project root directory to sops.yaml configuration file to be used by SOPS for encryption (default is `./sops/.sops.yaml`) |


1. Rename the `populate_app_startup_vars.example.sh` file to `populate_app_startup_vars.sh`

2. Replace the placeholder values with the desired values for each of the environment variables displayed at the top of `populate_app_startup_vars.sh`

3. Execute `populate_app_startup_vars.sh` from the project root directory generate each of the different startup scripts using the pre-provided
   shell script templates.

4. Each of these shell scripts will be directly utilized by the different environment preset configurations managed by the different Docker Compose
   files. These in turn will be executed by entering the appropriate environment-specific Make command to streamline alternating application execution
   between different environment configurations

**The value of `APP_ENV` can be set to one of three values to indicate which environment configuration to run the application under. This value**
**should be preset to the appropriate value for each script so do not change the `APP_ENV` value for any of these shell scripts**

| Environment Configuration Type | Corresponding `APP_ENV` Value | 
| --- | --- |
| `development` | `dev` |
| `production` | `prod` |
| `deployment` | `deploy` |


Phew! That was a lot of setup steps! Luckily, the vast majority of the application setup is now complete! Congrats for having the patience
and determination to make it this far! 


# Launching the Full Application

The complete suite of internally networked containerized services that make up the full application can be hosted
on your local machine or can be externally hosted by the Google Cloud Platform (GCP) using the Cloud Run API service.

Under both conditions, key environment variables must be exported and made available to the application at run-time
in order to ensure all required credentials can be utilized to establish secure connections with the MySQL database,
authorization/authentication servers, and Google Cloud Platform APIs/Services.

This will be primarily handled by the execution of the appropriate shell script immediately before execution of the
Flask application itself. This will be explained in the next section.


## Launching the Application Locally

> [!IMPORTANT]
> **Ensure you have completes ALL of the setup steps detailed in ALL of the previous sections before attempting to execute the application.**
> Attempting to do so without completing all of the steps will most likely result in one or more services failing to operate as intended or
> the application being unable to complete its startup process.


By default, the application ia intended to be executed on your local machine through the use of the preset Docker Compose service configurations.
The application can be run within the `development` or `production` environment configurations defined by the Docker Compose files `docker-compose.local.dev.yml`
and `docker-compose.local.prod.yml` files respectively.

Since the application secrets stored within the vault server are required to run the application locally, both environments are configured to run
over HTTPS and utilize SSL certificate verification (SSL verification can be disabled by changing the appropriate env variables but this is discouraged).

   - When running the application under the `production` configuration, the application utilizes gunicorn to improve application performance and support scalability.

   - When running the application under the `development` configuration, the application utilizes the basic Flask development server to support rebuilding/restarting 
     the Flask server upon detecting changes to the application's files.


Before local execution of the application under either configuration, the shell script `./scripts/rotate/update_gcp_secrets.sh` should first
be executed locally to update the GCP's Secret Manager with all Vault KV secrets that were added within the Vault service during the Vault setup process.
**Under normal conditions, this script should only be required to be executed once, barring changes to what otherwise should be static values**

As mentioned in an earlier section, you should also ensure you execute the `./scripts/rotate/rotate_app_credentials.sh` script to refresh the short-lived
Google OAuth2.0 temporary access token and the Flask session private key used to encrypt/sign its current Flask server session's data. This script will
also update the Secret Manager service's corresponding secrets with the refreshed values.

You may then execute the application utilizing the appropriate preset Makefile command to execute the application within the desired environment 
configuration.

> [!IMPORTANT]
> **The Google Cloud Platform access token is set to expire an hour after it is issued by default so ensure you call this script to programatically**
> **refresh this access token when it has expired.** It is also important to note that is only required when locally hosting the application.
> Cloud Run will be preconfigured to automatically manage authentication to the GCP API services without requiring a service access token to be provided
> by the application. 


The steps listed below can be used to rotate the short-lived Google OAuth service access token and then execute the application.

1. Start up the containerized Vault and Nginx reverse-proxy services using the `docker-compose.vault.yml` file with the supplied
   environment variable values by entering the Make command `make run-vault-service` within the terminal.
 

2. In a second terminal, execute the `rotate_app_credentials.sh` shell script to refresh the temporary service token (using gcloud CLI
   or the REST API, which can configured by changing function called under `main` within the `utils/rotate_app_creds.py` file) and a new session
   secret key for the WSGI Flask server. Verify the script output indicates credential rotation was successful.


3. Shut down the running Vault and Nginx services within in the first shell terminal using `Ctrl + C`


4. Start up the complete application using the appropriate Docker Compose file under the desired environment configuration:

   | Environment | Make Command |
   | --- | --- |
   | `development` | `make run-local-dev-app` |
   | `production` | `make run-local-prod-app` | 


5. If encountering any authentication errors at startup, this may be due to the authentication errors with Google service APIs
   or the configured environment variable values passed to the main application's entrypoint within the `start_app.local.dev.sh`
   or `start_app.local.prod.sh` file for the `development` or `production` environment configuration, respectively.

```bash

# Startup the vault service and nginx reverse-proxy server using Make command to run docker compose configurations

make run-vault-service  # Runs Hashicorp Vault and Nginx reverse-proxy servers networked containerized services 

# Open second shell terminal and run the bash script used to generate a new session secret key and temporary GCP service access token

bash ./scripts/rotate/rotate_app_credentials.sh

# Shutdown the running services in the first terminal and start all services using the docker-compose.local.yml file instead

# Ctrl + C

make run-local-dev-app  # for running application locally under development environment

make run-local-prod-app # for running application locally under production environment

```

6. You should now be able to access the application by opening your preferred browser client and then
   visiting `http://localhost:your-external-port-number`!

If encountering startup errors, startup the process in the development environment and view any logged errors
written to standard output to fix any issues logged by any of the application services


## Launching the Application Externally (Application Deployment)

If wishing to have the application hosted externally by Google Cloud Platform (GCP), you must complete a few additional
steps to properly deploy it utilizing Google Cloud's Cloud Run API service:

1. First, build the appropriate Docker image of the Flask service with the appropriate tagging/naming syntax.

2. Second, push it to Google's Artifact Registry (You may also push it to GitHub's Container Registry instead,
   but this use case is not covered in the provided instructions).

3. After successfully pushing the built image to the Artifact Registry, configure Cloud Run service to pull the
   Flask service image and manage its execution within a pre-configured and isolated container instance.
   
4. If initial startup of the Flask service is successful and it passes the established health checks, the deployed
   service will be become externally accessible via a HTTPS endpoint generated by Cloud Run.


Cloud Run will effectively replace both the Nginx reverse-proxy service and HashiCorp Vault service,
utilizing the GCP's Secret Manager API service to inject the application credentials as secret environment variables
at runtime and managing forwarding/redirection of external requests to Flask service over HTTPS (using its own generated
SSL certificate and certificate key for SSL verification).

Cloud Run also provides built in load balancing and automatic scaling to address fluctuations in traffic volume.


### Building the Application Image for Deployment

To build the flask server image to be deployed, the `Makefile` located within the root directory of the project contains a series
of pre-defined make rules/commands that can be used to build the Flask service image using the naming/tagging syntax required for images 
intended to be pushed to the Google Cloud Platform's Artifact Registry:

  `<your-chosen-region>-docker.pkg.dev/<your-project-id>/<your-project-repository-name>/<your-application-name>:<your-application-version>`.

First, build the appropriate Docker image of the Flask service with the appropriate tagging/naming syntax using the appropriate Makefile command:

1. Update the assigned environment variable values in the `./script/app/start_app.deploy.sh` file by executing
   `./scripts/app/populate_app_startup_vars.sh` with the appropriate assigned environment variable values.

2. Within the Makefile, update the environment variable values for `REGION`, `REGISTRY`, `PROJECT_ID`, `REPOSITORY_NAME`, 
   `REPOSITORY_NAME`, `APPLICATION_NAME` and `APPLICATION_VERSION` to correspond to the desired tag for the Flask service image
   to be built. Update the values of `PORT` to match the port you wish the Flask application to listen on and `RUN_SCRIPT` if wishing to change the
   name of script file you wish to use to export the run-time environment variables and execute the Flask application itself. 
   ***Ensure the assigned `PORT`, `HOSTNAME`, and `APP_ENV` values assigned in the `RUN_SCRIPT` file match those assigned***
   ***in the Makefile rule definiton of `build-deploy-flask-service-image`***
   
4. Ensure you have the Docker Engine running and then enter the make command `make build-deploy-flask-service-image` to build the Docker image of the
   Flask application and push it to your local machine's Docker registry (viewable via Docker Desktop application).


### Pushing the Application Image to Google Artifact Repository 

The Artifact Registry is GCP's equivalent to the Docker registry or GitHub's Container Registry.

The pre-built Docker image of the Flask application service can be pushed to the Artifacts Registry to allow for the application
image to be then pulled by the Cloud Run service.

Before proceeding, ensure you have already built the application image and have the Docker Engine running.

1. Ensure the defined value for the `REGION` variable is set to the region in which your project services are currrently be hosted by
   GCP's servers (preferentially the region closest to your physical address). This is utilized for setting the region in which to host
   the repository for storing and retrieving pushed Docker images of the application.

2. Ensure you have activated your virtual environment -> Export the `REGION` environment variable with the assigned value to be used
   in the command to create a new repostiory within GCP's Artifact Registry.

3. Ensure you have authenticated to gcloud with an authorized service account for the project (otherwise your gcloud commands will be denied).
   This can be quickly done by entering `gcloud auth login` -> Clicking on the provided link -> Completing the verification process using the gmail
   account you used to create the GCP project.

4. Create a new repository within the Artifact Registry by entering the following command into the terminal:
   
   ```bash
   gcloud artifacts repositories create <your-chosen-repository-name> \
      --repository-format=docker \
      --location=${REGION} \
      --description='<your-chosen-repository-description>'
   ```

5. Within the Makefile, ensure you have:
    - `REGION` set to the chosen region for servers hosting deployed application
    - `REGISTRY` set to Artifact Registry syntax of `<your-chosen-region>-docker.pkg.dev`
    - `PROJECT_ID` set to your GCP project ID
    - `REPOSITORY_NAME` set to the created repository's name
    - `APPLICATION_NAME` set to application's chosen name
    - `APPLICATION_VERSION` set to the targeted version of application to be deployed


6. Configure Docker CLI to authenticate to GCP's Artifact Registry by entering the following command into the terminal:
   `gcloud auth configure-docker ${REGION}-docker.pkg.dev`

7. Push the Docker image of the application to the newly created repository within GCP's Artifact Registry by entering the predefined make command:
   `make push-flask-service-image`

> [!NOTE]
> If any authentication errors occur during repository creation or image deployment to the Artifact Registry, visit the official
> documentation for [managing Docker images with GCP's Artifact Registry](https://docs.cloud.google.com/artifact-registry/docs/docker/store-docker-container-images)
> or [proper naming and deployment of images to GCP's Artifact Registry](https://cloud.google.com/artifact-registry/docs/docker/pushing-and-pulling#pushing)


### Deploying Application using Cloud Run API Service

After pushing the application image to your created repository within GCP's Artifact Registry, GCP's Cloud Run service can be
used to deploy application image within a newly created container instance that is directly managed by the Cloud Run service.

> [!NOTE]
> While use of GCP's Compute Engine to run deployed container images using Virtual Machine instances provides increased control
> over the container's running environment, it has limited built-in disk image support and its use for this type of use case is
> now considered deprecated. Use of Cloud Run or Google Kubernetes Engine (GKE) are considered more suitable for deploying web-based
> applications that utilize containerized services. Due to the application only comprising of a single service, GKE was determined
> to be less suitable as it is intended for simultaneously managing multiple applications that consist of one or more internal services.


To deploy the pushed Flask application image using Cloud Run:

1. Ensure your created service account user has the roles of `Cloud Run Admin` and `Cloud Run Developer`

2. Navigate to `Cloud Run` from the GCP project's dashboard (from within left-hand side navigation bar)

3. Click on `Services` under the `Cloud Run` left-hand overview section

4. Click `Deploy Container`

5. Ensure `Create Service` is now displayed at the top of the page.

6. Ensure `Deploy one revision from an existing container image` is selected

7. Click `Select` from within the selection bar displaying the `Container image URL` placeholder value

8. From within the righthand side bar that has now appeared, click the collapsed element with the title matching the
   created Artifact Registry repository (i.e. `<your-chosen-region>-docker.pkg.dev/<your-project-id>/<your-project-repository-name>`)
   If you do not see this displayed, ensure the correct project is displayed as the selected project and click `Change` if it is not.

9. Click on the item with name matching your chosen application name, then click on the shortened image SHA digest with the
   desired version tag outlined in gray (i.e. value assigned to `APPLICATION_VERSION`, such as `v0.0.1`)

10. Under the `Configure` section, enter the desired service name and select the region matching the assigned `REGION` value

11. Optionally, copy the displayed Endpoint URL, which can be pasted within a new browser tab to access the Cloud Run service-hosted application
    after its successful deployment.

12. Under `Authentication`, select `Allow public access` (publicly exposed endpoints will be secured solely by the application) 

13. Under `Billing`, if desiring to use the hosted application for prolonged testing (generate high request rates over short periods of time),
    it is recommended to select `Instance-based`. Otherwise, select `Request-based`.

14. Under `Service Scaling`, leave `Auto Scaling` selected.

15. Under `Ingress`, leave `All` selected.

16. Click on `Containers, Volumes, Networking, Security` to expand the collapsed section

17. With the `Containers` tab selected, enter the assigned value of the `PORT` variable found within the Makefile within the `Container Port`
    section under the `Edit Container` section of the container now associated with the pushed application service image

18. Under the `Settings` tab, leave the default settings for the `Resources` and `Health Checks` sections.
    There is no need to increase the default memory or hardware requirements nor set up a Startup Health Check as this
    will be automatically be created for the ingress container (which will the application image's container by default).

19. With the `Settings` tab still selected, scroll down past the `Requests`, `Execution Environment`, and `Revision Scaling` sections
    (leave these sections with their default values set) to the checkbox labeled `Startup CPU Boost` and check this box.

20. Scroll past the checkbox to the `Cloud SQL Connections` section, and click on the `Add Connection` button to reveal a dropdown menu

21. Select the name of your MySQL database managed by the Cloud SQL service from the revealed dropdown menu.

22. Scroll back up to the `Settings` tab and now click on the `Variables & Secrets` tab.

23. Leave the `Environment Variables` section untouched and scroll down to the `Secrets exposed as Environment Variables` section below it.

24. Click on the `Reference a secret` button to populate an empty set of fields consisting of `Name`, `Secret`, and `Version`

25. For each of the Vault KV secrets listed below, select the menu item with the matching name from the dropdown menu within the `Secret` field,
    type the exact same name value of the selected menu itme into the `Name` field (such that `Secret` and `Name` now hold the exact same values), and
    select `latest` from the dropdown menu within the `Version` field.

   | Required Vault KV Secret Name |
   | --- |
   | `CLIENT_ID` |
   | `CLIENT_SECRET` |
   | `DOMAIN` |
   | `ADMIN_ROLE_ID` |
   | `INSTRUCTOR_ROLE_ID` |
   | `STUDENT_ROLE_ID` |
   | `PROJECT_ID` |
   | `INSTANCE_CONNECTION_NAME` |
   | `AUTH_MANAGEMENT_API_ID` |
   | `DEFAULT_ADMIN_USERNAME` |
   | `DEFAULT_ADMIN_PASS` |
   | `AUTH_DB_CONNECTION` |
   | `DB_USER` |
   | `DB_PASS` |
   | `DB_NAME` |
   | `AVATAR_BUCKET_NAME` |
   | `APP_SECRET` |

> [!NOTE]
> If any of these secrets are not selectable from within the `Secret` dropdown menu, review your vault's KV secrets
> and ensure this secret exists within the vault. Run the `rotate_app_credentials.sh` after confirming any secrets
> missing from dropdown menu exist within the vault to add them to the Secret Manager.
> These should now be selectable from the dropdown menu. The total number of secrets should be 17 

   You may leave all other fields and tabs under ` in their current settings/configuration

26. Click on the `Security` tab.

27. Click on the `Service Account` dropdown menu and select the GCP service account that has been used throughout the setup process. 

28. Click `Create` to initiate the deployment of the now configured container instance to be deployed with the pulled application image

29. Wait until the service container creation is complete and now appears below `Services`, then select it to be navigated to its details page.
    If one or more checks fail, review the logs to verify the instance was successfully started. If it was not, ensure the container's
    hostname is set to '0.0.0.0' and port numbers match for both the `start_app.deploy.sh` script and the Makefile settings for the 
    `build-deploy-flask-service-image` command. If errors occur after startup, view the logs to locate the traceback to the locate
    the source of the error(s).

30. At the top of the details page, locate the link displayed to the left of `URL` and click on it to open an external connection to
    container running the application using your browser client. You may now access this running instance of your application for as
    long as you chose to run this Cloud Run service!
