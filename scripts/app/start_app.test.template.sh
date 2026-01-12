#!/usr/bin/env bash

# Flask server configuration settings
HOSTNAME=${HOSTNAME}
PORT=${PORT}
APP_ENV=test

# External Nginx reverse-proxy server configuration settings
PROXY_ADDR=${PROXY_ADDR}
RUN_SCRIPT=./scripts/app/start_app.test.sh

CLIENT_ID=your-auth0-client-id
CLIENT_SECRET=your-auth0-client-secret
DOMAIN=your-auth0-tenant-domain-uri
ADMIN_ROLE_ID=your-auth0-assigned-role-id-for-admin-user-roles
INSTRUCTOR_ROLE_ID=your-auth0-assigned-role-id-for-instructor-user-roles
STUDENT_ROLE_ID=your-auth0-assigned-role-id-for-student-user-roles
PROJECT_ID=your-gcp-project-id
INSTANCE_CONNECTION_NAME=your-gcp-cloud-my-sql-instance-connection-name
AUTH_MANAGEMENT_API_ID=your-auth0--auth-management-api-uri
DEFAULT_ADMIN_USERNAME=your-default-admin-username
DEFAULT_ADMIN_PASS=your-default-admin-password
AUTH_DB_CONNECTION=your-auth0-managed-database-connection-name
DB_USER=your-built-in-gcp-mysql-database-user-username
DB_PASS=your-built-in-gcp-mysql-database-user-password
DB_NAME=your-gcp-cloud-sql-instance-my-sql-database-name
AVATAR_BUCKET_NAME=your-gcp-storage-bucket-for-avatar-images-name
APP_SECRET=your-generated-flask-session-secret-key
TMP_SERVICE_TOKEN=your-short-lived-gcp-Oauth-service-access-token

# Ensure all public/private keypairs of pgp keys used to originally encrypt vault keys file and for runtime decryption/encryption is mounted to flask-app container at runtime
HOSTNAME=$HOSTNAME PORT=$PORT PROXY_ADDR=$PROXY_ADDR APP_ENV=$APP_ENV CLIENT_ID=$CLIENT_ID CLIENT_SECRET=$CLIENT_SECRET RUN_SCRIPT=$RUN_SCRIPT \
 DOMAIN=$DOMAIN ADMIN_ROLE_ID=$ADMIN_ROLE_ID INSTRUCTOR_ROLE_ID=$INSTRUCTOR_ROLE_ID STUDENT_ROLE_ID=$STUDENT_ROLE_ID \
 PROJECT_ID=$PROJECT_ID INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME AUTH_MANAGEMENT_API_ID=$AUTH_MANAGEMENT_API_ID \
 DEFAULT_ADMIN_USERNAME=$DEFAULT_ADMIN_USERNAME DEFAULT_ADMIN_PASS=$DEFAULT_ADMIN_PASS AUTH_DB_CONNECTION=$AUTH_DB_CONNECTION \
 DB_USER=$DB_USER DB_PASS=$DB_PASS DB_NAME=$DB_NAME AVATAR_BUCKET_NAME=$AVATAR_BUCKET_NAME APP_SECRET=$APP_SECRET TMP_SERVICE_TOKEN=$TMP_SERVICE_TOKEN \
 gunicorn --config gunicorn.conf.py wsgi:app