.PHONY: build-app-image run-app-image push-app-image build-alpine-app-image run-alpine-app-image push-alpine-app-image encrypt-sensitive-files decrypt-sensitive-files run-local-app-services

# BUILD-TIME ENVIRONMENT VARIABLES

# Chosen region of cloud servers to host application
export REGION=your-gcp-project-region

# Artifacts Registry package syntax
export REGISTRY=${REGION}-docker.pkg.dev

# Chosen GCP Project ID
export PROJECT_ID=your-gcp-project-id

# Name of designated repository for storing deployed application images
export REPOSITORY_NAME=defaux-course-portal-repo

# Chosen name of application
export APPLICATION_NAME=defaux-course-portal

# Version of application being built
export APPLICATION_VERSION ?= v0.0.1

# WSGI Flask Server Configuration Variables
export APP_PORT=your-flask-application-port-number
export HOSTNAME=0.0.0.0


# Shell script executed within application image at runtime
export RUN_SCRIPT=./scripts/app/your-script-name
APP_ENV ?= dev

# Vault Image Configuration Variables
VAULT_PORT=8200
VAULT_CLUSTER_PORT=8201
VAULT_SKIP_VERIFY ?= false
VAULT_HOSTNAME ?= vault-store

VAULT_ADDR=https://${VAULT_HOSTNAME}:${VAULT_PORT}
VAULT_API_ADDR=https://${VAULT_HOSTNAME}:${VAULT_PORT}
VAULT_ADDRESS=https://${VAULT_HOSTNAME}:${VAULT_PORT}

VAULT_CERT_FILENAME=your-vault-ssl-certificate-filename
VAULT_CERT_KEY_FILENAME=your-vault-ssl-certificate-private-key-filename
VAULT_CREDS_FILENAME=your-sops-encrypted-vault-credentials-env-file

# Nginx Image Configuration Variables
EXTERNAL_PROXY_PORT=8800
INTERNAL_PROXY_PORT=80

# User configuration varialbles
USER=your-local-username
GROUP=your-local-user-group-name

USER_ID=$(shell id -u)
GROUP_ID=$(shell id -g)

IMAGE=your-build-deployment-image-name-or-SHA

# PREDEFINED APPLICATION IMAGE MANAGEMENT COMMANDS

# Exclusively run HashiCorp Vault (in pre-setup form) and Nginx servers (for conducting isolated vault service testing/intialization/configuration)
run-initial-vault-service:
	VAULT_PORT=${VAULT_PORT} \
	VAULT_ADDR=${VAULT_ADDR} \
	VAULT_API_ADDR=${VAULT_API_ADDR} \
	VAULT_CLUSTER_PORT=${VAULT_CLUSTER_PORT} \
	VAULT_ADDRESS=${VAULT_ADDRESS} \
	VAULT_SKIP_VERIFY=true \
	VAULT_CERT_FILENAME=${VAULT_CERT_FILENAME} \
	VAULT_CERT_KEY_FILENAME=${VAULT_CERT_KEY_FILENAME} \
	VAULT_CREDS_FILENAME=${VAULT_CREDS_FILENAME} \
	EXTERNAL_PROXY_PORT=${EXTERNAL_PROXY_PORT} \
	INTERNAL_PROXY_PORT=${INTERNAL_PROXY_PORT} \
	docker compose -f docker-compose.init.yml up --remove-orphans


# Exclusively run HashiCorp Vault (in post-setup form) and Nginx reverse-proxy server (for conducting isolated vault service testing/configuration)
run-vault-service:
	VAULT_PORT=${VAULT_PORT} \
	VAULT_ADDR=${VAULT_ADDR} \
	VAULT_API_ADDR=${VAULT_API_ADDR} \
	VAULT_CLUSTER_PORT=${VAULT_CLUSTER_PORT} \
	VAULT_ADDRESS=${VAULT_ADDRESS} \
	VAULT_SKIP_VERIFY=${VAULT_SKIP_VERIFY} \
	VAULT_CERT_FILENAME=${VAULT_CERT_FILENAME} \
	VAULT_CERT_KEY_FILENAME=${VAULT_CERT_KEY_FILENAME} \
	VAULT_CREDS_FILENAME=${VAULT_CREDS_FILENAME} \
	EXTERNAL_PROXY_PORT=${EXTERNAL_PROXY_PORT} \
	INTERNAL_PROXY_PORT=${INTERNAL_PROXY_PORT} \
	docker compose -f docker-compose.vault.yml up --remove-orphans


# Run all application services on local machine within production configuration/environment
run-local-prod-app:
	USER=${USER} \
	GROUP=${GROUP} \
	USER_ID=${USER_ID} \
	GROUP_ID=${GROUP_ID} \
	APP_ENV=prod \
	RUN_SCRIPT=./scripts/app/start_app.local.prod.sh \
	PORT=${APP_PORT} \
	HOSTNAME=${HOSTNAME} \
	APPLICATION_NAME=${APPLICATION_NAME} \
	VAULT_PORT=${VAULT_PORT} \
	VAULT_ADDR=${VAULT_ADDR} \
	VAULT_API_ADDR=${VAULT_API_ADDR} \
	VAULT_CLUSTER_PORT=${VAULT_CLUSTER_PORT} \
	VAULT_ADDRESS=${VAULT_ADDRESS} \
	VAULT_SKIP_VERIFY=false \
	VAULT_CERT_FILENAME=${VAULT_CERT_FILENAME} \
	VAULT_CERT_KEY_FILENAME=${VAULT_CERT_KEY_FILENAME} \
	VAULT_CREDS_FILENAME=${VAULT_CREDS_FILENAME} \
	EXTERNAL_PROXY_PORT=${EXTERNAL_PROXY_PORT} \
	INTERNAL_PROXY_PORT=${INTERNAL_PROXY_PORT} \
	docker compose -f docker-compose.local.prod.yml up --build --remove-orphans


# Run all application services on local machine within development configuration/environment
run-local-dev-app:
	USER=${USER} \
	GROUP=${GROUP} \
	USER_ID=${USER_ID} \
	GROUP_ID=${GROUP_ID} \
	APP_ENV=dev \
	RUN_SCRIPT=./scripts/app/start_app.local.dev.sh \
	PORT=${APP_PORT} \
	HOSTNAME=${HOSTNAME} \
	APPLICATION_NAME=${APPLICATION_NAME} \
	VAULT_PORT=${VAULT_PORT} \
	VAULT_ADDR=${VAULT_ADDR} \
	VAULT_API_ADDR=${VAULT_API_ADDR} \
	VAULT_CLUSTER_PORT=${VAULT_CLUSTER_PORT} \
	VAULT_ADDRESS=${VAULT_ADDRESS} \
	VAULT_SKIP_VERIFY=false \
	VAULT_CERT_FILENAME=${VAULT_CERT_FILENAME} \
	VAULT_CERT_KEY_FILENAME=${VAULT_CERT_KEY_FILENAME} \
	VAULT_CREDS_FILENAME=${VAULT_CREDS_FILENAME} \
	EXTERNAL_PROXY_PORT=${EXTERNAL_PROXY_PORT} \
	INTERNAL_PROXY_PORT=${INTERNAL_PROXY_PORT} \
	docker compose -f docker-compose.local.dev.yml up --build --remove-orphans



# Build image of flask application service to be pushed to GCP Artifact Registry and subsequently deployed via GCP Cloud Run
build-deploy-flask-service-image:
	PORT=${APP_PORT} \
	APP_ENV=deploy \
    HOSTNAME=0.0.0.0 \
	RUN_SCRIPT=./scripts/app/start_app.deploy.sh \
	docker buildx build \
	--build-arg USER=${USER} \
	--build-arg GROUP=${GROUP} \
	--build-arg USER_ID=${USER_ID} \
	--build-arg GROUP_ID=${GROUP_ID} \
	--build-arg PORT=${APP_PORT} \
	--build-arg RUN_SCRIPT=./scripts/app/start_app.deploy.sh \
	--build-arg APP_ENV=deploy \
	--target debian-deploy-runner \
	-t ${REGISTRY}/${PROJECT_ID}/${REPOSITORY_NAME}/${APPLICATION_NAME}-flask-service:${APPLICATION_VERSION} \
	-f ./deploy_images/flask_server/Dockerfile \
	.


# Deploy the built application image with Debian Linux base to designated repository within Artifact Registry
push-flask-service-image:
	docker push ${REGISTRY}/${PROJECT_ID}/${REPOSITORY_NAME}/${APPLICATION_NAME}-flask-service:${APPLICATION_VERSION}



#==================================== ADVANCED DEBUGGING/TROUBLESHOOTING RULESETS ========================================

# Build image of flask application service to deployed on local machine BUT providing secrets directly into running container
# process as environment variables to mimic the same process that is completed by Secrets Manager on deployed Cloud Run containers
# WARNING: This will be an exposed service and requires direct local injection of naked credentials that would otherwise
# be provided by GCP's Secret Manager! It is recommended to first try to include additional startup logging before proceeding with
# this method!
# This should be used as a last resort when Cloud Run logs do not provide sufficient data to diagnose startup issues/failures
build-test-flask-service-image:
	PORT=${APP_PORT} \
	APP_ENV=test \
    HOSTNAME=0.0.0.0 \
	RUN_SCRIPT=./scripts/app/start_app.test.sh \
	docker buildx build \
	--build-arg USER=${USER} \
	--build-arg GROUP=${GROUP} \
	--build-arg USER_ID=${USER_ID} \
	--build-arg GROUP_ID=${GROUP_ID} \
	--build-arg PORT=8500 \
	--build-arg RUN_SCRIPT=./scripts/app/start_app.test.sh \
	--build-arg APP_ENV=test-deploy \
	--target debian-deploy-runner \
	-t ${REGISTRY}/${PROJECT_ID}/${REPOSITORY_NAME}/${APPLICATION_NAME}-flask-service:${APPLICATION_VERSION} \
	-f ./deploy_images/flask_server/Dockerfile \
	.


# Run latest built image of flask application service to deployed on local machine
# WARNING: This will be an exposed service and requires direct local injection of naked credentials that would otherwise
# provided by GCP's Secret Manager!
# This should be used as a last resort when Cloud Run logs do not provide sufficient data to diagnose startup issues/failures 
run-test-flask-service-image:
	docker run -p 8500:8500 --name test-flask-service -a stderr -a stdout ${IMAGE}