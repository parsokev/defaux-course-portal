# syntax=docker/dockerfile:1

FROM python:3.13.9-slim-bookworm AS debian-dev-builder

# Install all required dependencies for initial setup and copying operations as ROOT user
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install python3 && \
    apt-get -y install python3-dev && \
    apt-get -y install gnupg && \
    apt-get -y install curl && \
    python3 -m ensurepip && \
    pip3 install --upgrade setuptools pip wheel && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

ARG USER
ARG GROUP
ARG USER_ID
ARG GROUP_ID
ARG RUN_SCRIPT

# Generate a new user with matching group and user IDs for providing read access to mounted files and execution permission for shell scripts
RUN groupadd -g $GROUP_ID $GROUP && \
    useradd -m -u $USER_ID -g $GROUP $USER

# When running in development mode, the templates, static, main.py, and utils files will be directly mounted on the container
# to enable runtime detection of changes (allow server reloading on changes)
COPY --chown=$USER:$GROUP ./${RUN_SCRIPT} ./${RUN_SCRIPT}
COPY --chown=$USER:$GROUP ./sops/.sops.yaml ./sops/.sops.yaml
COPY --chown=$USER:$GROUP ./course_sheet.json ./course_sheet.json
COPY --chown=$USER:$GROUP ./requirements.local.txt ./requirements.local.txt


FROM python:3.13.9-slim-bookworm AS debian-prod-builder

# Install all required dependencies for initial setup and copying operations as ROOT user
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install python3 && \
    apt-get -y install python3-dev && \
    apt-get -y install gnupg && \
    apt-get -y install curl && \
    python3 -m ensurepip && \
    pip3 install --upgrade setuptools pip wheel && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

ARG USER
ARG GROUP
ARG USER_ID
ARG GROUP_ID
ARG RUN_SCRIPT

# Generate a new user with matching group and user IDs for providing read access to mounted files and execution permission for shell scripts
RUN groupadd -g $GROUP_ID $GROUP && \
    useradd -m -u $USER_ID -g $GROUP $USER



# Ensure only required application files are added to generated container
COPY --chown=$USER:$GROUP ./${RUN_SCRIPT} ./${RUN_SCRIPT}
COPY --chown=$USER:$GROUP ./sops/.sops.yaml ./sops/.sops.yaml
COPY --chown=$USER:$GROUP ./static ./static
COPY --chown=$USER:$GROUP ./templates ./templates
COPY --chown=$USER:$GROUP ./utils/db_connector.py ./utils/
COPY --chown=$USER:$GROUP ./utils/vault_connector.py ./utils/
COPY --chown=$USER:$GROUP ./utils/auth_utils.py ./utils/
COPY --chown=$USER:$GROUP ./utils/db_utils.py ./utils/
COPY --chown=$USER:$GROUP ./utils/vc_utils.py ./utils/
COPY --chown=$USER:$GROUP ./course_sheet.json ./course_sheet.json
COPY --chown=$USER:$GROUP ./main.py ./main.py
COPY --chown=$USER:$GROUP ./requirements.local.txt ./requirements.local.txt
COPY --chown=$USER:$GROUP ./gunicorn.conf.py ./gunicorn.conf.py
COPY --chown=$USER:$GROUP ./wsgi.py ./wsgi.py


FROM python:3.13.9-slim-bookworm AS debian-dev-runner

# Install all required dependencies for initial setup and copying operations as ROOT user
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install python3 && \
    apt-get -y install  python3-dev && \
    apt-get -y install gnupg && \
    apt-get -y install curl && \
    apt-get -y install build-essential && \
    apt-get -y install cargo && \
    python3 -m ensurepip && \
    pip3 install --upgrade setuptools pip wheel && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Download the SOPS binary from official SOPS git repository, move it to local PATH, and make it executable as ROOT user
RUN curl -LO https://github.com/getsops/sops/releases/download/v3.11.0/sops-v3.11.0.linux.amd64 && \
    mv sops-v3.11.0.linux.amd64 /usr/bin/sops && \
    chmod +x /usr/bin/sops

ARG USER
ARG GROUP
ARG USER_ID
ARG GROUP_ID
ARG PORT
ARG RUN_SCRIPT
ARG APP_ENV
ENV APP_ENV=${APP_ENV}

# Generate a new user with matching group and user IDs for providing read access to mounted files and execution permission for shell scripts
RUN groupadd -g $GROUP_ID $GROUP && \
    useradd -m -u $USER_ID -g $GROUP $USER

ENV PORT=$PORT

# Ensure required application files are accessible by generated container user
COPY --chown=$USER:$GROUP --from=debian-dev-builder /tmp/ ./

# Install all required python libraries as ROOT user
RUN pip3 install -r requirements.local.txt

USER $USER
EXPOSE $PORT

# Execute container process as generated user (not as ROOT)
CMD ["/bin/bash", "-c", "bash ${RUN_SCRIPT}"]


FROM python:3.13.9-slim-bookworm AS debian-prod-runner

# Install all required dependencies for initial setup and copying operations as ROOT user
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install python3 && \
    apt-get -y install  python3-dev && \
    apt-get -y install gnupg && \
    apt-get -y install curl && \
    apt-get -y install build-essential && \
    apt-get -y install cargo && \
    python3 -m ensurepip && \
    pip3 install --upgrade setuptools pip wheel && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Download the SOPS binary from official SOPS git repository, move it to local PATH, and make it executable as ROOT user
RUN curl -LO https://github.com/getsops/sops/releases/download/v3.11.0/sops-v3.11.0.linux.amd64 && \
    mv sops-v3.11.0.linux.amd64 /usr/bin/sops && \
    chmod +x /usr/bin/sops

ARG USER
ARG GROUP
ARG USER_ID
ARG GROUP_ID
ARG PORT
ARG RUN_SCRIPT
ARG APP_ENV
ENV APP_ENV=${APP_ENV}

# Generate a new user with matching group and user IDs for providing read access to mounted files and execution permission for shell scripts
RUN groupadd -g $GROUP_ID $GROUP && \
    useradd -m -u $USER_ID -g $GROUP $USER

ENV PORT=$PORT

# Ensure required application files are accessible by generated container user
COPY --chown=$USER:$GROUP --from=debian-prod-builder /tmp/ ./

# Install all required python libraries as ROOT user
RUN pip3 install -r requirements.local.txt

USER $USER
EXPOSE $PORT

# Execute container process as generated user (not as ROOT)
CMD ["/bin/bash", "-c", "bash ${RUN_SCRIPT}"]