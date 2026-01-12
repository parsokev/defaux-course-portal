#!/usr/bin/env bash

# Flask server configuration settings
HOSTNAME=${HOSTNAME}
PORT=${PORT}
APP_ENV=deploy

# External Cloud Run Instance Default Address (Provided Container Port as Port Number and Localhost as Host Address)
PROXY_ADDR=http://127.0.0.1:8800


HOSTNAME=$HOSTNAME PORT=$PORT PROXY_ADDR=$PROXY_ADDR APP_ENV=$APP_ENV gunicorn --config gunicorn.conf.py wsgi:app
