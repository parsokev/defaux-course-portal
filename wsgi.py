from main import app
import os

HOST_URL = os.environ["HOSTNAME"] if os.environ["HOSTNAME"] else '127.0.0.1'
HOST_PORT = os.environ["PORT"]

if __name__ == "__main__":
    app.run(host=HOST_URL, port=HOST_PORT,debug=False)