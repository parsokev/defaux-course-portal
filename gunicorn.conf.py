import multiprocessing
from gunicorn import arbiter
import os


HOSTNAME = os.environ["HOSTNAME"]
PORT = os.environ["PORT"]

bind = f"{HOSTNAME}:{PORT}"
workers = multiprocessing.cpu_count() * 2 + 1

accesslog = "-"  # Log HTTP requests to a file
errorlog = "-"  # Log errors to a file
loglevel = "info"  # Set log verbosity (debug, info, warning, error, critical)


def on_starting(server):
    # print(f"GUNICORN CONFIG: Binding on {bind}...")
    pass


def on_exit(arbiter: arbiter):
    # print("Gunicorn master process is exiting. Performing final cleanup.")
    pass
