
from google.oauth2.credentials import Credentials
from google.cloud.sql.connector import Connector, IPTypes
import os
import pymysql
import sqlalchemy


APP_ENV = os.environ["APP_ENV"]

# Python Cloud SQL connector for establishing connection between Flask server and Cloud SQL MySQL database instance
# See: https://cloud.google.com/sql/docs/mysql/connect-app-engine-standard?hl=en#connect
def connect_with_connector() -> sqlalchemy.engine.base.Engine:
    """
    Initializes a connection pool for a Cloud SQL instance of MySQL.

    Uses the Cloud SQL Python Connector package.
    """
    ip_type = IPTypes.PRIVATE if os.environ.get("PRIVATE_IP") else IPTypes.PUBLIC
    
    if APP_ENV != 'deploy' and APP_ENV != 'test':
        from . import vc_utils as vc_op
        vc_data = vc_op.get_secrets()
        instance_connection_name = vc_data["INSTANCE_CONNECTION_NAME"]  # i.e. 'project:region:instance'
        db_user = vc_data["DB_USER"]
        db_pass = vc_data["DB_PASS"] 
        db_name = vc_data["DB_NAME"]
        access_token = str(vc_data["TMP_SERVICE_TOKEN"]).strip()
        credentials=Credentials(access_token)
        connector = Connector(ip_type=ip_type, credentials=credentials, refresh_strategy="LAZY")
    else:

        instance_connection_name = os.environ["INSTANCE_CONNECTION_NAME"]
        db_user = os.environ["DB_USER"]
        db_pass = os.environ["DB_PASS"]
        db_name = os.environ["DB_NAME"]
        if APP_ENV == 'test':
            access_token = str(os.environ["TMP_SERVICE_TOKEN"]).strip()
            credentials=Credentials(access_token)
            connector = Connector(ip_type=ip_type, credentials=credentials, refresh_strategy="LAZY")
        else:
            connector = Connector(ip_type=ip_type, refresh_strategy="LAZY")


    def getconn() -> pymysql.connections.Connection:
        conn: pymysql.connections.Connection = connector.connect(
            instance_connection_name,
            "pymysql",
            user=db_user,
            password=db_pass,
            db=db_name,
        )
        return conn
    
    # NOTES: 
    #  - Pool size is the maximum number of permanent connections to keep.
    #
    #  - Max overflow will exceed the set pool_size if no connections are available by at most 2
    #    for a total number of concurrent connections equal to pool size + max overflow.
    #
    #  - Pool recycle is the set maximum number of seconds a connection can persist before being 
    #    reset/re-established

    pool = sqlalchemy.create_engine(
        "mysql+pymysql://",
        creator=getconn,
        pool_size=5,
        max_overflow=2,
        pool_timeout=30,
        pool_recycle=1800,
    )

    return pool
