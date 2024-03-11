import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = int(os.environ.get("MYSQL_PORT"))


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "Authorization failed", 401

    cur = mysql.connection.cursor()
    result = cur.execute("SELECT email, password FROM user WHERE email = %s", [auth.username])

    if result > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "Authorization failed", 401
        else:
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)
    return "Authorization failed", 401


def createJWT(username, secret, isAdmin=False):
    return jwt.encode(
        {"username": username,
         "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
         "admin": isAdmin
         },
        secret,
        algorithm="HS256",
    )


@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers.get("Authorization")
    if not encoded_jwt:
        return "Authorization failed", 401
    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"])
    except:
        return "Not Authorized", 403
    return decoded, 200


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
