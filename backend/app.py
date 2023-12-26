import flask
from flask import request, jsonify
import flask_security
import requests
import json
import os
import argon2
import pymongo
import jwt
import datetime

from base64 import b64decode

ENV_VAR_NAMES = ("GOOGLE_MAPS_API_KEY", "MONGO_HOSTNAME", "MONGO_USERNAME", "MONGO_PASSWORD", "FLASK_SECRET_KEY", "DEBUG")

# According to https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
Hasher = argon2.PasswordHasher().from_parameters({
    "time_cost": 2,
    "memory_cost": 19 * (MiB := 1024),
    "parallelism": 2,
    "hash_len": 32,
    "salt_len": 16,
    "encoding": "utf-8",
    "type": argon2.Type.ID,
})

app = flask.Flask(__name__)

TOKEN_VALIDITY = datetime.timedelta(hours=2)

def main():
    unset_vars = [name for name in ENV_VAR_NAMES if not os.environ.get(name)]
    if unset_vars:
        raise ValueError(f"Environment variables {*unset_vars,} not set")
    app.config["SECURITY_TOKEN_MAX_AGE"]=2 * (HOURS := 3600)
    app.config["SECRET_KEY"] = b64decode(os.environ.get("FLASK_SECRET_KEY"))
    app.config["SECURITY_PASSWORD_HASH"] = "argon2"
    client = pymongo.MongoClient(f"mongodb://{os.environ.get('MONGO_USERNAME')}:{os.environ.get('MONGO_PASSWORD')}@{os.environ.get('MONGO_HOSTNAME')}")
    db = client["db"]
    dbg_option = None
    match os.environ.get("DEBUG").lower():
        case "1":
            dbg_option = True
        case "0":
            dbg_option = False
        case "y":
            dbg_option = True
        case "n":
            dbg_option = False
        case "yes":
            dbg_option = True
        case "no":
            dbg_option = False
        case "true":
            dbg_option = True
        case "false":
            dbg_option = False
        case _:
            raise ValueError("DEBUG environment variable must be set to a boolean value")
    app.run(host="0.0.0.0", port=5000, debug=dbg_option)

@app.route("/api/login", methods=["POST"])
def login():
    """Logs in a user and returns a JWT token"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if not data["username"]:
        return jsonify({"error": "No username provided"}), 400
    if not data["password"]:
        return jsonify({"error": "No password provided"}), 400
    user = db.users.find_one({"username": data["username"]})
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not Hasher.verify(user["password"], data["password"]):
        return jsonify({"error": "Incorrect password"}), 401
    return jsonify({
        "token": jwt.encode(
            {
                "username": data["username"],
                "exp": datetime.datetime.now()+TOKEN_VALIDITY,
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        ),
    }), 200

if __name__ == "__main__":
    main()