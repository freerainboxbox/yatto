import os
import datetime
from base64 import b64decode
import base62

from enum import Enum
from sys import maxsize as INFINITY

import flask
from flask import request, jsonify
import requests
import json
import argon2
import pymongo
from bson.objectid import ObjectId
oidtob62 = lambda oid: base62.encodebytes(oid.binary)
b62tooid = lambda b62: ObjectId(base62.decodebytes(b62).hex())
import jwt
import email_validator as eml_vldtr
from ortools.constraint_solver import pywrapcp, routing_enums_pb2
import googlemaps
import numpy as np


ENV_VAR_NAMES = ("GOOGLE_MAPS_API_KEY", "MONGO_HOSTNAME", "MONGO_USERNAME", "MONGO_PASSWORD", "FLASK_SECRET_KEY", "DEBUG")

class TSPMode(Enum):
    """TSP mode constants"""
    VANILLA = 0
    START_CONSTRAINT = 1
    START_END_CONSTRAINT = 2
    SHORTEST_OVERALL = 3

class TransitMode(Enum):
    """Transit mode constants"""
    DRIVING = 'driving'
    WALKING = 'walking'
    BICYCLING = 'bicycling'

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

db = None

def main():
    """Starts the API server"""
    unset_vars = [name for name in ENV_VAR_NAMES if not os.environ.get(name)]
    if unset_vars:
        raise ValueError(f"Environment variables {*unset_vars,} not set")
    app.config["SECRET_KEY"] = b64decode(os.environ.get("FLASK_SECRET_KEY"))
    client = pymongo.MongoClient(f"mongodb://{os.environ.get('MONGO_USERNAME')}:{os.environ.get('MONGO_PASSWORD')}@{os.environ.get('MONGO_HOSTNAME')}")
    global db
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

def token_auth(func: callable):
    """Decorator for token authentication"""
    def wrapper(*args, **kwargs):
        if not request.headers.get("Authorization"):
            return jsonify({"error": "No authorization header provided"}), 401
        try:
            jwt.decode(
                request.headers["Authorization"],
                app.config["SECRET_KEY"],
                algorithms=["HS256"],
                
            )
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.exceptions.InvalidSignatureError:
            return jsonify({"error": "Invalid token"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route("/api/login", methods=["POST"])
def login():
    """Logs in a user and returns a JWT token"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if not data.get("username"):
        return jsonify({"error": "No username provided"}), 400
    if not data.get("password"):
        return jsonify({"error": "No password provided"}), 400
    user_found = db.users.find_one({"username": data["username"]})
    if not user_found:
        return jsonify({"error": "User not found"}), 404
    if not Hasher.verify(user_found["password"], data["password"]):
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

@app.route("/api/register", methods=["POST"])
def register():
    """Attempts to register a username (valid email) and password pair"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if not data["username"]:
        return jsonify({"error": "No username provided"}), 400
    if not data["password"]:
        return jsonify({"error": "No password provided"}), 400
    try:
        eml_vldtr.validate_email(data["username"], check_deliverability=False)
    except eml_vldtr.EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400
    try:
        eml_vldtr.validate_email(data["username"], check_deliverability=True)
    except eml_vldtr.EmailNotValidError:
        return jsonify({"error": "Unable to deliver to email address"}), 400
    if db.users.find_one({"username": data["username"]}):
        return jsonify({"error": "User already exists"}), 409
    db.users.insert_one({
        "username": data["username"],
        "password": Hasher.hash(data["password"]),
    })
    return jsonify({"error": None}), 200

def simple_distance_matrix(client: googlemaps.Client, waypoints: list[str], transit_mode: TransitMode) -> list[list[int]]:
    """Returns a simple distance (time) matrix for the given waypoints,
    with each cell containing time in seconds.

    Input:
    - client: A Google Maps API client object
    - waypoints: A list of Place IDs
    - transit_mode: One of the transit mode constants
    """
    waypoints = ["place_id:"+place_id for place_id in waypoints]
    response = client.distance_matrix(
        waypoints,
        waypoints,
        mode=transit_mode.value,
    )
    # Extract the distance matrix (as values of time)
    # (origin points)
    rows = [row['elements'] for row in response['rows']]
    # (origin, destination)
    matrix = [[column['duration']['value'] for column in row] for row in rows]
    return matrix

def optimize_simple_matrix(matrix: list[list[int]]) -> dict:
    """Optimizes a route based on the given distance matrix."""
    manager = pywrapcp.RoutingIndexManager(len(matrix), 1, 0)
    routing = pywrapcp.RoutingModel(manager)
    callback_index = routing.RegisterTransitCallback(
        lambda i, j: matrix[i][j]
    )
    routing.SetArcCostEvaluatorOfAllVehicles(callback_index)
    search_parameters = pywrapcp.DefaultRoutingSearchParameters()
    search_parameters.first_solution_strategy = routing_enums_pb2.FirstSolutionStrategy.PATH_CHEAPEST_ARC
    solution = routing.SolveWithParameters(search_parameters)
    if not solution:
        raise RuntimeError("No solution found")
    # Get order as list of indices for waypoints (a permutation)
    optimized_order = []
    index = routing.Start(0)
    total_time = 0
    while not routing.IsEnd(index):
        prev = index
        index = solution.Value(routing.NextVar(index))
        total_time += routing.GetArcCostForVehicle(prev, index, 0)
        optimized_order.append(manager.IndexToNode(index))
    return {"optimized_order": optimized_order, "time": total_time}

@app.route("/api/optimize", methods=["GET", "PUT"])
@token_auth
def optimize():
    """Optimizes a route based on the given parameters.

    Input:
        - waypoints: A list of Place IDs
        If the mode is well-ordered, the first and last elements
        of the list are the start and end points respectively.
        - tsp_mode: One of the TSP mode constants
        - transit_mode: One of the transit mode constants
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if request.method() == "PUT":
        if not data.get("trip_id"):
            return jsonify({"error": "No trip ID provided for PUT"}), 400
        if not db.trips.find_one({"_id": b62tooid(data["trip_id"])}):
            return jsonify({"error": "Trip not found"}), 404
    if not data.get("waypoints"):
        return jsonify({"error": "No waypoints provided"}), 400
    if not data.get("tsp_mode"):
        return jsonify({"error": "No TSP mode provided"}), 400
    if not data.get("transit_mode"):
        return jsonify({"error": "No transit mode provided"}), 400
    tsp_mode = None
    try:
        tsp_mode = TSPMode(int(data["tsp_mode"]))
    except ValueError as e:
        return jsonify({"error": e}), 400
    waypoints = data["waypoints"]
    if not isinstance(waypoints, list):
        return jsonify({"error": "Waypoints must be a list"}), 400
    client = googlemaps.Client(key=os.environ.get("GOOGLE_MAPS_API_KEY"))
    matrix = None
    try:
        matrix = simple_distance_matrix(client, waypoints, TransitMode(data["transit_mode"]))
    except ValueError as e:
        return jsonify({"error": e}), 400
    solution = None
    match tsp_mode:
        case TSPMode.VANILLA:
            try:
                solution = optimize_simple_matrix(matrix)
            except RuntimeError as e:
                return jsonify({"error": e}), 400
        case TSPMode.START_CONSTRAINT:
            # Set all distances back to start as 0
            for row in matrix:
                row[0] = 0
            # Optimize modified problem
            solution = None
            try:
                solution = optimize_simple_matrix(matrix)
            except RuntimeError as e:
                return jsonify({"error": e}), 400
            solution["optimized_order"] = solution["optimized_order"][:-1]
        case TSPMode.START_END_CONSTRAINT:
            # Base Cases
            match len(matrix):
                case 1:
                    return jsonify({"optimized_order": [0], "time": 0}), 200
                case 2:
                    return jsonify({"optimized_order": [0, 1], "time": matrix[0][1]}), 200
                case 3:
                    return jsonify({"optimized_order": [0, 1, 2], "time": matrix[0][1] + matrix[1][2]}), 200
                case _:
                    pass

            # Construct additional node v at start such that:
            # - dist(nth node -> v) = 0
            # - dist(v -> 0th node) = 0
            # - dist(v -> all other nodes) = inf
            # - dist(all other nodes -> v) = inf
            # - dist(v -> v) = 0
            n = len(matrix)+1
            v = 0
            matrix = np.array(matrix)
            matrix = np.insert(matrix, 0, INFINITY, axis=0)
            matrix = np.insert(matrix, 0, INFINITY, axis=1)
            matrix[v][v] = 0
            matrix[v][1] = 0
            matrix[n][v] = 0

            # Optimize modified problem
            solution = None
            try:
                solution = optimize_simple_matrix(matrix.tolist())
            except RuntimeError as e:
                return jsonify({"error": e}), 400
            # Remove both instances of v from solution
            solution["optimized_order"] = solution["optimized_order"][1:-1]
        case TSPMode.SHORTEST_OVERALL:
            # Construct additional node v at start such that:
            # - dist(v -> all nodes) = 0
            # - dist(all nodes -> v) = 0
            matrix = np.array(matrix)
            matrix = np.insert(matrix, 0, 0, axis=0)
            matrix = np.insert(matrix, 0, 0, axis=1)

            # Optimize modified problem
            solution = None
            try:
                solution = optimize_simple_matrix(matrix.tolist())
            except RuntimeError as e:
                return jsonify({"error": e}), 400
            # Remove both instances of v from solution
            solution["optimized_order"] = solution["optimized_order"][1:-1]
        case _:
            return jsonify({"error": "Invalid TSP mode"}), 400
    if request.method() == "PUT":
        db.trips.update_one({"_id": b62tooid(data["trip_id"])},
            {"$set": {
                "optimized_order": solution["optimized_order"],
                "time": datetime.timedelta(seconds=solution["time"]),
            }}
        )
    return jsonify(solution), 200

@app.route("/api/save_trip", methods=["POST", "PUT"])
@token_auth
def save_trip():
    """Saves a trip to the database. May or may not contain the optimized route."""
    #TODO: Implment trip saving
    pass


if __name__ == "__main__":
    main()
