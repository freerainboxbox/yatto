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

ENV_VAR_NAMES = (
    "GOOGLE_MAPS_API_KEY",
    "MONGO_HOSTNAME",
    "MONGO_USERNAME",
    "MONGO_PASSWORD",
    "FLASK_SECRET_KEY",
    "DEBUG",
)


class TSPMode(Enum):
    """TSP mode constants"""

    VANILLA = 0
    START_CONSTRAINT = 1
    START_END_CONSTRAINT = 2
    SHORTEST_OVERALL = 3


class TransitMode(Enum):
    """Transit mode constants"""

    DRIVING = "driving"
    WALKING = "walking"
    BICYCLING = "bicycling"


# According to https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
Hasher = argon2.PasswordHasher().from_parameters(
    {
        "time_cost": 2,
        "memory_cost": 19 * (MiB := 1024),
        "parallelism": 2,
        "hash_len": 32,
        "salt_len": 16,
        "encoding": "utf-8",
        "type": argon2.Type.ID,
    }
)

app = flask.Flask(__name__)

TOKEN_VALIDITY = datetime.timedelta(hours=2)

db = None


def main():
    """Starts the API server"""
    unset_vars = [name for name in ENV_VAR_NAMES if not os.environ.get(name)]
    if unset_vars:
        raise ValueError(f"Environment variables {*unset_vars,} not set")
    app.config["SECRET_KEY"] = b64decode(os.environ.get("FLASK_SECRET_KEY"))
    client = pymongo.MongoClient(
        f"mongodb://{os.environ.get('MONGO_USERNAME')}:{os.environ.get('MONGO_PASSWORD')}@{os.environ.get('MONGO_HOSTNAME')}"
    )
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
            raise ValueError(
                "DEBUG environment variable must be set to a boolean value"
            )
    app.run(host="0.0.0.0", port=5000, debug=dbg_option)


def token_auth(func: callable):
    """Decorator for token authentication"""

    def wrapper(*args, **kwargs):
        if not request.headers.get("Authorization"):
            return jsonify({"error": "No authorization header provided"}), 401
        authoritative_user = None
        try:
            authoritative_user = jwt.decode(
                request.headers["Authorization"],
                app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.exceptions.InvalidSignatureError:
            return jsonify({"error": "Invalid token"}), 401
        return func(username=authoritative_user, *args, **kwargs)

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
    return (
        jsonify(
            {
                "token": jwt.encode(
                    {
                        "username": data["username"],
                        "exp": datetime.datetime.now() + TOKEN_VALIDITY,
                    },
                    app.config["SECRET_KEY"],
                    algorithm="HS256",
                ),
            }
        ),
        200,
    )


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
        return (
            jsonify(
                {
                    "error": "Email address is unreachable, double-check that it is valid."
                }
            ),
            400,
        )
    if db.users.find_one({"username": data["username"]}):
        return jsonify({"error": "User already exists"}), 409
    db.users.insert_one(
        {
            "username": data["username"],
            "password": Hasher.hash(data["password"]),
        }
    )
    return jsonify({"error": None}), 200


def simple_distance_matrix(
    client: googlemaps.Client, waypoints: list[str], transit_mode: TransitMode
) -> list[list[int]]:
    """Returns a simple distance (time) matrix for the given waypoints,
    with each cell containing time in seconds.

    Input:
    - client: A Google Maps API client object
    - waypoints: A list of Place IDs
    - transit_mode: One of the transit mode constants
    """
    waypoints = ["place_id:" + place_id for place_id in waypoints]
    response = client.distance_matrix(
        waypoints,
        waypoints,
        mode=transit_mode.value,
    )
    # Extract the distance matrix (as values of time)
    # (origin points)
    rows = [row["elements"] for row in response["rows"]]
    # (origin, destination)
    matrix = [[column["duration"]["value"] for column in row] for row in rows]
    return matrix


def optimize_simple_matrix(matrix: list[list[int]]) -> dict:
    """Optimizes a route based on the given distance matrix.

    Input:
    - matrix: A distance matrix (time in seconds) for the waypoints

    Output:
    - optimized_order: A list of indices of the waypoints in optimized order
    - time: The time taken to complete the route"""
    manager = pywrapcp.RoutingIndexManager(len(matrix), 1, 0)
    routing = pywrapcp.RoutingModel(manager)
    callback_index = routing.RegisterTransitCallback(lambda i, j: matrix[i][j])
    routing.SetArcCostEvaluatorOfAllVehicles(callback_index)
    search_parameters = pywrapcp.DefaultRoutingSearchParameters()
    search_parameters.first_solution_strategy = (
        routing_enums_pb2.FirstSolutionStrategy.PATH_CHEAPEST_ARC
    )
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
def optimize(username):
    """Optimizes a route based on the given parameters.

    Input:
        - trip_id (str): The ID of the trip to optimize, base62 (PUT only)
        - waypoints (str[]): A list of Place IDs (should NOT have the "placeid:" prefix)
        If the mode is well-ordered, the first and last elements
        of the list are the start and end points respectively.
        - tsp_mode (TSPMode): One of the TSP mode constants
        - transit_mode (TransitMode): One of the transit mode constants

    Output:
        - error (str): nullable
        - optimized_order (int[]): A list of indices of the waypoints in optimized order
        - time (int): The time taken to complete the route
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
        matrix = simple_distance_matrix(
            client, waypoints, TransitMode(data["transit_mode"])
        )
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
                    return (
                        jsonify({"optimized_order": [0, 1], "time": matrix[0][1]}),
                        200,
                    )
                case 3:
                    return (
                        jsonify(
                            {
                                "optimized_order": [0, 1, 2],
                                "time": matrix[0][1] + matrix[1][2],
                            }
                        ),
                        200,
                    )
                case _:
                    pass

            # Construct additional node v at start such that:
            # - dist(nth node -> v) = 0
            # - dist(v -> 0th node) = 0
            # - dist(v -> all other nodes) = inf
            # - dist(all other nodes -> v) = inf
            # - dist(v -> v) = 0
            n = len(matrix) + 1
            v = 0
            matrix = np.array(matrix)
            matrix = np.insert(matrix, 0, INFINITY, axis=0)
            matrix = np.insert(matrix, 0, INFINITY, axis=1)
            matrix[v][v] = 0
            matrix[v][1] = 0
            matrix[n][v] = 0

            # Optimize modified problem
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
            try:
                solution = optimize_simple_matrix(matrix.tolist())
            except RuntimeError as e:
                return jsonify({"error": e}), 400
            # Remove both instances of v from solution
            solution["optimized_order"] = solution["optimized_order"][1:-1]
        case _:
            return jsonify({"error": "Invalid TSP mode"}), 400
    solution["error"] = None
    code = 200
    if request.method() == "PUT":
        # Construct list of waypoints in optimized order, including duplicate start if vanilla
        waypoints = [waypoints[i] for i in solution["optimized_order"]]
        # Check that trip belongs to user using username field in database
        owner = db.trips.find_one({"_id": b62tooid(data["trip_id"])})["username"]
        if owner == username:
            db.trips.update_one(
                {"_id": b62tooid(data["trip_id"])},
                {
                    "$set": {
                        "waypoints": waypoints,
                        "optimized": True,
                        "optimization_type": tsp_mode.value,
                        "transit_mode": data["transit_mode"],
                        "time": datetime.timedelta(seconds=solution["time"]),
                        "modified_at": datetime.datetime.now(),
                    }
                },
            )
        else:
            solution["error"] = "Trip does not belong to user"
    return jsonify(solution), code


@app.route("/api/save_trip", methods=["POST", "PUT"])
@token_auth
def save_trip(username):
    """Saves a trip to the database. May or may not contain the optimized route.
    Input:
        - trip_id (str): The ID of the trip to save, base62 (PUT only)
        - name (str): The name of the trip (optional if PUT, does not update if not provided)
        - waypoints (str[]): A list of Place IDs (order-dependent)
        - optimized (bool): Whether the waypoints are in optimized order
        - optimization_type (TSPMode): Must be specified if optimized is true
        - transit_mode (TransitMode): Must be specified if optimized is true
        - time (int): The time taken to complete the route

    Output:
        - error (str): nullable
        - trip_id (str): The ID of the saved trip, base62
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if request.method() == "POST":
        if not data.get("name"):
            return jsonify({"error": "No name provided"}), 400
        if db.trips.find_one({"username": username, "name": data["name"]}):
            return jsonify({"error": "Duplicate trip name"}), 409
    if request.method() == "PUT":
        if not data.get("trip_id"):
            return jsonify({"error": "No trip ID provided for PUT"}), 400
        if not db.trips.find_one({"_id": b62tooid(data["trip_id"])}):
            return jsonify({"error": "Trip not found"}), 404
        if db.trips.find_one(
            {
                "username": username,
                "name": data["name"],
                "_id": {"$ne": b62tooid(data["trip_id"])},
            }
        ):
            return jsonify({"error": "Duplicate trip name"}), 409
    if not data.get("waypoints"):
        return jsonify({"error": "No waypoints provided"}), 400
    if not data.get("optimized"):
        return jsonify({"error": "No optimization status provided"}), 400
    optimization_type = None
    transit_mode = None
    if data.get("optimized"):
        if not data.get("optimization_type"):
            return jsonify({"error": "No optimization type provided"}), 400
        try:
            optimization_type = TSPMode(int(data["optimization_type"]))
        except ValueError as e:
            return jsonify({"error": e}), 400
        if not data.get("transit_mode"):
            return jsonify({"error": "No transit mode provided"}), 400
        try:
            transit_mode = TransitMode(data["transit_mode"])
        except ValueError as e:
            return jsonify({"error": e}), 400
    if not data.get("time"):
        return jsonify({"error": "No time provided"}), 400
    if not isinstance(data["waypoints"], list):
        return jsonify({"error": "Waypoints must be a list"}), 400
    if not isinstance(data["optimized"], bool):
        return jsonify({"error": "Optimization status must be a boolean"}), 400
    if not isinstance(data["time"], int):
        return jsonify({"error": "Time must be an integer"}), 400
    if request.method() == "POST":
        trip_id = oidtob62(
            db.trips.insert_one(
                {
                    "username": username,
                    "name": data["name"],
                    "waypoints": data["waypoints"],
                    "optimized": data["optimized"],
                    "optimization_type": optimization_type.value
                    if optimization_type
                    else None,
                    "transit_mode": transit_mode.value if transit_mode else None,
                    "time": datetime.timedelta(seconds=data["time"]),
                    "modified_at": datetime.datetime.now(),
                }
            ).inserted_id
        )
    else:
        trip_id = data["trip_id"]
        db.trips.update_one(
            {"_id": b62tooid(trip_id)},
            {
                "$set": {
                    "username": username,
                    "name": data["name"],
                    "waypoints": data["waypoints"],
                    "optimized": data["optimized"],
                    "optimization_type": optimization_type.value
                    if optimization_type
                    else None,
                    "transit_mode": transit_mode.value if transit_mode else None,
                    "time": datetime.timedelta(seconds=data["time"]),
                    "modified_at": datetime.datetime.now(),
                }
            },
        )
    return jsonify({"error": None, "trip_id": trip_id}), 200


@app.route("/api/delete_trip", methods=["DELETE"])
@token_auth
def delete_trip(username):
    """Deletes a trip from the database.
    Input:
        - trip_id (str): The ID of the trip to delete, base62

    Output:
        - error (str): nullable
    """
    data = request.get_json()
    trip_found = db.trips.find_one({"_id": b62tooid(data["trip_id"])})
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if not data.get("trip_id"):
        return jsonify({"error": "No trip ID provided"}), 400
    if not trip_found:
        return jsonify({"error": "Trip not found"}), 404
    if trip_found["username"] != username:
        return jsonify({"error": "Trip does not belong to user"}), 401
    return jsonify({"error": None}), 200


@app.route("/api/get_trips", methods=["GET"])
@token_auth
def get_trips(username):
    """Get listable trips belonging to a user, at a glance.

    Input:
        - query (str): A query string to filter trips by name (optional)
        - total (int): The total number of trips to return (optional)
        - offset (int): The number of trips to skip (optional)

    Output:
        - error (str): nullable
        - trips (dict[]): A list of {
            trip_id (str, base62),
            name (str),
            optimized (bool),
            optimization_type (TSPMode, nullable),
            transit_mode (TransitMode, nullable),
            time (timedelta, seconds),
            modified_at (datetime, UNIX seconds),
        }

    Trips are selected by closeness to query string (if applicable),
    then sorted by most recently modified.
    """
    data = request.get_json()
    if not data.get("query"):
        data["query"] = ""
    if not data.get("total"):
        data["total"] = 0
    if not data.get("offset"):
        data["offset"] = 0
    pipeline = [
        {"$match": {"username": username}},
        {"$sort": {"score": {"$meta": "textScore"}}},
        {"$skip": data["offset"]},
        {"$limit": data["total"]},
        {"$sort": {"modified_at": -1}},
        {"$match": {"name": {"$regex": data["query"], "$options": "i"}}},
        {
            "$project": {
                "trip_id": 1,
                "name": 1,
                "optimized": 1,
                "optimization_type": 1,
                "transit_mode": 1,
                "time": 1,
                "modified_at": 1,
            }
        },
    ]
    trips = list(db.trips.aggregate(pipeline))
    for trip in trips:
        trip["trip_id"] = oidtob62(trip["trip_id"])
        trip["time"] = trip["time"].total_seconds()
        trip["modified_at"] = trip["modified_at"].timestamp()
    try:
        return (
            jsonify(
                {
                    "error": None,
                    "trips": trips,
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": e}), 500


@app.route("/api/get_trip", methods=["GET"])
@token_auth
def get_trip(username):
    """Get specific trip information.
    Input:
        - trip_id (str): The ID of the trip to get, base62

    Output:
        - error (str): nullable
        - trip (dict):
            - trip_id (str)
            - name (str)
            - waypoints (str[])
            - optimized (bool)
            - optimization_type (TSPMode, nullable)
            - transit_mode (TransitMode, nullable)
            - time (timedelta, seconds)
            - modified_at (datetime, UNIX seconds)
    """
    data = request.get_json()
    if not data.get("trip_id"):
        return jsonify({"error": "No trip ID provided"}), 400
    trip_found = db.trips.find_one({"_id": b62tooid(data["trip_id"])})
    if not trip_found:
        return jsonify({"error": "Trip not found"}), 404
    if trip_found["username"] != username:
        return jsonify({"error": "Trip does not belong to user"}), 401
    trip_found["trip_id"] = oidtob62(trip_found["trip_id"])
    trip_found["time"] = trip_found["time"].total_seconds()
    trip_found["modified_at"] = trip_found["modified_at"].timestamp()
    return jsonify({"error": None, "trip": trip_found}), 200


def place_id_to_plus_code(client: googlemaps.Client, place_id: str) -> str:
    """Converts a Place ID to a plus code.

    Input:
    - client: A Google Maps API client object
    - place_id: A Place ID

    Output:
    - plus_code: A plus code
    """
    return client.place(place_id)["plus_code"]["global_code"]


def place_id_to_name(client: googlemaps.Client, place_id: str) -> str:
    """Converts a Place ID to a name.

    Input:
    - client: A Google Maps API client object
    - place_id: A Place ID

    Output:
    - name: A name
    """
    return client.place(place_id)["name"]


@app.route("/api/map_url", methods=["GET"])
@token_auth
def map_url(username):
    """Get a URL to a map of the given waypoints, allowing user to navigate.
    Input:
        - trip_id (str): The ID of the trip to get, base62

    Output:
        - error (str): nullable
        - url (str): The URL to the map

    This endpoint will only return a URL if the user owns the trip and the trip is already optimized.
    """
    data = request.get_json()
    if not data.get("trip_id"):
        return jsonify({"error": "No trip ID provided"}), 400
    trip_found = db.trips.find_one({"_id": b62tooid(data["trip_id"])})
    if not trip_found:
        return jsonify({"error": "Trip not found"}), 404
    if trip_found["username"] != username:
        return jsonify({"error": "Trip does not belong to user"}), 401
    if not trip_found["optimized"]:
        return jsonify({"error": "Trip must be optimized"}), 405
    client = googlemaps.Client(key=os.environ.get("GOOGLE_MAPS_API_KEY"))
    origin_name = place_id_to_name(client, trip_found["waypoints"][0])
    destination_name = place_id_to_name(client, trip_found["waypoints"][-1])
    # Get plus codes for all intermediate waypoints [1:-2]
    # FIXME: This works, but plus codes are not user friendly.
    # We should attempt to convert to names and check that they resolve to the same placeid,
    # and use plus codes as a fallback.
    intermediate_plus_codes = [
        place_id_to_plus_code(client, place_id)
        for place_id in trip_found["waypoints"][1:-2]
    ]
    url = (
        "https://www.google.com/maps/dir/?api=1&origin="
        + requests.utils.quote(origin_name)
        + "&destination="
        + requests.utils.quote(destination_name)
        + "&waypoints="
        + "%7C".join(intermediate_plus_codes)
    )
    return jsonify({"error": None, "url": url}), 200

if __name__ == "__main__":
    main()
