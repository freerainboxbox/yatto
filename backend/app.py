import flask
from flask import request, jsonify
import flask_security
import requests
import json
import os

app = flask.Flask(__name__)
app.config["SECURITY_TOKEN_MAX_AGE"]=2 * (HOURS := 3600)

def main():
    pass