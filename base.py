# ------------------------------------------------------------------------------
#
# Test with: 
#   1) curl -X POST http://localhost:5000/token -H 'Content-Type: application/json' -d '{"email":"test@test.se","password":"123"}'
#
#   response: {"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY1NDUwMzAxMSwianRpIjoiODA3YjY0MDktNDI2MS00OGZmLTkzODMtMGUxYmUwNGYzODBjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InRlc3RAdGVzdC5zZSIsIm5iZiI6MTY1NDUwMzAxMSwiZXhwIjoxNjU0NTAzMDQxfQ.dKX7xSsNb_UJ29FSUOrG56a398KnfrGvaI3SRt6KcaE"}
#
#   2) curl http://localhost:5000/profile -X GET -H "Authorization: Bearer <token here>"
#
# ------------------------------------------------------------------------------

import json
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager
from werkzeug.exceptions import HTTPException                               
from flask_cors import CORS, cross_origin

api = Flask(__name__)
api.config["JWT_SECRET_KEY"] = "slemmig-torsk"
api.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=15) # 10 minutes
jwt = JWTManager(api)
CORS(api)

#
# Generic Exception Handler returning JSON
#
@api.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response, e.code


#
# This is run after each request.
# It will check the JWT token, and if it is expired, it will generate a new one
# and return it in the response header.
#
@api.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = float(get_jwt()["exp"])
        #print(f"EXP_TIMESTAMP IS: {exp_timestamp}")
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now)
        #print(f"TARGET TIMESTAMP IS: {target_timestamp}")
        #print(f"DIFF IS target_timestamp - exp_timestamp: {target_timestamp - exp_timestamp}")
        if target_timestamp > exp_timestamp:
            #print("TOKEN EXPIRED - GENERATING NEW TOKEN!")
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                #print(f"data before adding access_token: {data}")
                data["access_token"] = access_token 
                #print(f"NEW TOKEN IS: {access_token}")
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response


#
# Login endpoint handler
#
@api.route('/login', methods=["POST"])
@cross_origin()
def login():
    
    # Really simple authorization!
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if email != "test@test.se" or password != "123":
        return {"msg": "Wrong email or password"}, 401

    access_token = create_access_token(identity=email)
    response = {"access_token":access_token}
    return response

#
# Logout endpoint handler
#
@api.route("/logout", methods=["POST"])
@cross_origin()
def logout():
    response_body = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response_body)
    return response_body, 200

#
# Profile endpoint handler (protected)
#
@api.route('/profile')
@cross_origin()
@jwt_required()
def my_profile():
    response_body = {
        "endpointname": "profile",
        "description" :"/profile",
        "about": "This is the profile!"
    }

    return response_body, 200

#
# Status endpoint handler (protected)
#
@api.route('/status')
@cross_origin()
@jwt_required()
def status_quo():
    response_body = {
        "endpointname": "status",
        "description" :"/status",
        "about": "Quo!"
    }
    return response_body, 200

#
# Main
#
if __name__ == "__main__":
  api.run(host="0.0.0.0", port=5001, debug=True)
