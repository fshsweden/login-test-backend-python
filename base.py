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
from flask_cors import CORS, cross_origin

api = Flask(__name__)
api.config["JWT_SECRET_KEY"] = "slemmig-torsk"
api.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=300) # 5 minutes
jwt = JWTManager(api)
CORS(api)

@api.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token 
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original respone
        return response

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

@api.route("/logout", methods=["POST"])
@cross_origin()
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

@api.route('/profile')
@cross_origin()
@jwt_required()
def my_profile():
    response_body = {
        "endpointname": "protected",
        "description" :"This endpoint is protected!",
        "about": "This is the profile!"
    }

    return response_body

if __name__ == "__main__":
  api.run(host="0.0.0.0", debug=True)