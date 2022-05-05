# ------------------------------------------------------------------------------
#
# Test with: curl -X POST http://192.168.1.67:5000/token -H 'Content-Type: application/json' -d '{"login":"my_login","password":"my_password"}'
#
# ------------------------------------------------------------------------------

import json
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager
from flask_cors import CORS

api = Flask(__name__)
api.config["JWT_SECRET_KEY"] = "slemmig-torsk"
api.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=30)
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

@api.route('/token', methods=["POST"])
def create_token():
    print(request.headers)
    email = request.json.get("email", None)
    print("email: ", email)
    password = request.json.get("password", None)
    print("password: ", password)
    if email != "test@test.se" or password != "123":
        return {"msg": "Wrong email or password"}, 401

    access_token = create_access_token(identity=email)
    response = {"access_token":access_token}
    return response

@api.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

@api.route('/profile')
@jwt_required()
def my_profile():
    response_body = {
        "name": "Nagato",
        "about" :"Hello! I'm a full stack developer that loves python and javascript"
    }

    return response_body

if __name__ == "__main__":
  api.run(host="0.0.0.0")