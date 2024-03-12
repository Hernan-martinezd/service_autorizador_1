import awsgi
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/monitor')
def monitor():
    return jsonify(status= 200, message= 'Echo: I\'m good')

def lambda_handler(event, context):
    return awsgi.response(app, event, context, base64_content_types={"image/png"})

