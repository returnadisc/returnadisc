from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "HOME WORKS"

@app.route("/test")
def test():
    return "TEST WORKS"
