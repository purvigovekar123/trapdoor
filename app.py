from flask import Flask, request, jsonify, send_from_directory

from detection.url_analyzer import analyze_url
from detection.message_analyzer import analyze_message


app = Flask(__name__)


@app.route("/")
def home():
    return send_from_directory("frontend", "index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No data provided"
        }), 400

    input_type = data.get("type")
    content = data.get("content")

    if not content:
        return jsonify({
            "error": "No content provided"
        }), 400

    if input_type == "url":
        result = analyze_url(content)

    elif input_type == "message":
        result = analyze_message(content)

    else:
        return jsonify({
            "error": "Invalid input type. Use 'url' or 'message'."
        }), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)