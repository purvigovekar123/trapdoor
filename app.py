from flask import Flask, render_template, jsonify

# Create the Flask application
app = Flask(__name__)


@app.route("/")
def home():
    # Shows the page at templates/index.html
    return render_template("index.html")


@app.route("/api/health")
def health():
    # A tiny test route that returns JSON, to prove the backend works
    return jsonify({"status": "ok", "app": "Trapdoor"})


if __name__ == "__main__":
    # debug=True auto-reloads the server when you save changes
    app.run(debug=True)
