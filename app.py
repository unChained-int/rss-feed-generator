from flask import Flask, send_file
import os
from fetch_and_cache import collect_all, build_and_write, CACHE_FILE

app = Flask(__name__)

@app.route("/")
def index():
    return "<h2>Security & Policy News Aggregator</h2><a href='/rss'>RSS Feed anzeigen</a>"

@app.route("/rss")
def rss():
    # Optional: Bei jedem Aufruf neu aggregieren (oder nur bei Bedarf)
    entries = collect_all()
    build_and_write(entries)
    return send_file(CACHE_FILE, mimetype="application/rss+xml")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
