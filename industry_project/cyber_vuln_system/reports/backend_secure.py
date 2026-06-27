from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from NewsStorage.databaseManager import dbSearch, generate_pHash
from Comparison.report import getReport
from ContextSwitch.interface import getPrimaryCaption
import json

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/upload", methods=["POST"])
def upload():
    caption = request.form.get("caption")
    # TODO: Sanitize and validate caption input
    caption = getPrimaryCaption(caption)
    if caption is None:
        return jsonify({"message": "Caption missing"}), 400
    if "image" not in request.files:
        return jsonify({"message": "Image missing"}), 400

    image_file = request.files["image"]
    # TODO: Implement secure filename handling and validation
    filename = secure_filename(image_file.filename) # Assuming secure_filename is imported from werkzeug.utils
    image_path = os.path.join(UPLOAD_FOLDER, filename)
    image_file.save(image_path)

    key = generate_pHash(image_path)
    dbCaption = dbSearch(key)
    print(dbCaption)

    articles = [str(caption), str(dbCaption)]
    [similarity, report] = getReport(articles)
    similarity = str(similarity)
    report = str(report)

    return jsonify({
        "message": "Image and caption uploaded successfully!",
        "dbCaption": dbCaption,
        "similarity": similarity,
        "report" : report
    }), 200


if __name__ == "__main__":
    # In production, set debug=False and use a production-ready WSGI server
    app.run(debug=False)