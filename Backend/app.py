from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
import joblib
import re
import socket
import whois
import datetime
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
from flask_cors import CORS

import tensorflow as tf
from urllib.parse import urlparse
import tensorflow as tf
from tensorflow.python.client._pywrap_tf_session import * 

app = Flask(__name__)
CORS(app)
# Load pre-trained models (adjust paths as needed)
base_model_names = ['rf', 'gb', 'lr', 'knn', 'dt']
base_models = {name: joblib.load(f'models\\{name}_stacking2.pkl') for name in base_model_names}

# Load meta-model
meta_model = tf.keras.models.load_model(r"meta_model2.keras")
print("Model loaded successfully.")

# Feature extraction function
def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    feature_values = [
        1 if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url) else 0,  # Have_IP
        1 if '@' in url else 0,  # Have_At
        len(url),  # URL_Length
        len(parsed_url.path.strip("/").split('/')) if parsed_url.path else 0,  # URL_Depth
        1 if '//' in parsed_url.path else 0,  # Redirection
        1 if parsed_url.scheme == "https" else 0,  # HTTPS_Domain
        1 if len(domain) < 10 else 0,  # TinyURL
        1 if '-' in domain else 0,  # Prefix/Suffix
        check_dns(domain),  # DNS_Record
        get_web_traffic(domain),  # Web_Traffic
        get_domain_age(domain),  # Domain_Age
        get_domain_end(domain),  # Domain_End
        1 if "<iframe" in url.lower() else 0,  # iFrame
        1 if "onmouseover" in url.lower() else 0,  # Mouse_Over
        1 if "event.button==2" in url.lower() else 0,  # Right_Click
        1 if "redirect" in domain else 0  # Web_Forwards
    ]

    feature_names = [
        "Have_IP", "Have_At", "URL_Length", "URL_Depth", "Redirection",
        "https_Domain", "TinyURL", "Prefix/Suffix", "DNS_Record", "Web_Traffic",
        "Domain_Age", "Domain_End", "iFrame", "Mouse_Over", "Right_Click", "Web_Forwards"
    ]

    return pd.DataFrame([feature_values], columns=feature_names)

# Helper functions
def check_dns(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except socket.gaierror:
        return 0

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return -1
        return (datetime.datetime.now() - creation_date).days // 30
    except:
        return -1

def get_domain_end(domain):
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if not expiration_date:
            return -1
        return (expiration_date - datetime.datetime.now()).days // 30
    except:
        return -1

def get_web_traffic(domain):
    # Placeholder: Replace this with real web traffic data lookup
    return 1 if "example.com" in domain else 0

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400
    print(type(data))
    url = data["url"]
    print(type(url))
    features = extract_features(url)

    try:
        # Get predictions from base models
        base_preds = np.column_stack([
            model.predict(features).reshape(-1, 1) for model in base_models.values()
        ])

        # Meta-model prediction
        final_pred = (meta_model.predict(base_preds) > 0.5).astype(int)

        result = "Malicious" if final_pred[0][0] == 1 else "Legitimate"
        return jsonify({"url": url, "prediction": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



from pyzbar.pyzbar import decode
from PIL import Image
import base64
import io

@app.route('/predict/qr', methods=['POST'])
def decode_qr_and_predict():
    data = request.get_json()
    if not data or "image" not in data:
        return jsonify({"error": "No image provided"}), 400

    try:
        # Decode base64 image
        image_data = data['image'].split(",")[1]  # Remove data:image/... prefix
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))

        decoded_objects = decode(image)
        if not decoded_objects:
            return jsonify({"error": "No QR code found"}), 400

        text = decoded_objects[0].data.decode('utf-8')
        print(f"Decoded QR text: {text}")

        # Optional: Check if it's a URL and run prediction
        if text.startswith("http"):
            features = extract_features(text)
            base_preds = np.column_stack([
                model.predict(features).reshape(-1, 1) for model in base_models.values()
            ])
            final_pred = (meta_model.predict(base_preds) > 0.5).astype(int)
            result = "Malicious" if final_pred[0][0] == 1 else "Legitimate"
            return jsonify({"text": text, "prediction": result})
        else:
            return jsonify({"text": text, "prediction": "Not a URL"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# import cv2
# import numpy as np
# from flask import Flask, request, jsonify
# from PIL import Image
# import base64
# import io

# @app.route('/predict/qr', methods=['POST'])
# def decode_qr_and_predict():
#     data = request.get_json()
#     if not data or "image" not in data:
#         return jsonify({"error": "No image provided"}), 400

#     try:
#         # Decode base64 image
#         image_data = data['image'].split(",")[1]  # Remove data:image/... prefix
#         image_bytes = base64.b64decode(image_data)
#         image = Image.open(io.BytesIO(image_bytes))

#         # Convert the PIL image to an OpenCV format (numpy array)
#         open_cv_image = np.array(image)
#         # Convert the image from RGB to BGR (OpenCV uses BGR by default)
#         open_cv_image = open_cv_image[:, :, ::-1].copy()

#         # Initialize the QRCode detector
#         qr_code_detector = cv2.QRCodeDetector()

#         # Detect and decode the QR code
#         data, pts, qr_code = qr_code_detector(open_cv_image)

#         if data is None:
#             return jsonify({"error": "No QR code found"}), 400

#         print(f"Decoded QR text: {data}")

#         # Optional: Check if it's a URL and run prediction
#         if data.startswith("http"):
#             features = extract_features(data)
#             base_preds = np.column_stack([model.predict(features).reshape(-1, 1) for model in base_models.values()])
#             final_pred = (meta_model.predict(base_preds) > 0.5).astype(int)
#             result = "Malicious" if final_pred[0][0] == 1 else "Legitimate"
#             return jsonify({"text": data, "prediction": result})
#         else:
#             return jsonify({"text": data, "prediction": "Not a URL"})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

