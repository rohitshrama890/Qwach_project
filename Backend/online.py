from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
import joblib
import re
import socket
import whois
import datetime
import os
import tldextract
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import requests
from tensorflow.keras.models import load_model, Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import Callback
from tensorflow.keras.models import save_model
from datetime import datetime
from sklearn.metrics import accuracy_score

from bs4 import BeautifulSoup

app = Flask(__name__)
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Paths
meta_model_path = r"Backend\meta_model2.keras"
# Load base models


def load_meta_model():
    if not os.path.exists(meta_model_path):
        raise FileNotFoundError(f"Model not found at: {meta_model_path}")
    return load_model(meta_model_path)

# -------- Base Model Trainers -------- #
def train_base_models(X, y):
    print(f"[{datetime.now()}] 🔄 Training base models...")
    models = {
        'rf': RandomForestClassifier(),
        'gb': GradientBoostingClassifier(),
        'lr': LogisticRegression(max_iter=1000),
        'knn': KNeighborsClassifier(),
        'dt': DecisionTreeClassifier()
    }
    trained_models = {}
    for name, model in models.items():
        model.fit(X, y)
        joblib.dump(model, f"Backend\\models\\{name}_online_stacking2.pkl")
        trained_models[name] = model
        print(f"[{datetime.now()}] ✅ {name.upper()} trained and saved.")
    return trained_models
def update_meta_model(base_preds, labels):
    print(f"[{datetime.now()}] 🔄 Updating meta-model (MLP)...")
    
    # Load existing model or initialize new one
    if os.path.exists(meta_model_path):
        meta_model = load_model(meta_model_path)
        print(f"[{datetime.now()}] 📥 Loaded existing meta-model.")
    else:
        meta_model = Sequential([
            Dense(256, activation='relu', input_shape=(base_preds.shape[1],)),
            Dense(128, activation='relu'),
            Dense(64, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        meta_model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])
        print(f"[{datetime.now()}] 🆕 Initialized new meta-model.")

    class TimestampLogger(Callback):
        def on_epoch_end(self, epoch, logs=None):
            print(f"[{datetime.now()}] 🧠 Epoch {epoch+1} done - loss: {logs['loss']:.4f} - acc: {logs['accuracy']:.4f}")

    # -------- Simulated Partial Fit -------- #
    meta_model.fit(
        base_preds,
        labels,
        epochs=1,             # Only 1 epoch to simulate partial update
        batch_size=8,
        verbose=0,
        callbacks=[TimestampLogger()],
        shuffle=False         # Important to simulate online learning
    )
    meta_model.save(meta_model_path)
    print(f"[{datetime.now()}] 💾 Meta-model updated and saved.")
    return meta_model

def extract_url_features(url):
    parsed_url = urlparse(url)
    domain_info = tldextract.extract(url)

    try:
        domain_whois = whois.whois(parsed_url.netloc)  # WHOIS Lookup
    except:
        domain_whois = None

    # 1️⃣ Basic URL Features
    features = {
        "Have_IP": bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc)),
        "Have_At": "@" in url,
        "URL_Length": len(url),
        "URL_Depth": url.count('/'),
        "Redirection": "//" in url[7:],
        "https_Domain": "https" in domain_info.domain,
        "TinyURL": any(short in url.lower() for short in ["bit.ly", "tinyurl", "goo.gl"]),
        "Prefix/Suffix": "-" in parsed_url.netloc
    }

    # 2️⃣ Domain-Based Features
    try:
        socket.gethostbyname(parsed_url.netloc)  # Check if DNS record exists
        features["DNS_Record"] = 1
    except:
        features["DNS_Record"] = 0

    try:
        alexa_rank = requests.get(f"https://www.alexa.com/siteinfo/{parsed_url.netloc}").status_code  # Check if site exists
        features["Web_Traffic"] = 1 if alexa_rank == 200 else 0
    except:
        features["Web_Traffic"] = 0

    # Domain Age & Expiry
    if domain_whois:
        try:
            domain_age = (domain_whois.creation_date[0] if isinstance(domain_whois.creation_date, list) else domain_whois.creation_date)
            domain_expiry = (domain_whois.expiration_date[0] if isinstance(domain_whois.expiration_date, list) else domain_whois.expiration_date)
            features["Domain_Age"] = (domain_expiry - domain_age).days if domain_age and domain_expiry else 0
            features["Domain_End"] = (domain_expiry - domain_age).days if domain_expiry else 0
        except:
            features["Domain_Age"], features["Domain_End"] = 0, 0
    else:
        features["Domain_Age"], features["Domain_End"] = 0, 0

    # 3️⃣ Web Content Features (if accessible)
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # iFrame Detection
        features["iFrame"] = 1 if "<iframe" in response.text else 0

        # Mouse Over Detection
        features["Mouse_Over"] = 1 if "onmouseover" in response.text else 0

        # Right Click Disabled
        features["Right_Click"] = 1 if "event.button==2" in response.text else 0

        # Web Forwarding Detection
        features["Web_Forwards"] = len(response.history) > 2  # If multiple redirects

    except:
        features["iFrame"], features["Mouse_Over"], features["Right_Click"], features["Web_Forwards"] = 0, 0, 0, 0

    return features
# @app.route('/train', methods=['POST'])
# def train():
#     try:
#         phishing = pd.read_csv("phishing_urls.csv").head(5)  # Only first 20 rows
#         phishing["label"] = 1  # Label phishing as 1

#         clean = pd.read_csv("final_cleaned_urls.csv").head(5) # Only first 20 rows
#         clean["label"] = 0  # Label clean as 0
#         # Ensure both datasets have a 'url' column
#         if 'url' not in phishing.columns or 'url' not in clean.columns:
#             return jsonify({"error": "Missing 'url' column in dataset"}), 400

#         df = pd.concat([phishing, clean], ignore_index=True)

#         all_features = []
#         all_labels = []

#         for _, row in df.iterrows():
#             try:
#                 features = extract_url_features(row['url'])
#                 all_features.append(list(features.values()))
#  # append feature row
#                 all_labels.append(row['label'])
#             except Exception as e:
#                 print(f"Skipping URL due to error: {row['url']} | Error: {e}")
#                 continue

#         X = pd.DataFrame(all_features, columns=list(features.keys()))

#         y = np.array(all_labels)

#         base_models = train_base_models(X, y)
#         base_preds = np.column_stack([model.predict(X) for model in base_models.values()])
#         update_meta_model(base_preds, y)

#         from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
#         meta_model = load_meta_model()
#         y_pred_meta = (meta_model.predict(base_preds) > 0.5).astype(int).flatten()

       

       

#         return jsonify({
#     "message": f"✅ Base and meta-models retrained at {datetime.now()}"
    
# })


#     except Exception as e:
#         return jsonify({"error": f"Training failed: {e}"}), 500
    






from sklearn.model_selection import train_test_split
from flask import jsonify
from datetime import datetime
import traceback
import os
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import accuracy_score

@app.route('/train', methods=['POST'])
def train():
    try:
        # Load and label data (ensure URLs column is named 'url')
        phishing = pd.read_csv(r"Backend\phishtank_urls.csv").head(5)
        phishing["label"] = 1

        clean = pd.read_csv(r"Backend\cleaned_urls.csv").head(5)
        clean["label"] = 0

        df = pd.concat([phishing, clean], ignore_index=True)

        # Ensure required columns are present
        if 'URL' not in df.columns or 'label' not in df.columns:
            raise ValueError("Required columns 'url' and 'label' not found in the dataset.")

        # Train/Test split
        df_train, df_test = train_test_split(df, test_size=0.2, stratify=df['label'], random_state=42)

        # Feature extraction for training
        X_train_features, y_train = [], []
        for _, row in df_train.iterrows():
            try:
                features = extract_url_features(row['URL'])  # your custom function
                X_train_features.append(list(features.values()))
                y_train.append(row['label'])
            except Exception as e:
                print(f"Skipping train URL: {row['URL']} | Error: {e}")

        if not X_train_features:
            raise ValueError("No valid training features were extracted.")

        X_train = pd.DataFrame(X_train_features, columns=list(features.keys()))
        y_train = np.array(y_train)

        # Feature extraction for testing
        X_test_features, y_test = [], []
        for _, row in df_test.iterrows():
            try:
                features = extract_url_features(row['URL'])
                X_test_features.append(list(features.values()))
                y_test.append(row['label'])
            except Exception as e:
                print(f"Skipping test URL: {row['URL']} | Error: {e}")

        if not X_test_features:
            raise ValueError("No valid testing features were extracted.")

        X_test = pd.DataFrame(X_test_features, columns=list(features.keys()))
        y_test = np.array(y_test)

        # Base model names
        base_model_names = ['rf', 'gb', 'lr', 'knn', 'dt']
        meta_model_path = r"Backend\meta_model2.keras"

        # Load old base models and predict
        old_preds = []
        for name in base_model_names:
            model_path = f"Backend\\models\\{name}_stacking2.pkl"
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Missing base model: {model_path}")
            model = joblib.load(model_path)
            old_preds.append(model.predict(X_test))
        old_preds = np.column_stack(old_preds)

        # Load old meta model if available
        old_acc = 0
        if os.path.exists(meta_model_path):
            existing_meta = load_model(meta_model_path)
            y_pred_old = (existing_meta.predict(old_preds) > 0.5).astype(int).flatten()
            old_acc = accuracy_score(y_test, y_pred_old)

        unique_labels = np.unique(y_train)
        if len(unique_labels) < 2:
            return jsonify({"error": f"Training data must have at least 2 classes. Found only {unique_labels}"}), 400
        print("1")
        # Train new base models and stacking model
        new_base_models = train_base_models(X_train, y_train)  # <- Your implementation
        new_preds = np.column_stack([model.predict(X_test) for model in new_base_models.values()])

        new_meta_model = update_meta_model(new_preds, y_test)  # <- Your implementation
        y_pred_new = (new_meta_model.predict(new_preds) > 0.5).astype(int).flatten()
        new_acc = accuracy_score(y_test, y_pred_new)

        # Save only if new accuracy is better
        if new_acc > old_acc:
            # for name, model in new_base_models.items():
            #     joblib.dump(model, f"{name}_stacking2.pkl")
            new_meta_model.save(meta_model_path)
            message = f"✅ Model updated. New Accuracy ({new_acc:.4f}) > Old Accuracy ({old_acc:.4f})"
        else:
            message = f"⚠️ Model NOT updated. New Accuracy ({new_acc:.4f}) <= Old Accuracy ({old_acc:.4f})"

        return jsonify({
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "message": message,
            "old_accuracy": round(old_acc, 4),
            "new_accuracy": round(new_acc, 4)
        })

    except Exception as e:
        # Print full traceback in terminal
        traceback.print_exc()
        return jsonify({"error": f"Training failed: {str(e)}"}), 500



# -------- Main -------- #
if __name__ == '__main__':
    app.run(debug=True)
