# ⚡ QWACH-Detecting-Malicious-QR-code-URL-using-AI

This project focuses on classifying URLs extracted from QR codes into malicious and legitimate categories using machine learning models. We propose a **Hybrid Stacked MLP model** that integrates multiple base models and a Multi-Layer Perceptron (MLP) as a meta-model.

## 📂 Dataset
- 🟠4002 QR Code Images: 2001 malicious & 2001 legitimate.
- 🔵Additional URL Dataset: 10,001 URLs.
- 🟢Total URLs: 14,013.

## 🚀 Features Extracted (16 total) 

- ✅ Address-Based Features
- ✅ JavaScript-Based Features
- ✅ Domain-Based Features

---

## 📂 Data Splitting
-  80% for Training
-  20% for Validation
-  10% for Testing

---
## 📊 Machine Learning Models Tested

✔ Decision Tree

✔ k-Nearest Neighbors (KNN)

✔ Logistic Regression

✔ Gradient Boosting

✔ Random Forest

✔ SVM

✔ Naive Bayes

---
## 🔮 Proposed Model: Hybrid Stacked MLP

- 🟠**Base Models**: Decision Tree, KNN, Logistic Regression, Gradient Boosting, Random Forest

- 🔵**Meta-Model**: Multi-Layer Perceptron (MLP) with a pyramid structure:

- 🟢**Hidden layers**: 512  → 256 → 128 → 64 → 1

---

## 📈 Evaluation Metrics

- 1️⃣ Accuracy : 91.30%
- 2️⃣ Precision : 95.15%
- 3️⃣ Recall : 86.49%
- 4️⃣ F1 Score : 90.61%
