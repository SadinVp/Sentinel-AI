from flask import Blueprint, render_template, request, jsonify
import joblib, html, re
from bs4 import BeautifulSoup

xss_bp = Blueprint('xss_bp', __name__)

# Load your XSS model and vectorizer
model = joblib.load('models/xss_rf_model.joblib')
vectorizer = joblib.load('models/xss_tfidf_vectorizer.joblib')

saved_reviews = []

def normalize_html(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    normalized_text = soup.prettify()
    return normalized_text.lower()

def decode_entities(text):
    return html.unescape(text)

def remove_whitespace(text):
    text = text.strip()
    text = re.sub(r'\s+', ' ', text)
    return text

def preprocess_input(html_text):
    normalized = normalize_html(html_text)
    decoded = decode_entities(normalized)
    cleaned = remove_whitespace(decoded)
    return cleaned


@xss_bp.route('/product/<name>')
def product_page(name):
    return render_template('product1.html', product_name=name)


@xss_bp.route('/detect_xss', methods=['POST'])
def detect_xss():
    data = request.json
    user_input = data.get('input', '')

    if not user_input:
        return jsonify({'error': 'No input provided'}), 400

    processed = preprocess_input(user_input)
    features = vectorizer.transform([processed])
    prediction = model.predict(features)[0]

    if prediction == 1:
        return jsonify({'xss_detected': True})
    else:
        saved_reviews.append(user_input)
        return jsonify({'xss_detected': False})


@xss_bp.route('/reviews', methods=['GET'])
def get_reviews():
    return jsonify({'reviews': saved_reviews})