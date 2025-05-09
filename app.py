from flask import Flask, request, jsonify, render_template
import pandas as pd
import re
import math
from urllib.parse import urlparse

# Initialize the Flask app
app = Flask(__name__)

# Load the phishing URL dataset
df = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv')

# Get phishing domains for domain-based detection
phishing_domains = set(df[df['label'] == 1]['Domain'])

# Define phishing detection methods

def is_phishing_by_domain(url):
    """
    Check if the URL domain matches any known phishing domain.
    """
    domain = urlparse(url).netloc
    return domain in phishing_domains

def is_phishing_by_url_length(url):
    """
    Check if the URL length is unusually long (more likely to be phishing).
    """
    return len(url) > 100

def is_phishing_by_subdomain(url):
    """
    Check for suspicious subdomains in the URL.
    """
    domain = urlparse(url).netloc
    subdomains = domain.split('.')
    suspicious_keywords = ['login', 'security', 'account', 'user']
    for subdomain in subdomains:
        if any(keyword in subdomain for keyword in suspicious_keywords):
            return True
    return len(subdomains) > 3

def calculate_entropy(url):
    """
    Calculate the entropy of the URL to check how random it is.
    """
    url = url.replace('http://', '').replace('https://', '')  # Remove scheme
    url = url.replace('.', '')  # Ignore dots for entropy calculation
    entropy = 0
    for char in set(url):
        p = url.count(char) / len(url)
        entropy -= p * math.log(p, 2)
    return entropy

def is_phishing_by_entropy(url):
    """
    Use the URL entropy to determine if it's suspicious.
    """
    entropy = calculate_entropy(url)
    return entropy > 4  # Threshold for high entropy

def is_phishing_by_keywords(url):
    """
    Check for suspicious keywords in the URL (e.g., login, account).
    """
    suspicious_keywords = ['login', 'secure', 'account', 'verify']
    return any(keyword in url for keyword in suspicious_keywords)

@app.route('/')
def index():
    """
    Render the index.html template for the homepage.
    """
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    """
    Endpoint to check if a URL is phishing, safe, or suspicious.
    """
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'result': 'Please provide a URL to scan'}), 400

    # Check using all detection methods
    phishing = is_phishing_by_domain(url) or is_phishing_by_url_length(url) or \
               is_phishing_by_subdomain(url) or is_phishing_by_entropy(url) or \
               is_phishing_by_keywords(url)

    # If it's phishing, return phishing detected
    if phishing:
        return jsonify({'result': 'Phishing detected', 'status': 'phishing'}), 200
    
    # If the URL doesn't pass any check and is too close to phishing behavior, flag as suspicious
    suspicious = not phishing and (
        len(url) > 80 or
        any(keyword in url for keyword in ['login', 'secure', 'account', 'verify'])
    )

    if suspicious:
        return jsonify({'result': 'Suspicious URL detected', 'status': 'suspicious'}), 200

    # If it's safe, return the safe result
    return jsonify({'result': 'This URL is safe', 'status': 'safe'}), 200

if __name__ == '__main__':
    # Start the Flask app
    app.run(debug=True)
