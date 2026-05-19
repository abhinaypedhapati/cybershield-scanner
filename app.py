#!/usr/bin/env python3
"""
Vulnerability Scanner - Web Interface
Flask backend server
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from scanner import NetworkScanner, WebScanner
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Store scan history (in production, use a database)
scan_history = []

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/api/scan/network', methods=['POST'])
def scan_network():
    """API endpoint for network scan"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    try:
        scanner = NetworkScanner(target)
        results = scanner.scan()
        
        # Add to history
        scan_history.append({
            'id': len(scan_history) + 1,
            'type': 'network',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': results
        })
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/web', methods=['POST'])
def scan_web():
    """API endpoint for web scan"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Add protocol if missing
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        scanner = WebScanner(target)
        results = scanner.scan()
        
        # Add to history
        scan_history.append({
            'id': len(scan_history) + 1,
            'type': 'web',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': results
        })
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    return jsonify(scan_history[-10:])  # Last 10 scans

@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    print("=" * 50)
    print("🔒 Vulnerability Scanner Web Interface")
    print("=" * 50)
    print("Starting server at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)