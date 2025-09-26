#===================#
# MAIN BACKEND FILE #
#===================#

import os
import threading
import time
import google.generativeai as genai
from flask import Flask, jsonify
from flask_cors import CORS
from elasticsearch import Elasticsearch
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta

# --- Configuration ---
ES_HOST = "http://localhost:64298"
INDEX_PATTERN = "logstash-*"
# --- IMPORTANT: Add your Gemini API Key here ---
GEMINI_API_KEY = "AIzaSyBxIDzqlhbCQxZWth026yIki54-_b5xzRs"

# --- Flask App & AI Cache Initialization ---
app = Flask(__name__)
CORS(app)
ai_analysis_cache = {
    "summary": "AI analysis is initializing. Please check back in a few minutes...",
    "threat_type": "Initializing...",
    "recommendations": ["Waiting for first data batch..."],
    "last_updated": None
}

# --- Configure Gemini AI ---
try:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-pro')
except Exception as e:
    print(f"FATAL ERROR: Could not configure Gemini AI. Check your API key. Error: {e}")
    model = None

# --- Elasticsearch Connection ---
try:
    es = Elasticsearch(ES_HOST, request_timeout=30)
    if not es.ping():
        raise ConnectionError("Could not connect to Elasticsearch.")
except ConnectionError as e:
    print(f"FATAL ERROR: Could not connect to Elasticsearch at {ES_HOST}.")
    es = None

# --- AI Analysis Background Task ---
def fetch_and_analyze_data():
    global ai_analysis_cache
    if not es or not model:
        print("AI ANALYSIS SKIPPED: Elasticsearch or Gemini model not available.")
        return

    print(f"AI TASK: Running scheduled analysis at {datetime.now()}")
    try:
        # 1. Aggregate recent data (last 15 minutes)
        query_body = {
            "query": {"range": {"@timestamp": {"gte": "now-15m/m"}}},
            "size": 0,
            "aggs": {
                "unique_ips": {"cardinality": {"field": "source_ip.keyword"}},
                "top_countries": {"terms": {"field": "geoip.country_name.keyword", "size": 5}},
                "top_honeypots": {"terms": {"field": "honeypot.keyword", "size": 5}},
                "top_ports": {"terms": {"field": "dest_port", "size": 5}},
                "top_passwords": {"terms": {"field": "password.keyword", "size": 5}}
            }
        }
        response = es.search(index=INDEX_PATTERN, **query_body)
        aggs = response.get('aggregations', {})
        total_events = response['hits']['total']['value']

        if total_events == 0:
            print("AI TASK: No new events to analyze.")
            # Keep the old analysis if there's no new data
            return

        # 2. Create a concise text summary (the "briefing")
        briefing = f"Honeypot Security Briefing (last 15 mins):\n"
        briefing += f"- Total Events: {total_events}\n"
        briefing += f"- Unique Attacker IPs: {aggs.get('unique_ips', {}).get('value', 0)}\n"
        briefing += f"- Top Attacking Countries: {[b['key'] for b in aggs.get('top_countries', {}).get('buckets', [])]}\n"
        briefing += f"- Top Targeted Honeypots: {[b['key'] for b in aggs.get('top_honeypots', {}).get('buckets', [])]}\n"
        briefing += f"- Top Targeted Ports: {[b['key'] for b in aggs.get('top_ports', {}).get('buckets', [])]}\n"
        briefing += f"- Top Passwords Attempted: {[b['key'] for b in aggs.get('top_passwords', {}).get('buckets', [])]}\n"

        # 3. Create the intelligent prompt
        prompt = f"""
        You are a senior cybersecurity analyst. Based on the following honeypot activity summary, provide a concise analysis in JSON format. The JSON object must have three keys: "summary", "threat_type", and "recommendations".

        - "summary": A brief, one-sentence summary of the activity in plain English.
        - "threat_type": A short, descriptive label for the dominant threat pattern (e.g., "Automated Scanning", "SSH Brute-Force", "Web Server Probing", "Coordinated Attack").
        - "recommendations": A JSON array of 2 short, actionable mitigation steps a security admin should take.

        Here is the data:
        {briefing}

        Provide only the raw JSON object as your response.
        """
        
        print("AI TASK: Sending data to Gemini for analysis...")
        # 4. Call the Gemini API
        response = model.generate_content(prompt)
        
        # 5. Parse and cache the response
        # A simple but effective way to clean the response
        cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
        import json
        ai_result = json.loads(cleaned_response)
        ai_result["last_updated"] = datetime.now().isoformat()
        ai_analysis_cache = ai_result
        print(f"AI TASK: Analysis complete and cache updated.")

    except Exception as e:
        print(f"AI TASK ERROR: {e}")

# --- API Endpoints ---
@app.route('/')
def health_check():
    return jsonify({"status": "ok", "message": "T-Pot Dashboard API is running."})

@app.route('/api/dashboard')
def get_dashboard_data():
    # This endpoint remains the same as before, providing chart/map data
    if not es:
        return jsonify({"error": "Elasticsearch connection not available"}), 500
    try:
        # The original dashboard query logic...
        query_body = {
            "size": 200, "query": {"range": {"@timestamp": {"gte": "now-24h/h"}}},
            "aggs": {
                "unique_attackers": {"cardinality": {"field": "source_ip.keyword"}},
                "attacks_over_time": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0, "extended_bounds": {"min": "now-24h/h", "max": "now/h"}}},
                "attacks_by_country": {"terms": {"field": "geoip.country_name.keyword", "size": 10}},
                "attacks_by_honeypot": {"terms": {"field": "honeypot.keyword", "size": 10}},
                "top_attacked_ports": {"terms": {"field": "dest_port", "size": 10}},
                "top_attacker_ips": {"terms": {"field": "source_ip.keyword", "size": 10}},
                "top_usernames": {"terms": {"field": "user.keyword", "size": 15}},
                "top_passwords": {"terms": {"field": "password.keyword", "size": 15}}
            },
            "sort": [{"@timestamp": "desc"}]
        }
        response = es.search(index=INDEX_PATTERN, **query_body)
        # The original data processing logic...
        aggregations = response.get('aggregations', {})
        def format_buckets(agg_data):
            if not agg_data or 'buckets' not in agg_data: return []
            return [{"name": bucket['key'], "value": bucket['doc_count']} for bucket in agg_data['buckets']]
        country_buckets = aggregations.get('attacks_by_country', {}).get('buckets', [])
        honeypot_buckets = aggregations.get('attacks_by_honeypot', {}).get('buckets', [])
        dashboard_data = {
            "kpi_total_attacks": response['hits']['total']['value'],
            "kpi_unique_attackers": aggregations.get('unique_attackers', {}).get('value', 0),
            "kpi_top_country": country_buckets[0]['key'] if country_buckets else 'N/A',
            "kpi_top_honeypot": honeypot_buckets[0]['key'] if honeypot_buckets else 'N/A',
            "chart_attacks_over_time": format_buckets(aggregations.get('attacks_over_time')),
            "chart_attacks_by_country": format_buckets(aggregations.get('attacks_by_country')),
            "chart_attacks_by_honeypot": format_buckets(aggregations.get('attacks_by_honeypot')),
            "chart_top_ports": format_buckets(aggregations.get('top_attacked_ports')),
            "table_top_attackers": format_buckets(aggregations.get('top_attacker_ips')),
            "list_top_usernames": [b['key'] for b in aggregations.get('top_usernames', {}).get('buckets', [])],
            "list_top_passwords": [b['key'] for b in aggregations.get('top_passwords', {}).get('buckets', [])],
            "map_recent_attacks": [
                {"lat": h['_source']['geoip']['location']['lat'], "lon": h['_source']['geoip']['location']['lon'], "ip": h['_source'].get('source_ip', 'N/A'), "country": h['_source']['geoip'].get('country_name', 'N/A'), "honeypot": h['_source'].get('honeypot', 'N/A')}
                for h in response['hits']['hits'] if h.get('_source', {}).get('geoip', {}).get('location')
            ]
        }
        return jsonify(dashboard_data)
    except Exception as e:
        print(f"ERROR in get_dashboard_data: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai-analysis', methods=['GET'])
def get_ai_analysis():
    """Instantly returns the latest cached AI analysis."""
    return jsonify(ai_analysis_cache)

# --- Main Execution ---
if __name__ == '__main__':
    # Run the first analysis shortly after startup
    # Using a thread to avoid blocking the main app startup
    threading.Timer(10, fetch_and_analyze_data).start()

    # Schedule the AI analysis to run every 10 minutes
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(fetch_and_analyze_data, 'interval', minutes=10)
    scheduler.start()
    
    print("Starting T-Pot Dashboard API Server with AI Analyst...")
    app.run(host='0.0.0.0', port=5001)

