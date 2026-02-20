"""
Internal API service for customer analytics.
Loads configuration from config/settings.json.
"""
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from pathlib import Path


def load_config():
    config_path = Path(__file__).parent / "config" / "settings.json"
    with open(config_path) as f:
        return json.load(f)


CONFIG = load_config()


class AnalyticsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        elif self.path == "/api/v1/metrics":
            api_key = CONFIG.get("analytics", {}).get("api_key")
            if not api_key:
                self.send_response(500)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "daily_active_users": 14823,
                "revenue_mtd": 284500.00,
                "churn_rate": 0.032,
            }).encode())
        elif self.path == "/api/v1/metrics/realtime":
            # New v2 endpoint — uses different config path
            endpoint = CONFIG.get("analytics", {}).get("endpoint")
            if not endpoint:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"error": "Analytics endpoint not configured"}
                ).encode())
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "active_users_now": 342,
                "events_per_second": 89.4,
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    port = CONFIG.get("app", {}).get("port", 8080)
    server = HTTPServer(("0.0.0.0", port), AnalyticsHandler)
    print(f"Analytics service running on port {port}")
    server.serve_forever()
