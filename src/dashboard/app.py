import os
import json
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="IPsecTrace Dashboard")

# Serve generated figures statically
if os.path.exists("results/figures"):
    app.mount("/figures", StaticFiles(directory="results/figures"), name="figures")

@app.get("/api/overview")
def get_overview():
    features_file = "results/features.csv"
    metrics_file = "results/metrics.json"
    sessions_file = "results/sessions.json"

    flow_count = 0
    if os.path.exists(features_file):
        with open(features_file) as f:
            flow_count = max(0, len(f.readlines()) - 1)

    sessions = []
    if os.path.exists(sessions_file):
        with open(sessions_file) as f:
            sessions = json.load(f)

    metrics = {}
    if os.path.exists(metrics_file):
        with open(metrics_file) as f:
            metrics = json.load(f)

    return {
        "ipsec_detected": True,
        "ike_version": "2.0",
        "num_sessions": len(sessions),
        "analyzed_flows": flow_count,
        "metrics": metrics,
        "sessions": sessions
    }

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>IPsecTrace — Real-Time VPN Security & AI Analyzer</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }
            h1 { color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
            .card { background: #1e293b; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); border: 1px solid #334155; }
            .metric { font-size: 28px; fontweight: bold; color: #38bdf8; margin: 10px 0; }
            .tag { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            .pass { background: #065f46; color: #34d399; }
            .warning { background: #854d0e; color: #fde047; }
            img { max-width: 100%; border-radius: 8px; border: 1px solid #475569; margin-top: 10px; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { border: 1px solid #334155; padding: 8px; text-align: left; font-size: 13px; }
            th { background: #0f172a; color: #94a3b8; }
        </style>
    </head>
    <body>
        <h1>🛡️ IPsecTrace Security & AI Assessment Dashboard</h1>
        
        <div class="grid">
            <div class="card">
                <h3>IPsec Protocol Detection</h3>
                <div class="metric">IKEv2 / ESP</div>
                <p>Status: <span class="tag pass">ACTIVE</span></p>
                <p>Control Plane: AES-128-CBC / SHA256 / DH Group 14</p>
            </div>
            
            <div class="card">
                <h3>Analyzed Flow Samples</h3>
                <div id="flow-count" class="metric">--</div>
                <p>Ground Truth: 4 Classes (ICMP, WEB, BULK, INTERACTIVE)</p>
            </div>

            <div class="card">
                <h3>AI Model Performance</h3>
                <div id="rf-f1" class="metric">--</div>
                <p>Classifier: Random Forest (Baseline)</p>
            </div>
        </div>

        <h2 style="color: #cbd5e1; margin-top: 30px;">Security Rule Findings</h2>
        <div class="card">
            <table id="security-table">
                <thead>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Finding</th>
                        <th>Evidence</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td colspan="5">Loading security evidence...</td></tr>
                </tbody>
            </table>
        </div>

        <h2 style="color: #cbd5e1; margin-top: 30px;">Visual Analytics & Confusion Matrix</h2>
        <div class="grid">
            <div class="card">
                <h4>Traffic Class Distribution</h4>
                <img src="/figures/traffic_class_distribution.png" alt="Distribution">
            </div>
            <div class="card">
                <h4>Random Forest Confusion Matrix</h4>
                <img src="/figures/confusion_matrix.png" alt="Confusion Matrix">
            </div>
            <div class="card">
                <h4>Model Performance Comparison</h4>
                <img src="/figures/model_comparison.png" alt="Model Comparison">
            </div>
            <div class="card">
                <h4>Throughput Distribution</h4>
                <img src="/figures/throughput_distribution.png" alt="Throughput">
            </div>
        </div>

        <script>
            fetch('/api/overview')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('flow-count').innerText = data.analyzed_flows + ' Flows';
                    if (data.metrics && data.metrics.models && data.metrics.models['Random Forest']) {
                        document.getElementById('rf-f1').innerText = (data.metrics.models['Random Forest'].macro_f1 * 100).toFixed(1) + '% F1';
                    }
                    
                    if (data.sessions && data.sessions.length > 0) {
                        const secTable = document.getElementById('security-table').getElementsByTagName('tbody')[0];
                        secTable.innerHTML = '';
                        data.sessions[0].security_findings.forEach(f => {
                            const row = secTable.insertRow();
                            const tagClass = f.status === 'PASS' ? 'pass' : 'warning';
                            row.innerHTML = `
                                <td><b>${f.check}</b></td>
                                <td><span class="tag ${tagClass}">${f.status}</span></td>
                                <td>${f.finding}</td>
                                <td><code>${f.evidence}</code></td>
                                <td>${f.recommendation}</td>
                            `;
                        });
                    }
                });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
