use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
// Remove futures dependency - we'll handle WebSocket differently
use serde_json::Value;
use tokio::sync::{mpsc, RwLock};
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
};
use tracing::{debug, error, info};

use crate::config::Config;
use crate::vulnerability_engine::{VulnerabilityEvent, VulnerabilityEngine, EngineStats};

type SharedState = Arc<RwLock<AppState>>;

#[derive(Clone)]
struct AppState {
    config: Config,
    recent_events: Vec<VulnerabilityEvent>,
}

pub struct WebServer {
    config: Config,
    state: SharedState,
}

impl WebServer {
    pub fn new(config: Config) -> Self {
        let state = Arc::new(RwLock::new(AppState {
            config: config.clone(),
            recent_events: Vec::new(),
        }));

        Self {
            config,
            state,
        }
    }

    pub async fn start(
        &self,
        mut vulnerability_events: mpsc::UnboundedReceiver<VulnerabilityEvent>,
        engine: Arc<VulnerabilityEngine>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app_state = self.state.clone();

        // Start event processing task
        let event_state = app_state.clone();
        tokio::spawn(async move {
            while let Some(event) = vulnerability_events.recv().await {
                if let Err(e) = Self::handle_vulnerability_event(event, &event_state).await {
                    error!("Error handling vulnerability event: {}", e);
                }
            }
        });

        // Create the router
        let app = self.create_router(app_state, engine).await;

        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.server.port));
        info!("🌐 Starting web server on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    async fn create_router(&self, state: SharedState, engine: Arc<VulnerabilityEngine>) -> Router {
        Router::new()
            // WebSocket endpoint
            .route("/ws", get(websocket_handler))
            // API routes
            .route("/api/stats", get(api_stats))
            .route("/api/vulnerabilities", get(api_vulnerabilities))
            .route("/api/summary", get(api_summary))
            .route("/api/events", get(api_events))
            .route("/health", get(health_check))
            // Static file serving
            .route("/", get(serve_index))
            .nest_service("/static", ServeDir::new("static"))
            // Add state
            .with_state(ApiState {
                app_state: state,
                engine,
            })
            // Add CORS
            .layer(CorsLayer::permissive())
    }

    async fn handle_vulnerability_event(
        event: VulnerabilityEvent,
        state: &SharedState,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Update state with new event
        {
            let mut app_state = state.write().await;
            app_state.recent_events.insert(0, event.clone());
            
            // Keep only the most recent events  
            let max_events = app_state.config.monitoring.max_recent_events;
            if app_state.recent_events.len() > max_events {
                app_state.recent_events.truncate(max_events);
            }
        }

        // In a full implementation, this would broadcast to WebSocket clients
        debug!("Vulnerability event processed: {:?}", event);

        Ok(())
    }
}

#[derive(Clone)]
struct ApiState {
    app_state: SharedState,
    engine: Arc<VulnerabilityEngine>,
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(_socket: WebSocket, _state: ApiState) {
    info!("📱 New WebSocket client connected");
    // Simplified WebSocket handler for now
    // In a full implementation, this would handle real-time updates
    info!("📱 WebSocket client disconnected");
}

async fn api_stats(State(state): State<ApiState>) -> Result<Json<EngineStats>, StatusCode> {
    let stats = state.engine.get_stats().await;
    Ok(Json(stats))
}

async fn api_vulnerabilities(
    State(state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let vulnerabilities = if let Some(severity) = params.get("severity") {
        use crate::vulnerability_engine::SeverityLevel;
        let severity_level = match severity.to_lowercase().as_str() {
            "critical" => SeverityLevel::Critical,
            "high" => SeverityLevel::High,
            "medium" => SeverityLevel::Medium,
            "low" => SeverityLevel::Low,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        state.engine.get_detections_by_severity(&severity_level).await
    } else {
        state.engine.get_all_detections().await
    };

    Ok(Json(serde_json::to_value(vulnerabilities).unwrap()))
}

async fn api_summary(State(state): State<ApiState>) -> Result<Json<Value>, StatusCode> {
    let summary = state.engine.generate_summary_report().await;
    Ok(Json(summary))
}

async fn api_events(State(state): State<ApiState>) -> Result<Json<Value>, StatusCode> {
    let events = {
        let app_state = state.app_state.read().await;
        app_state.recent_events.clone()
    };
    Ok(Json(serde_json::to_value(events).unwrap()))
}

async fn health_check() -> Json<Value> {
    Json(serde_json::json!({
        "status": "ok",
        "timestamp": chrono::Utc::now()
    }))
}

async fn serve_index() -> Html<&'static str> {
    Html(DEFAULT_HTML)
}

// Alternative implementation if we want to serve files from disk
async fn _serve_index_from_file() -> Result<Response, StatusCode> {
    match tokio::fs::read_to_string("static/index.html").await {
        Ok(content) => Ok(Html(content).into_response()),
        Err(_) => Ok(Html(DEFAULT_HTML).into_response()),
    }
}

const DEFAULT_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pulsar + Kepler Demo - Real-Time Vulnerability Detection</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f23;
            color: #cccccc;
            line-height: 1.6;
        }
        
        .header {
            background: #1a1a2e;
            padding: 1rem 2rem;
            border-bottom: 2px solid #16213e;
        }
        
        .header h1 {
            color: #00d4ff;
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }
        
        .status-bar {
            background: #16213e;
            padding: 0.5rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .main-content {
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .panel {
            background: #1a1a2e;
            border: 1px solid #16213e;
            border-radius: 8px;
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .panel-header {
            background: #16213e;
            padding: 1rem;
            font-weight: bold;
        }
        
        .panel-content {
            padding: 1rem;
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #888;
        }
        
        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.8rem;
            background: #ff4444;
            color: white;
        }
        
        .connection-status.connected {
            background: #00ff00;
            color: black;
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>🛡️ Pulsar + Kepler Demo (Rust)</h1>
        <p>Real-Time Vulnerable Process Detection Dashboard</p>
    </header>
    
    <div class="status-bar">
        <div id="connection-status">Connecting...</div>
        <div id="stats-summary">Loading...</div>
    </div>
    
    <div class="connection-status" id="connection-indicator">
        Disconnected
    </div>
    
    <main class="main-content">
        <div class="panel">
            <div class="panel-header">📊 Statistics</div>
            <div class="panel-content" id="stats-panel">
                <div class="loading">Loading statistics...</div>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header">🚨 Recent Vulnerability Alerts</div>
            <div class="panel-content" id="vulnerabilities-panel">
                <div class="loading">Loading vulnerabilities...</div>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header">📋 Recent Events</div>
            <div class="panel-content" id="events-panel">
                <div class="loading">Loading events...</div>
            </div>
        </div>
    </main>

    <script>
        class Dashboard {
            constructor() {
                this.ws = null;
                this.isConnected = false;
                this.reconnectAttempts = 0;
                this.maxReconnectAttempts = 5;
                this.init();
            }
            
            init() {
                this.connect();
                this.loadInitialData();
            }
            
            connect() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${window.location.host}/ws`;
                
                this.ws = new WebSocket(wsUrl);
                
                this.ws.onopen = () => {
                    console.log('Connected to WebSocket');
                    this.isConnected = true;
                    this.reconnectAttempts = 0;
                    this.updateConnectionStatus(true);
                };
                
                this.ws.onmessage = (event) => {
                    const message = JSON.parse(event.data);
                    this.handleMessage(message);
                };
                
                this.ws.onclose = () => {
                    console.log('Disconnected from WebSocket');
                    this.isConnected = false;
                    this.updateConnectionStatus(false);
                    this.attemptReconnect();
                };
                
                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };
            }
            
            attemptReconnect() {
                if (this.reconnectAttempts < this.maxReconnectAttempts) {
                    this.reconnectAttempts++;
                    setTimeout(() => this.connect(), 2000 * this.reconnectAttempts);
                }
            }
            
            updateConnectionStatus(connected) {
                const indicator = document.getElementById('connection-indicator');
                const status = document.getElementById('connection-status');
                
                if (connected) {
                    indicator.textContent = 'Connected';
                    indicator.className = 'connection-status connected';
                    status.textContent = 'Connected';
                } else {
                    indicator.textContent = 'Disconnected';
                    indicator.className = 'connection-status';
                    status.textContent = 'Disconnected';
                }
            }
            
            async loadInitialData() {
                try {
                    const response = await fetch('/api/stats');
                    const stats = await response.json();
                    this.updateStats(stats);
                } catch (error) {
                    console.error('Error loading initial data:', error);
                }
            }
            
            handleMessage(message) {
                switch (message.type) {
                    case 'initial_state':
                        this.updateStats(message.data.stats);
                        this.updateVulnerabilities(message.data.vulnerabilities);
                        this.updateEvents(message.data.recent_events);
                        break;
                    case 'vulnerability_event':
                        this.addEvent(message.data);
                        this.refreshStats();
                        break;
                    default:
                        console.log('Unknown message type:', message.type);
                }
            }
            
            updateStats(stats) {
                const panel = document.getElementById('stats-panel');
                const summary = document.getElementById('stats-summary');
                
                panel.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                        <div style="text-align: center; padding: 1rem; background: #16213e; border-radius: 6px;">
                            <div style="font-size: 2rem; font-weight: bold;">${stats.events_processed || 0}</div>
                            <div style="color: #888; font-size: 0.8rem;">Events Processed</div>
                        </div>
                        <div style="text-align: center; padding: 1rem; background: #16213e; border-radius: 6px;">
                            <div style="font-size: 2rem; font-weight: bold;">${stats.processes_scanned || 0}</div>
                            <div style="color: #888; font-size: 0.8rem;">Processes Scanned</div>
                        </div>
                        <div style="text-align: center; padding: 1rem; background: #16213e; border-radius: 6px;">
                            <div style="font-size: 2rem; font-weight: bold;">${stats.vulnerabilities_found || 0}</div>
                            <div style="color: #888; font-size: 0.8rem;">Vulnerabilities Found</div>
                        </div>
                        <div style="text-align: center; padding: 1rem; background: #16213e; border-radius: 6px;">
                            <div style="font-size: 2rem; font-weight: bold;">${stats.high_severity_alerts || 0}</div>
                            <div style="color: #888; font-size: 0.8rem;">High Severity Alerts</div>
                        </div>
                    </div>
                `;
                
                summary.textContent = `Events: ${stats.events_processed || 0}, Vulnerabilities: ${stats.vulnerabilities_found || 0}`;
            }
            
            updateVulnerabilities(vulnerabilities) {
                const panel = document.getElementById('vulnerabilities-panel');
                
                if (!vulnerabilities || vulnerabilities.length === 0) {
                    panel.innerHTML = '<div style="text-align: center; color: #666;">No vulnerabilities detected yet</div>';
                    return;
                }
                
                panel.innerHTML = vulnerabilities.map(vuln => `
                    <div style="background: rgba(255, 68, 68, 0.1); margin-bottom: 1rem; padding: 1rem; border-radius: 6px; border-left: 4px solid #ff4444;">
                        <div style="color: #888; font-size: 0.8rem; margin-bottom: 0.5rem;">${new Date(vuln.timestamp).toLocaleString()}</div>
                        <div style="font-weight: bold; margin-bottom: 0.5rem;">
                            ${vuln.process.name} v${vuln.process.version}
                            <span style="background: #ff4444; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; margin-left: 0.5rem;">${vuln.severity}</span>
                        </div>
                        <div style="font-size: 0.9rem;">
                            ${vuln.vulnerabilities.length} CVE(s) found
                        </div>
                    </div>
                `).join('');
            }
            
            updateEvents(events) {
                const panel = document.getElementById('events-panel');
                
                if (!events || events.length === 0) {
                    panel.innerHTML = '<div style="text-align: center; color: #666;">No events yet</div>';
                    return;
                }
                
                panel.innerHTML = events.slice(0, 10).map(event => `
                    <div style="background: #0f0f23; margin-bottom: 1rem; padding: 1rem; border-radius: 6px; border-left: 4px solid #333;">
                        <div style="color: #888; font-size: 0.8rem; margin-bottom: 0.5rem;">${new Date(event.timestamp || Date.now()).toLocaleString()}</div>
                        <div style="font-weight: bold; margin-bottom: 0.5rem;">${this.getEventTitle(event)}</div>
                        <div style="font-size: 0.9rem;">${this.getEventDetails(event)}</div>
                    </div>
                `).join('');
            }
            
            addEvent(event) {
                // For now, just refresh the whole events list
                this.loadEvents();
            }
            
            async loadEvents() {
                try {
                    const response = await fetch('/api/events');
                    const events = await response.json();
                    this.updateEvents(events);
                } catch (error) {
                    console.error('Error loading events:', error);
                }
            }
            
            async refreshStats() {
                try {
                    const response = await fetch('/api/stats');
                    const stats = await response.json();
                    this.updateStats(stats);
                } catch (error) {
                    console.error('Error refreshing stats:', error);
                }
            }
            
            getEventTitle(event) {
                if (event.VulnerabilityDetected) {
                    return `🚨 Vulnerability Alert: ${event.VulnerabilityDetected.detection.process.name}`;
                } else if (event.ProcessScanned) {
                    return `🔍 Process Scanned: ${event.ProcessScanned.process.name}`;
                }
                return '📋 System Event';
            }
            
            getEventDetails(event) {
                if (event.VulnerabilityDetected) {
                    const detection = event.VulnerabilityDetected.detection;
                    return `Found ${detection.vulnerabilities.length} CVEs in ${detection.process.name} v${detection.process.version}`;
                } else if (event.ProcessScanned) {
                    return `Scanned ${event.ProcessScanned.process.name} v${event.ProcessScanned.process.version}`;
                }
                return 'System event occurred';
            }
        }
        
        // Initialize dashboard when page loads
        document.addEventListener('DOMContentLoaded', () => {
            new Dashboard();
        });
    </script>
</body>
</html>
"#;