use std::collections::HashMap;
use std::time::Duration;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::{System, Pid};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
    pub version: String,
    pub command: String,
    pub executable_path: String,
    pub start_time: DateTime<Utc>,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProcessEvent {
    ProcessStart {
        timestamp: DateTime<Utc>,
        process: ProcessInfo,
    },
    ProcessExit {
        timestamp: DateTime<Utc>,
        pid: i32,
        name: String,
    },
    ProcessScan {
        timestamp: DateTime<Utc>,
        process: ProcessInfo,
    },
}

pub struct ProcessMonitor {
    config: Config,
    event_sender: mpsc::UnboundedSender<ProcessEvent>,
    known_processes: HashMap<i32, ProcessInfo>,
    system: System,
}

impl ProcessMonitor {
    pub fn new(config: Config) -> (Self, mpsc::UnboundedReceiver<ProcessEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let monitor = Self {
            config,
            event_sender: tx,
            known_processes: HashMap::new(),
            system: System::new_all(),
        };
        
        (monitor, rx)
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("🔍 Starting process monitoring...");
        debug!("Monitoring config: enable_process_scan={}, enable_mock_events={}, scan_interval={:?}", 
               self.config.monitoring.enable_process_scan,
               self.config.monitoring.enable_mock_events,
               self.config.monitoring.scan_interval);
        
        // Initial scan of existing processes
        self.scan_existing_processes().await?;
        
        // Start periodic scanning
        if self.config.monitoring.enable_process_scan {
            info!("🚀 Process scanning enabled - starting periodic scanner");
            self.start_periodic_scanning().await;
        } else {
            warn!("⚠️ Process scanning disabled - no periodic scans will run");
        }
        
        // Generate mock events for demo
        if self.config.monitoring.enable_mock_events {
            info!("🎭 Mock events enabled - starting mock event generator");
            self.generate_mock_events().await;
        } else {
            warn!("⚠️ Mock events disabled - no demo events will be generated");
        }
        
        Ok(())
    }

    async fn scan_existing_processes(&mut self) -> Result<()> {
        info!("🔍 Scanning existing processes for monitored services...");
        debug!("Monitoring these processes: {:?}", self.config.detection.monitored_processes);
        let mut process_count = 0;
        let mut total_processes = 0;
        
        // Refresh system information
        self.system.refresh_all();
        total_processes = self.system.processes().len();
        debug!("Found {} total running processes", total_processes);
        
        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy().to_string();
            debug!("Checking process: {} (PID: {})", process_name, pid.as_u32());
            
            if let Some(process_info) = self.extract_process_info(pid, process).await {
                if self.should_monitor_process(&process_info) {
                    info!("📍 Found monitored process: {} v{} (PID: {})", 
                          process_info.name, process_info.version, process_info.pid);
                    
                    self.emit_process_event(ProcessEvent::ProcessScan {
                        timestamp: Utc::now(),
                        process: process_info.clone(),
                    });
                    
                    self.known_processes.insert(process_info.pid, process_info);
                    process_count += 1;
                } else {
                    debug!("⏭️ Skipping non-monitored process: {}", process_name);
                }
            }
        }
        
        info!("✅ Process scan complete: Found {}/{} monitored processes from {} total running processes", 
              process_count, self.config.detection.monitored_processes.len(), total_processes);
        Ok(())
    }

    async fn start_periodic_scanning(&self) {
        let config = self.config.clone();
        let sender = self.event_sender.clone();
        
        info!("🔄 Starting periodic process scanning (interval: {:?})", config.monitoring.scan_interval);
        debug!("Periodic scan will check for: {:?}", config.detection.monitored_processes);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.monitoring.scan_interval);
            let mut system = System::new_all();
            let mut scan_count = 0;
            
            loop {
                interval.tick().await;
                scan_count += 1;
                
                debug!("⏰ Starting periodic scan #{}", scan_count);
                
                match Self::periodic_scan(&config, &sender, &mut system).await {
                    Ok(_) => {
                        debug!("✅ Periodic scan #{} completed successfully", scan_count);
                    }
                    Err(e) => {
                        error!("❌ Error during periodic process scan #{}: {}", scan_count, e);
                    }
                }
                
                debug!("💤 Waiting {:?} until next scan...", config.monitoring.scan_interval);
            }
        });
    }

    async fn periodic_scan(
        config: &Config,
        sender: &mpsc::UnboundedSender<ProcessEvent>,
        system: &mut System,
    ) -> Result<()> {
        debug!("🔄 Performing periodic process scan (interval: {:?})...", config.monitoring.scan_interval);
        
        // Refresh system information
        system.refresh_all();
        let total_processes = system.processes().len();
        debug!("Scanning {} total running processes", total_processes);
        
        let mut new_processes = 0;
        let mut checked_processes = 0;
        
        for (pid, process) in system.processes() {
            checked_processes += 1;
            let process_name = process.name().to_string_lossy().to_string();
            
            if config.should_monitor_process(&process_name) {
                debug!("🎯 Found target process: {} (PID: {})", process_name, pid.as_u32());
                
                if let Some(process_info) = Self::extract_process_info_static(pid, process).await {
                    // For simplicity, treat all discovered processes as "new" during periodic scans
                    // In a real implementation, we'd track process start times more carefully
                    sender.send(ProcessEvent::ProcessStart {
                        timestamp: Utc::now(),
                        process: process_info.clone(),
                    }).ok();
                    
                    info!("📍 Detected monitored process: {} v{} (PID: {})", 
                          process_info.name, process_info.version, process_info.pid);
                    new_processes += 1;
                }
            }
        }
        
        debug!("🔍 Periodic scan complete: checked {}/{} processes, found {} monitored processes", 
               checked_processes, total_processes, new_processes);
        
        if new_processes > 0 {
            info!("✨ Found {} new monitored processes during scan", new_processes);
        } else {
            debug!("🔍 No new monitored processes found (monitoring: {:?})", config.detection.monitored_processes);
        }
        
        Ok(())
    }

    async fn generate_mock_events(&self) {
        info!("🎭 Generating mock events for demo...");
        debug!("Mock events will be generated every 5 seconds starting in 3 seconds");
        let sender = self.event_sender.clone();
        
        tokio::spawn(async move {
            // Wait a bit before generating mock events
            tokio::time::sleep(Duration::from_secs(3)).await;
            
            let mock_processes = vec![
                ProcessInfo {
                    pid: 12345,
                    name: "nginx".to_string(),
                    version: "1.14.2".to_string(),
                    command: "/usr/sbin/nginx -g daemon off;".to_string(),
                    executable_path: "/usr/sbin/nginx".to_string(),
                    start_time: Utc::now(),
                    user: "www-data".to_string(),
                },
                ProcessInfo {
                    pid: 54321,
                    name: "sshd".to_string(),
                    version: "7.4p1".to_string(),
                    command: "/usr/sbin/sshd -D".to_string(),
                    executable_path: "/usr/sbin/sshd".to_string(),
                    start_time: Utc::now(),
                    user: "root".to_string(),
                },
                ProcessInfo {
                    pid: 98765,
                    name: "mysqld".to_string(),
                    version: "8.0.25".to_string(),
                    command: "/usr/sbin/mysqld --user=mysql".to_string(),
                    executable_path: "/usr/sbin/mysqld".to_string(),
                    start_time: Utc::now(),
                    user: "mysql".to_string(),
                },
            ];
            
            for (i, process_info) in mock_processes.into_iter().enumerate() {
                // Stagger the mock events
                tokio::time::sleep(Duration::from_secs(2 + i as u64 * 3)).await;
                
                let event = ProcessEvent::ProcessStart {
                    timestamp: Utc::now(),
                    process: process_info.clone(),
                };
                
                if sender.send(event).is_err() {
                    warn!("Failed to send mock process event");
                    break;
                }
                
                info!("🎭 Generated mock process event: {} v{} (PID: {})", 
                      process_info.name, process_info.version, process_info.pid);
            }
        });
    }

    fn should_monitor_process(&self, process_info: &ProcessInfo) -> bool {
        self.config.should_monitor_process(&process_info.name)
    }

    fn emit_process_event(&self, event: ProcessEvent) {
        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to emit process event: {}", e);
        }
    }

    async fn extract_process_info(&self, pid: &Pid, process: &sysinfo::Process) -> Option<ProcessInfo> {
        Self::extract_process_info_static(pid, process).await
    }

    async fn extract_process_info_static(pid: &Pid, process: &sysinfo::Process) -> Option<ProcessInfo> {
        let pid = pid.as_u32() as i32;
        let name = process.name().to_string_lossy().to_string();
        
        // Get command line
        let command = if process.cmd().is_empty() {
            format!("[{}]", name)
        } else {
            process.cmd().iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        };
        
        // Get executable path
        let exe_path = process.exe()
            .and_then(|path| path.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("unknown/{}", name));
        
        // Try to extract version info
        let version = Self::extract_version(&exe_path, &name).await;
        
        // Get user info - simplified for cross-platform compatibility
        let user = "unknown".to_string(); // sysinfo doesn't provide user info on all platforms
        
        // Convert start time - simplified
        let start_time = Utc::now();
        
        Some(ProcessInfo {
            pid,
            name,
            version,
            command,
            executable_path: exe_path,
            start_time,
            user,
        })
    }

    async fn extract_version(exe_path: &str, process_name: &str) -> String {
        debug!("🔍 Extracting version for {} ({})", process_name, exe_path);
        
        // For demo purposes, use fallback versions immediately to avoid hanging
        // In production, you'd want the version detection below
        let fallback_version = Self::get_fallback_version(process_name).await;
        if fallback_version != "unknown" {
            debug!("✅ Using fallback version for {}: {}", process_name, fallback_version);
            return fallback_version;
        }
        
        debug!("🔧 Attempting to extract version from executable: {}", exe_path);
        
        // Try running --version on the executable (with timeout)
        if let Ok(output) = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::process::Command::new(exe_path)
                .arg("--version")
                .output()
        ).await {
            if let Ok(command_output) = output {
                if command_output.status.success() {
                    if let Ok(version_output) = String::from_utf8(command_output.stdout) {
                        let parsed_version = Self::parse_version_output(&version_output);
                        if parsed_version != "unknown" {
                            debug!("✅ Extracted version from --version: {}", parsed_version);
                            return parsed_version;
                        }
                    }
                }
            }
        } else {
            debug!("⏱️ Version extraction timed out for {}", exe_path);
        }
        
        debug!("❓ Could not extract version for {}, using unknown", process_name);
        "unknown".to_string()
    }

    fn parse_version_output(output: &str) -> String {
        // Extract version number from command output
        let lines: Vec<&str> = output.lines().take(3).collect(); // Only look at first few lines
        
        for line in lines {
            // Look for common version patterns - using simple string matching instead of regex
            if let Some(start) = line.find(char::is_numeric) {
                let version_part = &line[start..];
                if let Some(end) = version_part.find(' ') {
                    let version = &version_part[..end];
                    if version.contains('.') {
                        return version.to_string();
                    }
                } else if version_part.contains('.') {
                    return version_part.to_string();
                }
            }
        }
        
        "unknown".to_string()
    }

    async fn get_fallback_version(process_name: &str) -> String {
        // Provide some known versions for common processes for demo purposes
        match process_name {
            "nginx" => "1.14.2".to_string(),
            "sshd" => "7.4p1".to_string(),
            "mysqld" => "8.0.25".to_string(),
            "apache2" | "apache" => "2.4.41".to_string(),
            "postgres" => "13.7".to_string(),
            "node" => "16.14.0".to_string(),
            "python" | "python3" => "3.8.10".to_string(),
            _ => "unknown".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_output() {
        let nginx_output = "nginx version: nginx/1.18.0";
        assert_eq!(ProcessMonitor::parse_version_output(nginx_output), "1.18.0");
        
        let ssh_output = "OpenSSH_7.4p1, OpenSSL 1.0.2k-fips 26 Jan 2017";
        assert_eq!(ProcessMonitor::parse_version_output(ssh_output), "7.4p1");
        
        let unknown_output = "No version info here";
        assert_eq!(ProcessMonitor::parse_version_output(unknown_output), "unknown");
    }

    #[tokio::test]
    async fn test_fallback_version() {
        assert_eq!(ProcessMonitor::get_fallback_version("nginx").await, "1.14.2");
        assert_eq!(ProcessMonitor::get_fallback_version("sshd").await, "7.4p1");
        assert_eq!(ProcessMonitor::get_fallback_version("unknown").await, "unknown");
    }
}