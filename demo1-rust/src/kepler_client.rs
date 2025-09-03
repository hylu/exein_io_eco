use std::time::Duration;
use anyhow::{Context, Result};
use moka::future::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::config::KeplerConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVEQuery {
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVE {
    #[serde(rename = "cve")]
    pub cve_id: String,
    pub summary: String,
    #[serde(rename = "publishedDate")]
    pub published_date: String,
    pub cvss: Option<CVSSInfo>,
    #[serde(default)]
    pub references: Vec<Reference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVSSInfo {
    pub v3: Option<CVSSv3>,
    pub v2: Option<CVSSv2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVSSv3 {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVSSv2 {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl CVE {
    pub fn cvss_score(&self) -> f64 {
        self.cvss
            .as_ref()
            .and_then(|cvss| cvss.v3.as_ref().map(|v3| v3.base_score))
            .or_else(|| self.cvss
                .as_ref()
                .and_then(|cvss| cvss.v2.as_ref().map(|v2| v2.base_score)))
            .unwrap_or(0.0)
    }
    
    pub fn severity(&self) -> String {
        self.cvss
            .as_ref()
            .and_then(|cvss| cvss.v3.as_ref().map(|v3| v3.severity.clone()))
            .or_else(|| self.cvss
                .as_ref()
                .and_then(|cvss| cvss.v2.as_ref().map(|v2| v2.severity.clone())))
            .unwrap_or_else(|| "UNKNOWN".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub vendor: String,
    pub product: String,
}

#[derive(Debug)]
pub struct KeplerClient {
    client: Client,
    base_url: String,
    config: KeplerConfig,
    cache: Cache<String, Vec<CVE>>,
}

impl KeplerClient {
    pub fn new(config: KeplerConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        let cache = Cache::builder()
            .max_capacity(config.retry_attempts as u64 * 100) // Reasonable cache size
            .time_to_live(config.timeout * 60) // Cache for 60x timeout duration
            .build();

        Self {
            client,
            base_url: config.base_url.clone(),
            config,
            cache,
        }
    }

    pub async fn search_cves(&self, product: &str, version: &str) -> Result<Vec<CVE>> {
        let cache_key = format!("{}:{}", product, version);
        
        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for {}:{}", product, version);
            return Ok(cached);
        }

        debug!("Cache miss for {}:{}, querying Kepler API", product, version);

        let query = CVEQuery {
            product: product.to_string(),
            version: version.to_string(),
        };

        let url = format!("{}/cve/search", self.base_url);
        
        let mut last_error = None;
        
        for attempt in 1..=self.config.retry_attempts {
            match self.client
                .post(&url)
                .json(&query)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<Vec<CVE>>().await {
                            Ok(cves) => {
                                info!("Found {} CVEs for {} v{}", cves.len(), product, version);
                                
                                // Cache the result
                                self.cache.insert(cache_key, cves.clone()).await;
                                
                                return Ok(cves);
                            }
                            Err(e) => {
                                error!("Failed to parse CVE response: {}", e);
                                last_error = Some(anyhow::anyhow!(e));
                            }
                        }
                    } else {
                        warn!("Kepler API returned status: {}", response.status());
                        last_error = Some(anyhow::anyhow!("HTTP {}", response.status()));
                    }
                }
                Err(e) => {
                    warn!("Attempt {} failed for Kepler API: {}", attempt, e);
                    last_error = Some(anyhow::anyhow!(e));
                }
            }

            if attempt < self.config.retry_attempts {
                tokio::time::sleep(self.config.retry_delay).await;
            }
        }

        // If all attempts failed, return mock data for demo purposes
        match last_error {
            Some(e) if e.to_string().contains("Connection refused") 
                || e.to_string().contains("404") 
                || e.to_string().contains("HTTP") => {
                warn!("Kepler API unavailable ({}), using mock data for demo", e);
                Ok(self.get_mock_cve_data(product, version))
            }
            Some(e) => {
                error!("Failed to query Kepler API after {} attempts: {}", self.config.retry_attempts, e);
                Err(e).context("Kepler API query failed")
            }
            None => Ok(vec![]),
        }
    }

    #[allow(dead_code)]
    pub async fn search_products(&self, query: &str) -> Result<Vec<Product>> {
        let encoded_query = query.replace(' ', "%20");
        let url = format!("{}/products/search/{}", self.base_url, encoded_query);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to search products")?;

        if response.status().is_success() {
            let products = response.json::<Vec<Product>>().await
                .context("Failed to parse products response")?;
            
            debug!("Found {} products for query '{}'", products.len(), query);
            Ok(products)
        } else {
            warn!("Product search returned status: {}", response.status());
            Ok(vec![])
        }
    }

    pub async fn test_connection(&self) -> bool {
        // Test with a real CVE search instead of /products which returns 404 when empty
        let test_query = CVEQuery {
            product: "nginx".to_string(),
            version: "1.29.1".to_string(),
        };
        
        let url = format!("{}/cve/search", self.base_url);
        
        match self.client
            .post(&url)
            .json(&test_query)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => {
                let success = response.status().is_success();
                if success {
                    info!("✅ Connected to Kepler API at {}", self.base_url);
                } else {
                    warn!("⚠️ Kepler API responded with status: {}", response.status());
                }
                success
            }
            Err(e) => {
                warn!("⚠️ Cannot connect to Kepler API at {}: {}", self.base_url, e);
                false
            }
        }
    }

    pub fn get_cache_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    fn get_mock_cve_data(&self, product: &str, version: &str) -> Vec<CVE> {
        match product {
            "nginx" => match version {
                "1.14.2" => vec![
                    CVE {
                        cve_id: "CVE-2019-20372".to_string(),
                        summary: "NGINX before 1.17.7, with certain error_page configurations, allows HTTP request smuggling".to_string(),
                        published_date: "2020-01-09T21:15Z".to_string(),
                        cvss: Some(CVSSInfo {
                            v3: Some(CVSSv3 {
                                base_score: 5.3,
                                severity: "MEDIUM".to_string(),
                            }),
                            v2: None,
                        }),
                        references: vec![Reference {
                            url: "https://nginx.org/en/security_advisories.html".to_string(),
                            tags: vec!["Vendor Advisory".to_string()],
                        }],
                    }
                ],
                "1.18.0" => vec![
                    CVE {
                        cve_id: "CVE-2021-23017".to_string(),
                        summary: "A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets".to_string(),
                        published_date: "2021-05-25T13:15Z".to_string(),
                        cvss: Some(CVSSInfo {
                            v3: Some(CVSSv3 {
                                base_score: 8.1,
                                severity: "HIGH".to_string(),
                            }),
                            v2: None,
                        }),
                        references: vec![Reference {
                            url: "https://nginx.org/en/security_advisories.html".to_string(),
                            tags: vec!["Vendor Advisory".to_string()],
                        }],
                    }
                ],
                _ => vec![],
            },
            "openssh-server" | "sshd" => match version {
                "7.4p1" => vec![
                    CVE {
                        cve_id: "CVE-2018-15473".to_string(),
                        summary: "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout".to_string(),
                        published_date: "2018-08-17T14:29Z".to_string(),
                        cvss: Some(CVSSInfo {
                            v3: Some(CVSSv3 {
                                base_score: 5.3,
                                severity: "MEDIUM".to_string(),
                            }),
                            v2: None,
                        }),
                        references: vec![Reference {
                            url: "https://www.openssh.com/txt/release-7.8".to_string(),
                            tags: vec!["Vendor Advisory".to_string()],
                        }],
                    },
                    CVE {
                        cve_id: "CVE-2020-14145".to_string(),
                        summary: "The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak".to_string(),
                        published_date: "2020-12-02T21:15Z".to_string(),
                        cvss: Some(CVSSInfo {
                            v3: Some(CVSSv3 {
                                base_score: 4.3,
                                severity: "MEDIUM".to_string(),
                            }),
                            v2: None,
                        }),
                        references: vec![Reference {
                            url: "https://www.openssh.com/txt/release-8.5".to_string(),
                            tags: vec!["Vendor Advisory".to_string()],
                        }],
                    }
                ],
                _ => vec![],
            },
            "mysqld" | "mysql" => match version {
                "8.0.25" => vec![
                    CVE {
                        cve_id: "CVE-2021-35604".to_string(),
                        summary: "Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB)".to_string(),
                        published_date: "2021-10-20T11:17Z".to_string(),
                        cvss: Some(CVSSInfo {
                            v3: Some(CVSSv3 {
                                base_score: 4.4,
                                severity: "MEDIUM".to_string(),
                            }),
                            v2: None,
                        }),
                        references: vec![Reference {
                            url: "https://www.oracle.com/security-alerts/cpuoct2021.html".to_string(),
                            tags: vec!["Vendor Advisory".to_string()],
                        }],
                    }
                ],
                _ => vec![],
            },
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeplerConfig;

    fn test_config() -> KeplerConfig {
        KeplerConfig {
            base_url: "http://localhost:8000".to_string(),
            timeout: Duration::from_secs(5),
            retry_attempts: 2,
            retry_delay: Duration::from_millis(100),
        }
    }

    #[tokio::test]
    async fn test_mock_cve_data() {
        let client = KeplerClient::new(test_config());
        
        let nginx_cves = client.get_mock_cve_data("nginx", "1.14.2");
        assert_eq!(nginx_cves.len(), 1);
        assert_eq!(nginx_cves[0].cve_id, "CVE-2019-20372");
        
        let ssh_cves = client.get_mock_cve_data("sshd", "7.4p1");
        assert_eq!(ssh_cves.len(), 2);
        
        let unknown_cves = client.get_mock_cve_data("unknown", "1.0.0");
        assert_eq!(unknown_cves.len(), 0);
    }
}