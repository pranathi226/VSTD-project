/**
 * Visual Threat Detection Dashboard - Main JavaScript
 */

// Global variables
let trafficChart = null;
let threatChart = null;

// Initialize everything when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initializing Threat Detection Dashboard...');
    
    // Update time display
    updateTime();
    setInterval(updateTime, 1000);
    
    // Load initial data
    loadAllData();
    
    // Initialize charts
    initCharts();
    
    // Set up auto-refresh
    setInterval(loadAllData, 5000); // Refresh every 5 seconds
    
    console.log('✅ Dashboard initialized successfully');
});

// Update current time display
function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', {
        hour12: true,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    const dateString = now.toLocaleDateString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
    
    const timeElement = document.getElementById('currentTime');
    if (timeElement) {
        timeElement.innerHTML = `
            <i class="fas fa-clock"></i> ${timeString}<br>
            <small>${dateString}</small>
        `;
    }
}

// Initialize charts
function initCharts() {
    const trafficCtx = document.getElementById('trafficChart');
    const threatCtx = document.getElementById('threatChart');
    
    if (!trafficCtx || !threatCtx) {
        console.error('Chart canvases not found!');
        return;
    }
    
    // Traffic Chart
    trafficChart = new Chart(trafficCtx.getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Normal',
                    data: [],
                    borderColor: '#22c55e',
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Suspicious',
                    data: [],
                    borderColor: '#f97316',
                    backgroundColor: 'rgba(249, 115, 22, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Malicious',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: '#94a3b8'
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(71, 85, 105, 0.3)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(71, 85, 105, 0.3)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                }
            }
        }
    });
    
    // Threat Chart
    threatChart = new Chart(threatCtx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'Low', 'Medium', 'High'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#22c55e', '#3b82f6', '#f97316', '#ef4444'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#94a3b8'
                    }
                }
            }
        }
    });
}

// Load all data
async function loadAllData() {
    await Promise.all([
        loadStats(),
        loadThreats(),
        loadLogs(),
        loadNetworkData()
    ]);
}

// Load system statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success) {
            updateStatsDisplay(data.stats);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
        updateStatus('error');
    }
}

// Update stats display
function updateStatsDisplay(stats) {
    if (!stats) return;
    
    // Update individual stat elements
    document.getElementById('totalThreats').textContent = stats.total_threats || 0;
    document.getElementById('todayThreats').textContent = stats.threats_today || 0;
    document.getElementById('highSeverity').textContent = stats.high_severity || 0;
    document.getElementById('detectionRate').textContent = `${stats.detection_rate || 0}%`;
    document.getElementById('activeThreats').textContent = stats.active_threats || 0;
    document.getElementById('mitigatedThreats').textContent = stats.mitigated || 0;
    
    // Update threat distribution chart
    if (threatChart) {
        threatChart.data.datasets[0].data = [
            Math.max(0, (stats.total_threats || 0) - (stats.active_threats || 0)),
            Math.floor((stats.active_threats || 0) * 0.3), // Low
            Math.floor((stats.active_threats || 0) * 0.4), // Medium
            Math.floor((stats.active_threats || 0) * 0.3)  // High
        ];
        threatChart.update();
    }
    
    // Update system status
    updateStatus(stats.system_status || 'active');
}

// Update system status
function updateStatus(status) {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    
    if (!statusDot || !statusText) return;
    
    if (status === 'active') {
        statusDot.style.background = '#22c55e';
        statusText.textContent = 'System Active';
        statusText.style.color = '#22c55e';
    } else {
        statusDot.style.background = '#ef4444';
        statusText.textContent = 'System Error';
        statusText.style.color = '#ef4444';
    }
}

// Load threats
async function loadThreats() {
    try {
        const response = await fetch('/api/threats');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        const threatList = document.getElementById('threatList');
        
        if (data.success && data.threats && data.threats.length > 0) {
            threatList.innerHTML = '';
            
            // Show threats in reverse order (newest first)
            data.threats.reverse().forEach(threat => {
                threatList.appendChild(createThreatElement(threat));
            });
        } else {
            threatList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-shield-check"></i>
                    <p>No threats detected yet</p>
                    <button class="btn btn-primary" onclick="runDetection()">
                        <i class="fas fa-search"></i> Run Detection
                    </button>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

// Create threat element
function createThreatElement(threat) {
    const div = document.createElement('div');
    
    // Determine severity class and badge
    const severity = threat.severity || 'low';
    const status = threat.status || 'detected';
    const isMitigated = status === 'mitigated';
    
    const severityClass = isMitigated ? 'mitigated' : severity;
    const badgeClass = isMitigated ? 'badge-mitigated' : `badge-${severity}`;
    const badgeText = isMitigated ? 'Mitigated' : severity.charAt(0).toUpperCase() + severity.slice(1);
    
    div.className = `threat-item ${severityClass}`;
    div.onclick = () => showThreatDetails(threat);
    
    div.innerHTML = `
        <div class="threat-header">
            <div class="threat-type">
                <i class="fas fa-exclamation-triangle"></i>
                ${threat.type || 'Unknown Threat'}
            </div>
            <span class="threat-badge ${badgeClass}">
                ${badgeText}
            </span>
        </div>
        
        <div class="threat-meta">
            <div class="threat-meta-item">
                <i class="fas fa-clock"></i>
                ${threat.timestamp || 'Unknown'}
            </div>
            <div class="threat-meta-item">
                <i class="fas fa-network-wired"></i>
                ${threat.source_ip || 'Unknown'}
            </div>
            <div class="threat-meta-item">
                <i class="fas fa-percentage"></i>
                ${(threat.confidence * 100 || 0).toFixed(1)}% confidence
            </div>
        </div>
        
        <div class="threat-description">
            ${threat.description || 'No description available'}
        </div>
        
        <div class="threat-actions">
            ${!isMitigated ? `
                <button class="btn btn-success btn-sm" onclick="mitigateThreat(${threat.id}); event.stopPropagation();">
                    <i class="fas fa-check"></i> Mitigate
                </button>
            ` : ''}
            <button class="btn btn-primary btn-sm" onclick="viewThreatDetails(${threat.id}); event.stopPropagation();">
                <i class="fas fa-info-circle"></i> Details
            </button>
        </div>
    `;
    
    return div;
}

// Load logs
async function loadLogs() {
    try {
        const response = await fetch('/api/logs');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        const logContainer = document.getElementById('logContainer');
        
        if (data.success && data.logs && data.logs.length > 0) {
            logContainer.innerHTML = '';
            
            // Show logs in reverse order (newest first)
            data.logs.reverse().forEach(log => {
                const logElement = document.createElement('div');
                logElement.className = 'log-entry';
                
                const level = log.level || 'INFO';
                const levelClass = level === 'CRITICAL' ? 'level-critical' : 
                                level === 'WARNING' ? 'level-warning' : 'level-info';
                
                logElement.innerHTML = `
                    <span class="log-time">${log.timestamp || 'Unknown'}</span>
                    <span class="log-level ${levelClass}">${level}</span>
                    <span class="log-message">${log.message || 'No message'}</span>
                `;
                
                logContainer.appendChild(logElement);
            });
        } else {
            logContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-file-alt"></i>
                    <p>No logs available</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

// Load network data
async function loadNetworkData() {
    try {
        const response = await fetch('/api/network');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success && data.data && trafficChart) {
            const labels = data.data.map(item => item.time);
            const normalData = data.data.map(item => item.normal);
            const suspiciousData = data.data.map(item => item.suspicious);
            const maliciousData = data.data.map(item => item.malicious);
            
            trafficChart.data.labels = labels;
            trafficChart.data.datasets[0].data = normalData;
            trafficChart.data.datasets[1].data = suspiciousData;
            trafficChart.data.datasets[2].data = maliciousData;
            trafficChart.update();
        }
    } catch (error) {
        console.error('Error loading network data:', error);
    }
}

// Run threat detection
async function runDetection() {
    try {
        const response = await fetch('/api/detect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`Threat detected: ${data.threat.type}`, 'danger');
            loadThreats();
            loadStats();
        }
    } catch (error) {
        console.error('Error running detection:', error);
        showNotification('Failed to run threat detection', 'warning');
    }
}

// Simulate attack
async function simulateAttack() {
    try {
        const response = await fetch('/api/simulate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`Attack simulated: ${data.threat.type}`, 'warning');
            loadThreats();
            loadStats();
        }
    } catch (error) {
        console.error('Error simulating attack:', error);
        showNotification('Failed to simulate attack', 'warning');
    }
}

// Mitigate threat
async function mitigateThreat(threatId) {
    if (!confirm(`Are you sure you want to mitigate threat #${threatId}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/threats/${threatId}/mitigate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`Threat #${threatId} mitigated successfully`, 'success');
            loadThreats();
            loadStats();
        }
    } catch (error) {
        console.error('Error mitigating threat:', error);
        showNotification('Failed to mitigate threat', 'warning');
    }
}

// View threat details
async function viewThreatDetails(threatId) {
    try {
        const response = await fetch(`/api/threats/${threatId}`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success) {
            showThreatDetails(data.threat);
        }
    } catch (error) {
        console.error('Error loading threat details:', error);
        showNotification('Failed to load threat details', 'warning');
    }
}

// Show threat details in modal
function showThreatDetails(threat) {
    const modal = document.getElementById('threatModal');
    const modalBody = document.getElementById('modalBody');
    
    if (!modal || !modalBody) return;
    
    const severity = threat.severity || 'low';
    const status = threat.status || 'detected';
    const isMitigated = status === 'mitigated';
    
    modalBody.innerHTML = `
        <div class="threat-details">
            <div class="detail-section">
                <h3><i class="fas fa-info-circle"></i> Threat Information</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="detail-label">Type</div>
                        <div class="detail-value">${threat.type || 'Unknown'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Severity</div>
                        <div class="detail-value" style="color: ${
                            severity === 'high' ? '#ef4444' : 
                            severity === 'medium' ? '#f97316' : '#22c55e'
                        }">
                            ${severity.toUpperCase()}
                        </div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Status</div>
                        <div class="detail-value" style="color: ${isMitigated ? '#22c55e' : '#ef4444'}">
                            ${isMitigated ? '✅ Mitigated' : '⚠️ Active'}
                        </div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Confidence</div>
                        <div class="detail-value">${(threat.confidence * 100 || 0).toFixed(1)}%</div>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h3><i class="fas fa-network-wired"></i> Network Information</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="detail-label">Source IP</div>
                        <div class="detail-value">${threat.source_ip || 'Unknown'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Destination IP</div>
                        <div class="detail-value">${threat.destination_ip || '192.168.1.100'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Protocol</div>
                        <div class="detail-value">${threat.protocol || 'TCP'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Port</div>
                        <div class="detail-value">${threat.port || 'Unknown'}</div>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h3><i class="fas fa-file-alt"></i> Description</h3>
                <div class="detail-item">
                    <div class="detail-value">${threat.description || 'No description available'}</div>
                </div>
            </div>
            
            ${!isMitigated ? `
                <div class="detail-section">
                    <h3><i class="fas fa-tools"></i> Actions</h3>
                    <div style="text-align: center; padding: 20px;">
                        <button class="btn btn-success" onclick="mitigateThreat(${threat.id}); closeModal();">
                            <i class="fas fa-check"></i> Mitigate This Threat
                        </button>
                    </div>
                </div>
            ` : ''}
        </div>
    `;
    
    modal.style.display = 'flex';
}

// Close modal
function closeModal() {
    const modal = document.getElementById('threatModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Clear logs
async function clearLogs() {
    if (!confirm('Are you sure you want to clear all logs?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/clear-logs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Logs cleared successfully', 'success');
            loadLogs();
        }
    } catch (error) {
        console.error('Error clearing logs:', error);
        showNotification('Failed to clear logs', 'warning');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const icon = type === 'danger' ? 'exclamation-triangle' : 
                type === 'warning' ? 'exclamation-circle' :
                type === 'success' ? 'check-circle' : 'info-circle';
    
    notification.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <div class="notification-content">
            <div class="notification-message">${message}</div>
        </div>
    `;
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);
}

// Handle keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+D or Cmd+D to run detection
    if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
        e.preventDefault();
        runDetection();
    }
    
    // Escape to close modal
    if (e.key === 'Escape') {
        closeModal();
    }
});

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('threatModal');
    if (event.target === modal) {
        closeModal();
    }
};