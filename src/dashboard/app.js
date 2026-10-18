// Cloud Defense Sentinel - Frontend Dashboard Controller

let telemetryChart = null;
let threatRadarChart = null;
let currentTab = 'live-monitoring';

// ----------------- TAB SWITCHING -----------------
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
  document.querySelectorAll('.nav-tabs .tab-btn').forEach(btn => btn.classList.remove('active'));

  const activeContent = document.getElementById(tabId);
  if (activeContent) activeContent.classList.add('active');

  const activeBtn = Array.from(document.querySelectorAll('.nav-tabs .tab-btn')).find(b =>
    b.getAttribute('onclick') && b.getAttribute('onclick').includes(tabId)
  );
  if (activeBtn) activeBtn.classList.add('active');

  if (tabId === 'active-alerts') loadAlerts();
  if (tabId === 'attack-history') loadAttackLog();
  if (tabId === 'poisoning-defense') loadQuarantine();
}

// ----------------- CHARTS INITIALIZATION -----------------
function initCharts() {
  const ctxTel = document.getElementById('telemetryChart').getContext('2d');
  telemetryChart = new Chart(ctxTel, {
    type: 'line',
    data: {
      labels: ['T-50s', 'T-40s', 'T-30s', 'T-20s', 'T-10s', 'Now'],
      datasets: [
        {
          label: 'Shannon Entropy (bits/byte)',
          data: [3.4, 3.5, 3.45, 3.6, 3.42, 3.48],
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.1)',
          yAxisID: 'yEntropy',
          tension: 0.3,
          fill: true
        },
        {
          label: 'File Modification Rate (files/min)',
          data: [4.0, 5.0, 3.0, 6.0, 4.0, 5.0],
          borderColor: '#6366f1',
          backgroundColor: 'rgba(99, 102, 241, 0.1)',
          yAxisID: 'yModRate',
          tension: 0.3,
          fill: true
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: 'rgba(75, 85, 99, 0.2)' }, ticks: { color: '#9ca3af' } },
        yEntropy: {
          type: 'linear',
          position: 'left',
          min: 0,
          max: 8.0,
          grid: { color: 'rgba(75, 85, 99, 0.2)' },
          ticks: { color: '#06b6d4' },
          title: { display: true, text: 'Entropy (Max 8.0)', color: '#06b6d4' }
        },
        yModRate: {
          type: 'linear',
          position: 'right',
          min: 0,
          max: 150,
          grid: { drawOnChartArea: false },
          ticks: { color: '#6366f1' },
          title: { display: true, text: 'Files / Min', color: '#6366f1' }
        }
      },
      plugins: {
        legend: { labels: { color: '#f3f4f6' } }
      }
    }
  });

  const ctxThreat = document.getElementById('threatRadarChart').getContext('2d');
  threatRadarChart = new Chart(ctxThreat, {
    type: 'doughnut',
    data: {
      labels: ['Benign Normal', 'Ransomware Risk', 'Anomaly Outlier'],
      datasets: [{
        data: [95, 2, 3],
        backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#f3f4f6' } }
      }
    }
  });
}

// ----------------- LOG FEED HELPER -----------------
function appendLog(message, type = 'modify') {
  const feed = document.getElementById('telemetryLogFeed');
  if (!feed) return;
  const timeStr = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'log-line';
  
  let typeClass = 'log-modify';
  if (type === 'alert') typeClass = 'log-alert';
  if (type === 'benign') typeClass = 'log-benign';

  div.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="${typeClass}">${message}</span>`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

function clearLogFeed() {
  document.getElementById('telemetryLogFeed').innerHTML = '';
}

// ----------------- SYSTEM STATUS & RECENT FEATURES -----------------
async function fetchStatus() {
  try {
    const res = await fetch('/api/system/status');
    const data = await res.json();
    
    document.getElementById('valTotalEvents').innerText = Number(data.total_events_processed || 0).toLocaleString();
    const alertCount = data.active_alerts || 0;
    document.getElementById('alertCountBadge').innerText = alertCount;
    
    // Update threat level card based on alerts
    const threatCard = document.getElementById('cardThreatLevel');
    const threatVal = document.getElementById('valThreatLevel');
    const threatSub = document.getElementById('valThreatSub');
    
    if (alertCount > 0) {
      threatCard.classList.add('critical');
      threatVal.innerText = 'CRITICAL THREAT';
      threatVal.style.color = 'var(--accent-rose)';
      threatSub.innerText = `${alertCount} active ransomware alerts!`;
    } else {
      threatCard.classList.remove('critical');
      threatVal.innerText = 'NORMAL';
      threatVal.style.color = 'var(--accent-green)';
      threatSub.innerText = 'Dual ML Engine Standby';
    }
  } catch (err) {
    console.warn('Status poll failed:', err);
  }
}

async function fetchRecentFeatures() {
  try {
    const res = await fetch('/api/features/recent');
    const data = await res.json();
    if (!data.features || data.features.length === 0) return;

    const feats = data.features;
    const labels = feats.map((_, i) => `W-${feats.length - i}`);
    const entropies = feats.map(f => f.mean_entropy);
    const modRates = feats.map(f => f.files_modified_rate);

    if (telemetryChart) {
      telemetryChart.data.labels = labels;
      telemetryChart.data.datasets[0].data = entropies;
      telemetryChart.data.datasets[1].data = modRates;
      telemetryChart.update();
    }

    const latest = feats[feats.length - 1];
    document.getElementById('valModRate').innerHTML = `${latest.files_modified_rate} <span style="font-size: 1rem; color: var(--text-muted);">ops/min</span>`;
    document.getElementById('valEntropy').innerHTML = `${latest.mean_entropy} <span style="font-size: 1rem; color: var(--text-muted);">bits/byte</span>`;

    // Threat Radar update
    if (threatRadarChart) {
      if (latest.mean_entropy > 7.5 || latest.extension_changes > 5) {
        threatRadarChart.data.datasets[0].data = [5, 90, 5];
      } else {
        threatRadarChart.data.datasets[0].data = [95, 2, 3];
      }
      threatRadarChart.update();
    }
  } catch (err) {
    console.warn('Feature poll failed:', err);
  }
}

// ----------------- ALERTS -----------------
async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const data = await res.json();
    const tbody = document.getElementById('alertsTableBody');
    tbody.innerHTML = '';

    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No active security alerts. System normal.</td></tr>';
      return;
    }

    data.alerts.forEach(a => {
      const tr = document.createElement('tr');
      const badgeClass = a.severity === 'critical' ? 'badge-critical' : (a.severity === 'high' ? 'badge-high' : 'badge-medium');
      tr.innerHTML = `
        <td><strong>${a.alert_id}</strong></td>
        <td>${a.timestamp}</td>
        <td><span class="badge ${badgeClass}">${a.severity}</span></td>
        <td>${a.threat_type}</td>
        <td>${(a.confidence_score * 100).toFixed(1)}%</td>
        <td><code>${a.affected_resource}</code></td>
        <td><span class="badge ${a.status === 'active' ? 'badge-critical' : 'badge-low'}">${a.status}</span></td>
        <td>
          ${a.status === 'active' ? `<button class="btn" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="acknowledgeAlert('${a.alert_id}')">Acknowledge</button>` : `<span style="color:var(--text-muted)">Resolved</span>`}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading alerts:', err);
  }
}

async function acknowledgeAlert(alertId) {
  try {
    await fetch(`/api/alerts/${alertId}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'acknowledged' })
    });
    appendLog(`Alert ${alertId} marked as acknowledged by analyst`, 'benign');
    loadAlerts();
    fetchStatus();
  } catch (err) {
    alert('Failed to acknowledge alert: ' + err.message);
  }
}

// ----------------- ATTACK LOG -----------------
async function loadAttackLog() {
  try {
    const res = await fetch('/api/attacks/log');
    const data = await res.json();
    const tbody = document.getElementById('attacksTableBody');
    tbody.innerHTML = '';

    if (!data.attacks || data.attacks.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No historical attacks logged.</td></tr>';
      return;
    }

    data.attacks.forEach(atk => {
      const tr = document.createElement('tr');
      const badgeClass = atk.severity === 'critical' ? 'badge-critical' : 'badge-high';
      tr.innerHTML = `
        <td><strong>${atk.attack_id}</strong></td>
        <td>${atk.detected_at}</td>
        <td>${atk.attack_type}</td>
        <td><span class="badge ${badgeClass}">${atk.severity}</span></td>
        <td>${(atk.confidence * 100).toFixed(1)}%</td>
        <td><code>${atk.affected_resource}</code></td>
        <td style="font-size:0.75rem; color:var(--text-secondary);">${atk.top_signals || 'Shannon Entropy Burst, Mass Extensions'}</td>
        <td><span class="badge badge-low">${atk.mitigation_status}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading attacks:', err);
  }
}

// ----------------- POISONING DEFENSE -----------------
async function loadQuarantine() {
  try {
    const res = await fetch('/api/poisoning/quarantine');
    const data = await res.json();
    const tbody = document.getElementById('quarantineTableBody');
    tbody.innerHTML = '';

    if (!data.quarantined_samples || data.quarantined_samples.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Quarantine store is currently empty.</td></tr>';
      return;
    }

    data.quarantined_samples.forEach(q => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${q.quarantine_id}</strong></td>
        <td>${q.quarantined_at}</td>
        <td><span class="badge badge-high">${q.reason_code}</span></td>
        <td>${q.outlier_score ? q.outlier_score.toFixed(3) : 'N/A'}</td>
        <td>${q.knn_agreement !== null ? (q.knn_agreement * 100).toFixed(0) + '%' : 'N/A'}</td>
        <td><span class="badge badge-critical">${q.disposition}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading quarantine:', err);
  }
}

async function triggerPoisoningDefense() {
  const sel = document.getElementById('selectDataset').value;
  appendLog(`[Poisoning Defense] Inspecting candidate batch ${sel}...`, 'modify');
  
  try {
    const res = await fetch('/api/poisoning/trigger-defense', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset: sel })
    });
    const data = await res.json();
    
    const box = document.getElementById('sanitizationResultBox');
    const content = document.getElementById('sanitizationSummaryContent');
    box.style.display = 'block';
    
    const rep = data.report;
    const gate = data.validation_gate;
    
    const isApproved = gate.status === 'APPROVED_FOR_DEPLOYMENT';
    const statusColor = isApproved ? 'var(--accent-green)' : 'var(--accent-rose)';
    
    content.innerHTML = `
      <div><strong>Total Inspected:</strong> ${rep.total_samples_inspected} candidate samples</div>
      <div><strong>Flagged & Quarantined:</strong> <span style="color:var(--accent-rose); font-weight:bold;">${rep.poisoned_samples_flagged}</span> corrupted samples isolated</div>
      <div><strong>Sanitized Clean Retained:</strong> ${rep.clean_samples_retained} samples</div>
      <div><strong>Validation Gate F1-Score:</strong> ${(gate.validation_f1 * 100).toFixed(2)}% (Regression: ${(gate.regression_observed * 100).toFixed(2)}%)</div>
      <div style="margin-top:0.5rem; font-weight:bold; color:${statusColor};">Retraining Gate Verdict: ${gate.status}</div>
    `;
    
    appendLog(`[Poisoning Defense] Sanitization completed: ${rep.poisoned_samples_flagged} poisoned samples quarantined. Gate: ${gate.status}`, isApproved ? 'benign' : 'alert');
    loadQuarantine();
    fetchStatus();
  } catch (err) {
    alert('Poisoning defense execution failed: ' + err.message);
  }
}

// ----------------- SIMULATOR TRIGGERS -----------------
async function triggerSimulatedAttack() {
  const notif = document.getElementById('simNotification');
  notif.innerText = '⚡ Simulating rapid mass encryption in dummy sandbox...';
  appendLog('🚨 SIMULATED RANSOMWARE ENCRYPTION COMMENCED ON DUMMY DRIVE', 'alert');
  
  try {
    const res = await fetch('/api/sandbox/simulate-attack', { method: 'POST' });
    const data = await res.json();
    
    notif.innerText = `💥 Encrypted ${data.encrypted_files_count} files! Alert ID: ${data.detection_result.alert_id || 'Triggered'}`;
    appendLog(`[DETECTOR] Verdict: ${data.detection_result.verdict.toUpperCase()} (Confidence: ${(data.detection_result.composite_score * 100).toFixed(1)}%) | Entropy: ${data.computed_feature_row.mean_entropy}`, 'alert');
    
    fetchRecentFeatures();
    fetchStatus();
  } catch (err) {
    notif.innerText = 'Simulation failed: ' + err.message;
  }
}

async function triggerSimulatedBenign() {
  const notif = document.getElementById('simNotification');
  notif.innerText = '📁 Executing routine benign workload in sandbox...';
  appendLog('📁 Benign file read/modify workload simulated. Normal entropy maintained.', 'benign');
  
  try {
    const res = await fetch('/api/sandbox/simulate-benign', { method: 'POST' });
    const data = await res.json();
    
    notif.innerText = `📁 Processed ${data.events_count} benign events. Verdict: ${data.detection_result.verdict}`;
    appendLog(`[DETECTOR] Verdict: ${data.detection_result.verdict.toUpperCase()} | Entropy: ${data.computed_feature_row.mean_entropy}`, 'benign');
    
    fetchRecentFeatures();
    fetchStatus();
  } catch (err) {
    notif.innerText = 'Simulation failed: ' + err.message;
  }
}

function printReportSummary() {
  window.print();
}

// ----------------- STARTUP -----------------
window.addEventListener('DOMContentLoaded', () => {
  initCharts();
  fetchStatus();
  fetchRecentFeatures();
  
  // Set real-time polling intervals
  setInterval(fetchStatus, 3000);
  setInterval(fetchRecentFeatures, 3000);
});
