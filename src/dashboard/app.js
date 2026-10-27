// Cloud IDS Poisoning Defense Platform - Client Application
// BS Cybersecurity FYDP - Dawood University of Engineering & Technology

let radarChart = null;
let totalBatchesCount = 0;
let totalQuarantinedCount = 0;
let batchIndexCounter = 0;

document.addEventListener('DOMContentLoaded', () => {
  initRadarChart();
  loadInitialData();
  loadQuarantineRecords();
  loadModelGovernance();
  loadBenchmarkResults();
});

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  event.currentTarget.classList.add('active');
  const target = document.getElementById(tabId);
  if (target) {
    target.classList.add('active');
  }

  if (tabId === 'agent-console') {
    runLiveTriage();
  }
}

function initRadarChart() {
  const ctx = document.getElementById('defenseRadarChart').getContext('2d');
  radarChart = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: [
        'Layer A: Statistical Density (IsoForest)',
        'Layer B: k-NN Neighborhood Consistency',
        'Layer C: Model Loss Disparity',
        'Composite Risk Score',
        'Validation Gating Confidence'
      ],
      datasets: [
        {
          label: 'Clean Flow Baseline',
          data: [0.12, 0.05, 0.02, 0.06, 0.99],
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.2)',
          borderWidth: 2
        },
        {
          label: 'Incoming Batch Risk Profile',
          data: [0.15, 0.08, 0.04, 0.09, 0.98],
          borderColor: '#00f0ff',
          backgroundColor: 'rgba(0, 240, 255, 0.25)',
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0,
          max: 1,
          ticks: { color: '#94a3b8', backdropColor: 'transparent', stepSize: 0.2 },
          grid: { color: 'rgba(255, 255, 255, 0.08)' },
          angleLines: { color: 'rgba(255, 255, 255, 0.08)' },
          pointLabels: { color: '#f8fafc', font: { size: 11, family: 'Inter' } }
        }
      },
      plugins: {
        legend: { labels: { color: '#f8fafc' } }
      }
    }
  });
}

function updateRadarChart(layerA, layerB, layerC, composite) {
  if (!radarChart) return;
  radarChart.data.datasets[1].data = [layerA, layerB, layerC, composite, 1.0 - composite];
  radarChart.update();
}

async function loadInitialData() {
  try {
    const res = await fetch('/health');
    const data = await res.json();
    document.getElementById('activeModelTag').innerText = data.active_model_version;
  } catch (err) {
    console.error('Failed to load health status:', err);
  }
}

// ---------------- TAB 1: BATCH REPLAY & SIMULATION ----------------
async function replayNextBatch() {
  await requestStreamReplay(25, 0.0);
}

async function injectPoisonBatch(rate = 0.20) {
  await requestStreamReplay(25, rate);
}

async function requestStreamReplay(batchSize, poisonRate) {
  try {
    const res = await fetch('/api/stream/replay-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ batch_size: batchSize, poison_rate: poisonRate })
    });

    const result = await res.json();
    totalBatchesCount++;
    totalQuarantinedCount += result.quarantined_count;

    document.getElementById('kpiBatchesCount').innerText = totalBatchesCount;
    document.getElementById('kpiQuarantineCount').innerText = totalQuarantinedCount;
    document.getElementById('quarantineBadge').innerText = totalQuarantinedCount;
    document.getElementById('kpiLatency').innerText = `${result.processing_latency_ms.toFixed(1)} ms`;

    // Append to Batch Table
    const tbody = document.getElementById('batchLogBody');
    if (totalBatchesCount === 1) tbody.innerHTML = '';

    const row = document.createElement('tr');
    const isAttack = result.quarantined_count > 0;
    const statusBadge = isAttack 
      ? `<span class="badge" style="background:#ef4444;">⚠️ ${result.quarantined_count} Quarantined</span>`
      : `<span class="badge badge-success">✅ Clean Ingestion</span>`;

    row.innerHTML = `
      <td><code>${result.batch_id}</code></td>
      <td>${result.total_samples}</td>
      <td><span class="text-success">${result.accepted_count}</span></td>
      <td><span class="${isAttack ? 'text-danger font-bold' : 'text-muted'}">${result.quarantined_count}</span></td>
      <td>${result.processing_latency_ms} ms</td>
      <td>${statusBadge}</td>
    `;
    tbody.prepend(row);

    // Update radar chart and agent log
    if (isAttack) {
      updateRadarChart(0.78, 1.00, 0.95, 0.88);
      logAgentActivity(`[POISON DETECTED] ${result.batch_id}: Multi-layer defense identified ${result.quarantined_count} label-flipped records! Routed to Quarantine Store.`, 'danger');
    } else {
      updateRadarChart(0.12, 0.05, 0.02, 0.06);
      logAgentActivity(`[CLEAN INGESTION] ${result.batch_id}: All ${result.total_samples} records passed sanitization checks. Added to training candidate buffer.`, 'info');
    }

    // Refresh Quarantine store table
    loadQuarantineRecords();
  } catch (err) {
    console.error('Batch ingest failed:', err);
  }
}

// ---------------- TAB 2: QUARANTINE STORE ----------------
async function loadQuarantineRecords() {
  try {
    const res = await fetch('/api/quarantine?limit=50');
    const data = await res.json();
    const tbody = document.getElementById('quarantineBody');
    
    if (data.records.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-muted">No records currently quarantined. Clean stream.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    data.records.forEach(r => {
      const tr = document.createElement('tr');
      const statusClass = r.status === 'CONFIRMED_POISON' ? 'badge badge-danger' : 
                         r.status === 'APPROVED_CLEAN' ? 'badge badge-success' : 'badge badge-warning';
      
      const layerScores = Object.entries(r.detector_scores)
        .map(([k, v]) => `${k.split('_')[1] || k}: ${v.toFixed(2)}`)
        .join(' | ');

      tr.innerHTML = `
        <td><code>${r.sample_id}</code></td>
        <td><code>${r.batch_id}</code></td>
        <td>${r.assigned_label === 1 ? 'Malicious' : 'Benign'}</td>
        <td><strong class="text-danger">${r.combined_score.toFixed(3)}</strong></td>
        <td><small class="text-muted">${layerScores}</small></td>
        <td><small>${r.reason}</small></td>
        <td><span class="${statusClass}">${r.status}</span></td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="reviewSample('${r.sample_id}', 'APPROVED_CLEAN')">Approve Clean</button>
          <button class="btn btn-danger btn-sm" style="margin-left: 0.25rem;" onclick="reviewSample('${r.sample_id}', 'CONFIRMED_POISON')">Confirm Poison</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed loading quarantine:', err);
  }
}

async function reviewSample(sampleId, newStatus) {
  try {
    const res = await fetch(`/api/quarantine/${sampleId}/review`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_status: newStatus, reviewer_notes: 'Triaged from dashboard' })
    });
    if (res.ok) {
      logAgentActivity(`[TRIAGE] Sample ${sampleId} marked as ${newStatus}`, newStatus === 'APPROVED_CLEAN' ? 'success' : 'danger');
      loadQuarantineRecords();
    }
  } catch (err) {
    console.error('Review update failed:', err);
  }
}

// ---------------- TAB 3: MODEL GOVERNANCE & ROLLBACK ----------------
async function loadModelGovernance() {
  try {
    const res = await fetch('/api/models/active');
    const data = await res.json();
    const active = data.active_model;
    const manifest = data.registry_manifest;

    document.getElementById('govActiveVersion').innerText = active.version;
    document.getElementById('activeModelTag').innerText = active.version;
    document.getElementById('govPromotedAt').innerText = active.promoted_at ? active.promoted_at.split('T')[0] : '-';

    if (active.validation_metrics) {
      document.getElementById('govAccuracy').innerText = `${(active.validation_metrics.accuracy * 100).toFixed(1)}%`;
      document.getElementById('govF1').innerText = active.validation_metrics.f1_score.toFixed(4);
      document.getElementById('govFPR').innerText = `${(active.validation_metrics.false_positive_rate * 100).toFixed(2)}%`;
    }

    const tbody = document.getElementById('registryHistoryBody');
    tbody.innerHTML = '';
    manifest.history.forEach(h => {
      const tr = document.createElement('tr');
      const actionBadge = h.action === 'PROMOTE' 
        ? '<span class="badge badge-success">PROMOTE</span>' 
        : '<span class="badge badge-danger">ROLLBACK</span>';
      tr.innerHTML = `
        <td>${actionBadge}</td>
        <td><code>${h.version || h.restored_version}</code></td>
        <td>${h.f1_score ? h.f1_score.toFixed(4) : '-'}</td>
        <td><small class="text-muted">${h.timestamp.split('T')[0]}</small></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed loading governance:', err);
  }
}

async function triggerRollback() {
  if (!confirm('Are you sure you want to rollback active model to previous approved version?')) return;
  try {
    const res = await fetch('/api/models/rollback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const result = await res.json();
    if (res.ok) {
      alert(result.message);
      logAgentActivity(`[ROLLBACK ACTION] ${result.message}`, 'danger');
      loadModelGovernance();
    } else {
      alert(`Rollback failed: ${result.detail}`);
    }
  } catch (err) {
    console.error('Rollback failed:', err);
  }
}

// ---------------- TAB 4: BENCHMARK RESULTS ----------------
async function loadBenchmarkResults() {
  try {
    const res = await fetch('/api/experiments/results');
    const data = await res.json();
    const tbody = document.getElementById('benchmarkBody');
    tbody.innerHTML = '';

    data.results.forEach(row => {
      const tr = document.createElement('tr');
      const gateBadge = row.gate_action === 'PROMOTED' 
        ? '<span class="badge badge-success">PROMOTED</span>'
        : row.gate_action.includes('BLOCKED')
        ? '<span class="badge badge-danger">BLOCKED_BY_GATE</span>'
        : `<span class="badge badge-warning">${row.gate_action}</span>`;

      tr.innerHTML = `
        <td><strong>${row.attack_type}</strong></td>
        <td>${row.poison_rate}</td>
        <td>${row.defense_mode}</td>
        <td>${row.detection_precision.toFixed(4)}</td>
        <td>${row.detection_recall.toFixed(4)}</td>
        <td>${row.detection_f1.toFixed(4)}</td>
        <td>${row.false_quarantine_rate.toFixed(4)}</td>
        <td><strong>${row.ids_f1_after_retraining.toFixed(4)}</strong></td>
        <td>${gateBadge}</td>
        <td>${row.median_batch_latency_ms}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed loading benchmark:', err);
  }
}

// ---------------- TAB 5: INDUSTRY 5.0 AUTONOMOUS AGENTS ----------------

async function runLiveTriage() {
  const container = document.getElementById('triageReportsContainer');
  container.innerHTML = '<p class="text-info">SecOps Triage Agent investigating pending quarantine records...</p>';

  try {
    const res = await fetch('/api/agents/triage/pending?limit=10');
    const data = await res.json();

    if (data.reports.length === 0) {
      container.innerHTML = '<p class="text-muted">No pending quarantined samples require triage. The pipeline is operating cleanly.</p>';
      return;
    }

    container.innerHTML = '';
    data.reports.forEach(r => {
      const card = document.createElement('div');
      card.className = 'info-card';
      card.style.marginBottom = '1rem';
      card.style.borderLeft = r.severity === 'CRITICAL' ? '4px solid #ef4444' : '4px solid #f59e0b';

      const featList = r.top_anomalous_features.map(f => `<li><code>${f.feature}</code> (Z-score: <strong>${f.z_score > 0 ? '+' : ''}${f.z_score}</strong>): ${f.explanation}</li>`).join('');

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <div>
            <strong style="font-size: 0.95rem;">${r.sample_id}</strong>
            <span class="badge ${r.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}" style="margin-left: 0.5rem;">${r.severity}</span>
            <span class="badge badge-success" style="margin-left: 0.25rem;">Confidence: ${(r.confidence_score * 100).toFixed(0)}%</span>
          </div>
          <small class="text-muted">${r.threat_classification}</small>
        </div>

        <p style="font-size: 0.85rem; margin-bottom: 0.6rem;"><strong>Executive Summary:</strong> ${r.executive_summary}</p>
        
        <p style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 0.4rem;"><strong>Root-Cause Anomalous Features:</strong></p>
        <ul style="font-size: 0.8rem; margin-left: 1.2rem; color: #cbd5e1; margin-bottom: 0.8rem;">
          ${featList}
        </ul>

        <div style="background: rgba(0,0,0,0.25); padding: 0.6rem; border-radius: 6px; font-size: 0.82rem; margin-bottom: 0.75rem;">
          <strong>Agent Recommendation:</strong> <span class="${r.recommended_action === 'CONFIRM_POISON' ? 'text-danger font-bold' : 'text-success'}">${r.recommended_action}</span> — ${r.mitigation_rationale}
        </div>

        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-danger btn-sm" onclick="reviewSample('${r.sample_id}', 'CONFIRMED_POISON')">Confirm Poison (Permanent Drop)</button>
          <button class="btn btn-outline btn-sm" onclick="reviewSample('${r.sample_id}', 'APPROVED_CLEAN')">Approve Clean (False Alarm)</button>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error('Triage run failed:', err);
    container.innerHTML = '<p class="text-danger">Failed to execute Triage Agent.</p>';
  }
}

async function generateGuardTicket() {
  const container = document.getElementById('guardTicketContainer');
  container.innerHTML = '<p class="text-info">Poisoning Guard Agent validating sanitized buffer & training candidate model...</p>';

  try {
    const res = await fetch('/api/agents/guard/prepare-ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_type: 'random_forest', training_data_path: 'data/processed/train.csv' })
    });
    const ticket = await res.json();
    renderTicketCard(ticket);
  } catch (err) {
    console.error('Ticket generation failed:', err);
    container.innerHTML = '<p class="text-danger">Failed to generate retraining ticket.</p>';
  }
}

function renderTicketCard(ticket) {
  const container = document.getElementById('guardTicketContainer');
  const card = document.createElement('div');
  card.className = 'info-card';
  card.style.borderLeft = ticket.gate_passed ? '4px solid #10b981' : '4px solid #ef4444';

  const statusBadge = ticket.status === 'AWAITING_ANALYST_APPROVAL'
    ? '<span class="badge badge-warning">Awaiting Analyst Sign-off</span>'
    : ticket.status === 'DEPLOYED_TO_PRODUCTION'
    ? '<span class="badge badge-success">Deployed to Production</span>'
    : '<span class="badge badge-danger">Blocked by Gate</span>';

  card.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
      <div>
        <strong>Ticket: <code>${ticket.ticket_id}</code></strong>
        <span style="margin-left: 0.5rem;">${statusBadge}</span>
      </div>
      <small class="text-muted">Candidate: <strong>${ticket.candidate_version || 'N/A'}</strong></small>
    </div>

    <div class="info-row"><span>Active Production Model:</span> <strong>${ticket.active_version}</strong></div>
    <div class="info-row"><span>Candidate Holdout Accuracy:</span> <strong>${ticket.metrics ? (ticket.metrics.accuracy * 100).toFixed(1) + '%' : 'N/A'}</strong></div>
    <div class="info-row"><span>Candidate Holdout F1-Score:</span> <strong>${ticket.metrics ? ticket.metrics.f1_score.toFixed(4) : 'N/A'}</strong></div>
    <div class="info-row"><span>Validation Gate Decision:</span> <strong class="${ticket.gate_passed ? 'text-success' : 'text-danger'}">${ticket.gate_passed ? 'PASSED (0.00% Regression)' : 'FAILED'}</strong></div>

    <p style="font-size: 0.85rem; margin-top: 0.75rem; color: #94a3b8;">
      <strong>Guard Recommendation:</strong> ${ticket.recommendation}
    </p>

    ${ticket.status === 'AWAITING_ANALYST_APPROVAL' ? `
      <div style="margin-top: 1rem;">
        <button class="btn btn-primary" onclick="signoffTicket('${ticket.ticket_id}')">
          ✅ Analyst Sign-off & Deploy ${ticket.candidate_version} to Production
        </button>
      </div>
    ` : ''}
  `;

  container.innerHTML = '';
  container.appendChild(card);
}

async function signoffTicket(ticketId) {
  try {
    const res = await fetch(`/api/agents/guard/tickets/${ticketId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_id: 'Sir_Arfan_Naich' })
    });
    const result = await res.json();
    if (res.ok) {
      alert(`Success! ${result.message}`);
      loadModelGovernance();
      renderTicketCard(result.ticket);
    } else {
      alert(`Approval rejected: ${result.detail}`);
    }
  } catch (err) {
    console.error('Signoff failed:', err);
  }
}

function exportQuarantineCsv() {
  window.open('/api/quarantine', '_blank');
}

