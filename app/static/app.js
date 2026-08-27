const state = { results: [], apiKey: localStorage.getItem('red-team-api-key') || 'local-dev-key' };
const $ = (id) => document.getElementById(id);
$('api-key').value = state.apiKey;
const escapeHtml = (value) => String(value || '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));

function setHealth(online, label) {
  $('health-dot').classList.toggle('online', online);
  $('health-label').textContent = label;
}

function statusBadge(status) {
  const normalized = status === 'blocked' ? 'blocked' : status === 'flagged' ? 'flagged' : 'passed';
  return `<span class="badge badge-${normalized}">${status}</span>`;
}

function renderResults() {
  const filter = $('family-filter').value;
  const visible = state.results.filter((item) => filter === 'all' || item.family === filter);
  $('results-body').innerHTML = visible.length ? visible.map((item) => `
    <tr>
      <td>${escapeHtml(item.name)}</td>
      <td class="family">${escapeHtml(item.family)}</td>
      <td>${statusBadge(item.status)}</td>
      <td class="severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</td>
      <td class="score">${item.metrics.score}</td>
      <td class="evidence" title="${escapeHtml(item.evidence || 'No evidence recorded')}">${escapeHtml(item.evidence || 'No evidence recorded')}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="empty-state">No scenarios match this filter.</td></tr>';
}

function renderCategories() {
  const categories = {};
  state.results.forEach((item) => { categories[item.family] = Math.max(categories[item.family] || 0, item.metrics.score); });
  const entries = Object.entries(categories);
  $('category-list').innerHTML = entries.length ? entries.map(([family, score]) => `
    <div class="category"><div class="category-title"><span>${family}</span><span>${score}/100</span></div><div class="category-meter"><span style="width: ${score}%"></span></div></div>`).join('') : '<p class="empty-state">No category data yet.</p>';
}

function renderHistory(runs) {
  $('history-list').innerHTML = runs.length ? runs.map((run, index) => `
    <article class="history-item"><small>${new Date(run.created_at).toLocaleString()}</small><strong>${run.overall_score}<span class="trend">/100</span></strong><small>${run.total_attacks} attacks / ${run.blocked_attacks} blocked${index === 0 ? ' / latest' : ''}</small></article>`).join('') : '<p class="empty-state">No persisted runs yet.</p>';
}

function renderDashboard(payload) {
  state.results = payload.results || [];
  const blocked = state.results.filter((item) => item.status === 'blocked').length;
  const review = state.results.filter((item) => item.status !== 'blocked').length;
  const score = state.results.length ? Math.round(state.results.reduce((sum, item) => sum + item.metrics.score, 0) / state.results.length) : 0;
  $('score-value').textContent = score;
  $('score-meter').style.width = `${score}%`;
  $('score-caption').textContent = `${blocked} of ${state.results.length} scenarios blocked`;
  $('total-value').textContent = payload.total_attacks ?? state.results.length;
  $('blocked-value').textContent = blocked;
  $('blocked-caption').textContent = blocked ? 'Controls stopped the attack' : 'No blocked attacks yet';
  $('review-value').textContent = review;
  $('last-run').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const families = [...new Set(state.results.map((item) => item.family))];
  $('family-filter').innerHTML = '<option value="all">All families</option>' + families.map((family) => `<option value="${family}">${family}</option>`).join('');
  renderResults();
  renderCategories();
}

async function loadDashboard() {
  $('run-button').disabled = true;
  $('run-button').textContent = 'Running...';
  $('error-message').textContent = '';
  state.apiKey = $('api-key').value.trim();
  localStorage.setItem('red-team-api-key', state.apiKey);
  try {
    const response = await fetch('/attack-runs', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-API-Key': state.apiKey }, body: '{}' });
    if (!response.ok) {
      if (response.status === 401) throw new Error('API key missing or invalid. Enter it above and retry.');
      throw new Error(`Suite returned HTTP ${response.status}`);
    }
    const run = await response.json();
    renderDashboard({ ...run, results: run.results });
    const historyResponse = await fetch('/history', { headers: { Accept: 'application/json', 'X-API-Key': state.apiKey } });
    if (historyResponse.ok) renderHistory((await historyResponse.json()).runs);
    setHealth(true, 'Service online');
  } catch (error) {
    setHealth(false, 'Service unavailable');
    $('error-message').textContent = error.message;
  } finally {
    $('run-button').disabled = false;
    $('run-button').textContent = 'Run attack suite';
  }
}

$('run-button').addEventListener('click', loadDashboard);
$('family-filter').addEventListener('change', renderResults);
loadDashboard();
