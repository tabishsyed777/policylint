(() => {
  'use strict';
  const SAMPLE = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"},
    {"Sid": "AdminAccess", "Effect": "Allow", "Action": "iam:*", "Resource": "*"}
  ]
}`;
  const e = { policy: document.querySelector('#policy'), sample: document.querySelector('#sample'), lint: document.querySelector('#lint'), clear: document.querySelector('#clear'), status: document.querySelector('#status'), download: document.querySelector('#download'), score: document.querySelector('#score'), scoreHint: document.querySelector('#scoreHint'), scoreBar: document.querySelector('#scoreBar'), statements: document.querySelector('#statements'), high: document.querySelector('#high'), review: document.querySelector('#review'), findingCount: document.querySelector('#findingCount'), findings: document.querySelector('#findings') };
  let latestReport = null;
  const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
  const array = (value) => value === undefined ? [] : Array.isArray(value) ? value : [value];
  const strings = (value) => array(value).flatMap((item) => typeof item === 'string' ? [item] : item && typeof item === 'object' ? Object.values(item).flatMap(strings) : []);
  function lintPolicy(text) {
    let policy; try { policy = JSON.parse(text); } catch (error) { return { error: 'The policy is not valid JSON. Check commas, quotes, and brackets.' }; }
    const statements = array(policy.Statement); if (!statements.length) return { error: 'No Statement array was found in this policy.' };
    const findings = [];
    statements.forEach((statement, index) => {
      if (!statement || typeof statement !== 'object') return;
      const label = statement.Sid || `Statement ${index + 1}`; const effect = String(statement.Effect || '').toLowerCase(); const actions = strings(statement.Action).map((value) => value.toLowerCase()); const resources = strings(statement.Resource); const principals = strings(statement.Principal); const condition = statement.Condition && Object.keys(statement.Condition).length > 0;
      const add = (kind, title, detail, fix) => findings.push({ severity: kind, title, detail: `${label}: ${detail}`, fix });
      if (effect !== 'allow') return;
      if (principals.some((principal) => principal === '*')) add('critical', 'Public principal', 'This allow statement accepts a wildcard principal.', 'Name the trusted principal or add an explicit trust boundary.');
      if (actions.some((action) => action === '*' || action.endsWith(':*'))) add('high', 'Wildcard action', 'This statement grants an entire service or all actions.', 'List only the API actions this workload needs.');
      const adminVerb = actions.some((action) => action === 'iam:passrole' || /^(iam|kms|organizations|account):\*$/.test(action));
      if (adminVerb) add('critical', 'Control-plane privilege', 'This statement can change identity, key, or account administration.', 'Separate administration from runtime roles and constrain the exact verbs.');
      if (resources.some((resource) => resource === '*')) add('high', 'Wildcard resource', 'This statement applies across every resource in scope.', 'Use resource ARNs or IDs for the workload boundary.');
      if ((principals.some((principal) => principal === '*') || actions.some((action) => action === '*' || action.endsWith(':*')) || resources.some((resource) => resource === '*')) && !condition) add('review', 'Missing condition boundary', 'A broad allow has no condition to narrow when or how it can be used.', 'Add conditions such as source identity, tags, network, or time where your provider supports them.');
    });
    const critical = findings.filter((finding) => finding.severity === 'critical').length; const high = findings.filter((finding) => finding.severity === 'high').length; const review = findings.filter((finding) => finding.severity === 'review').length; const score = Math.max(0, Math.round(100 - critical * 25 - high * 15 - review * 7));
    return { generated_at: new Date().toISOString(), statements: statements.length, summary: { score, critical, high, review, findings: findings.length }, findings };
  }
  function render(report) { latestReport = report; e.score.textContent = report.summary.score; e.scoreHint.textContent = report.summary.score >= 85 ? 'Narrow permission posture' : report.summary.score >= 60 ? 'Review broad grants' : 'Prioritize high-risk grants'; e.scoreBar.style.width = `${report.summary.score}%`; e.statements.textContent = report.statements; e.high.textContent = report.summary.critical + report.summary.high; e.review.textContent = report.summary.review; e.findingCount.textContent = `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}`; e.status.textContent = `Linted ${report.statements} statement${report.statements === 1 ? '' : 's'}`; e.status.classList.add('ready'); e.download.disabled = false; if (!report.findings.length) { e.findings.innerHTML = '<div class="empty"><span>✓</span><strong>No broad grants detected</strong><p>Keep the policy narrow as it evolves and validate against provider semantics.</p></div>'; return; } e.findings.innerHTML = report.findings.map((finding) => `<article class="finding ${finding.severity}"><span class="finding-icon">${finding.severity === 'critical' ? '!' : finding.severity === 'high' ? '▲' : '·'}</span><div><div class="finding-title">${escapeHtml(finding.title)}</div><div class="finding-detail">${escapeHtml(finding.detail)} ${escapeHtml(finding.fix)}</div></div><span class="finding-severity">${escapeHtml(finding.severity.toUpperCase())}</span></article>`).join(''); }
  function run() { const text = e.policy.value.trim(); if (!text) { e.status.textContent = 'Add a policy first'; e.status.classList.remove('ready'); e.policy.focus(); return; } const report = lintPolicy(text); if (report.error) { e.status.textContent = report.error; e.status.classList.remove('ready'); return; } render(report); document.querySelector('#results').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  function clearAll() { e.policy.value = ''; latestReport = null; e.status.textContent = 'Waiting for a policy'; e.status.classList.remove('ready'); e.download.disabled = true; e.score.textContent = '—'; e.scoreHint.textContent = 'Run a lint pass to calculate'; e.scoreBar.style.width = '0'; e.statements.textContent = '—'; e.high.textContent = '—'; e.review.textContent = '—'; e.findingCount.textContent = '0 findings'; e.findings.innerHTML = '<div class="empty"><span>⌬</span><strong>No lint pass yet</strong><p>Load a policy to see specific, explainable permission findings.</p></div>'; }
  e.sample.addEventListener('click', () => { e.policy.value = SAMPLE; run(); }); e.lint.addEventListener('click', run); e.clear.addEventListener('click', clearAll); e.download.addEventListener('click', () => { if (!latestReport) return; const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' })); link.download = 'policylint-report.json'; link.click(); URL.revokeObjectURL(link.href); });
})();
