const API = window.location.origin;

// Load system config on page load
async function loadStatus() {
    try {
        const [health, config] = await Promise.all([
            fetch(`${API}/api/health`).then(r => r.json()),
            fetch(`${API}/api/config`).then(r => r.json()),
        ]);
        const statusDiv = document.getElementById('status');
        statusDiv.innerHTML = `
            <div class="status-item ${health.status === 'ok' ? 'ok' : 'err'}">
                Backend: ${health.status}
            </div>
            <div class="status-item">FactRegistry: <code>${config.fact_registry_address || 'not set'}</code></div>
            <div class="status-item">RPC: <code>${config.ethereum_rpc}</code></div>
            <div class="status-item">Verifier: <code>${config.verifier_id}</code></div>
        `;
        // Pre-fill verifier_id_hash if available
        if (config.verifier_id_hash) {
            document.getElementById('verifierIdHash').value = config.verifier_id_hash;
        }
    } catch (e) {
        document.getElementById('status').innerHTML = `<div class="status-item err">Backend unreachable: ${e.message}</div>`;
    }
}

document.getElementById('lookupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('lookupBtn');
    btn.disabled = true;
    btn.textContent = 'Looking up...';

    const verifierIdHash = document.getElementById('verifierIdHash').value.trim();
    const subjectTag = document.getElementById('subjectTag').value.trim();
    const factTypeHash = document.getElementById('factTypeHash').value.trim();

    const params = new URLSearchParams({
        verifier_id_hash: verifierIdHash,
        subject_tag: subjectTag,
        fact_type_hash: factTypeHash,
    });

    const resultDiv = document.getElementById('result');

    try {
        const res = await fetch(`${API}/api/lookup?${params}`);
        const data = await res.json();

        if (data.error) {
            resultDiv.innerHTML = `<div class="result-card err"><h3>Error</h3><p>${data.error}</p></div>`;
        } else if (data.exists) {
            resultDiv.innerHTML = `
                <div class="result-card ${data.is_valid ? 'valid' : 'expired'}">
                    <h3>${data.is_valid ? 'FACT VERIFIED' : 'FACT FOUND (expired)'}</h3>
                    <table>
                        <tr><td>Status</td><td><strong>${data.is_valid ? 'Valid' : 'Expired'}</strong></td></tr>
                        <tr><td>Verified At</td><td>${data.verified_at}</td></tr>
                        <tr><td>Valid Until</td><td>${data.valid_until}</td></tr>
                        <tr><td>Submitter</td><td><code>${data.submitter}</code></td></tr>
                        <tr><td>Nullifier</td><td><code>${shorten(data.nullifier)}</code></td></tr>
                        <tr><td>Policy Root</td><td><code>${shorten(data.issuer_policy_root)}</code></td></tr>
                        <tr><td>Schema Hash</td><td><code>${shorten(data.schema_hash)}</code></td></tr>
                    </table>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `<div class="result-card not-found"><h3>FACT NOT FOUND</h3><p>No verified fact exists for this subject_tag + fact_type combination.</p></div>`;
        }
    } catch (err) {
        resultDiv.innerHTML = `<div class="result-card err"><h3>Error</h3><p>${err.message}</p></div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Lookup Fact On-Chain';
    }
});

function shorten(hex) {
    if (!hex || hex.length < 20) return hex || '';
    return hex.slice(0, 10) + '...' + hex.slice(-8);
}

loadStatus();
