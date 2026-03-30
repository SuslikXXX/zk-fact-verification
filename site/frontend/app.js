document.getElementById('lookupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const verifierIdHash = document.getElementById('verifierIdHash').value;
    const subjectTag = document.getElementById('subjectTag').value;
    const factTypeHash = document.getElementById('factTypeHash').value;

    const params = new URLSearchParams({
        verifier_id_hash: verifierIdHash,
        subject_tag: subjectTag,
        fact_type_hash: factTypeHash,
    });

    try {
        const res = await fetch(`/api/status?${params}`);
        const data = await res.json();
        const resultDiv = document.getElementById('result');
        if (data.fact_valid) {
            resultDiv.innerHTML = '<div class="success">Fact VERIFIED on-chain</div>';
        } else {
            resultDiv.innerHTML = `<div class="error">Fact not found: ${data.message}</div>`;
        }
        resultDiv.innerHTML += `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    } catch (err) {
        document.getElementById('result').innerHTML = `<div class="error">Error: ${err.message}</div>`;
    }
});
