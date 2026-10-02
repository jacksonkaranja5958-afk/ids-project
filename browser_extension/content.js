document.addEventListener("click", function (event) {
    const link = event.target.closest("a");
    if (!link || !link.href) return;

    // Ignore internal page anchors and non-http links
    if (!link.href.startsWith("http")) return;

    event.preventDefault();
    const targetUrl = link.href;

    fetch("http://127.0.0.1:5000/api/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
    })
    .then(response => response.json())
    .then(data => {
        if (data.verdict === "BLOCK") {
            showWarning(targetUrl, data.reason);
        } else {
            window.location.href = targetUrl;
        }
    })
    .catch(error => {
        console.error("SentinelX check failed, allowing navigation:", error);
        window.location.href = targetUrl;
    });
}, true);


function showWarning(url, reason) {
    const overlay = document.createElement("div");
    overlay.style.cssText = `
        position: fixed; inset: 0; background: #070C16; color: #E2E8F0;
        z-index: 999999; display: flex; align-items: center; justify-content: center;
        font-family: Arial, sans-serif; flex-direction: column; text-align: center; padding: 40px;
    `;
    overlay.innerHTML = `
        <div style="font-size: 48px; margin-bottom: 20px;">⚠</div>
        <h1 style="color: #F87171; margin-bottom: 12px;">SentinelX blocked this link</h1>
        <p style="color: #8B98B3; max-width: 500px; margin-bottom: 8px;">${url}</p>
        <p style="color: #FBBF24; margin-bottom: 30px;">${reason}</p>
        <button id="sentinelx-proceed" style="padding: 10px 20px; background: #1E2A42; color: #E2E8F0; border: 1px solid #F87171; border-radius: 5px; cursor: pointer;">
            Proceed anyway (not recommended)
        </button>
    `;
    document.body.appendChild(overlay);

    document.getElementById("sentinelx-proceed").addEventListener("click", () => {
        window.location.href = url;
    });
}