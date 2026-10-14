// PhishGuard AI - Popup Script

document.addEventListener("DOMContentLoaded", () => {
  const navBtns = document.querySelectorAll(".nav-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  const activeUrlDisplay = document.getElementById("active-url-display");
  const statusBadge = document.getElementById("status-badge");
  const confidenceVal = document.getElementById("confidence-val");
  const progressFill = document.getElementById("progress-fill");
  const probLegit = document.getElementById("prob-legit");
  const probPhish = document.getElementById("prob-phish");

  const manualUrlInput = document.getElementById("manual-url-input");
  const manualEmailInput = document.getElementById("manual-email-input");
  const runManualScanBtn = document.getElementById("run-manual-scan-btn");
  const manualResultBox = document.getElementById("manual-result-box");
  const manualResultHeader = document.getElementById("manual-result-header");
  const manualResultDesc = document.getElementById("manual-result-desc");

  // Tab Switching
  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      navBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
    });
  });

  // Query Active Tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) {
      activeUrlDisplay.textContent = "Unavailable";
      return;
    }

    const currentUrl = tabs[0].url;
    activeUrlDisplay.textContent = currentUrl;

    // Send request to background script
    chrome.runtime.sendMessage({ type: "CHECK_URL", url: currentUrl }, (response) => {
      renderActiveTabResults(response);
    });
  });

  function renderActiveTabResults(result) {
    if (!result || result.status === "error" || result.status === "ignored") {
      statusBadge.textContent = "NOT APPLICABLE";
      statusBadge.className = "status-badge";
      confidenceVal.textContent = "--%";
      progressFill.style.width = "0%";
      probLegit.textContent = "--%";
      probPhish.textContent = "--%";
      return;
    }

    const isPhishing = result.prediction === "PHISHING";
    const confidence = result.confidence || 0;

    statusBadge.textContent = isPhishing ? "HIGH PHISHING RISK" : "LEGITIMATE & SAFE";
    statusBadge.className = `status-badge ${isPhishing ? 'danger' : 'safe'}`;

    confidenceVal.textContent = `${confidence.toFixed(1)}%`;
    confidenceVal.style.color = isPhishing ? "#EF4444" : "#10B981";

    progressFill.style.width = `${confidence}%`;
    progressFill.style.background = isPhishing ? "#EF4444" : "#10B981";

    probLegit.textContent = `${result.probability_legitimate.toFixed(1)}%`;
    probPhish.textContent = `${result.probability_phishing.toFixed(1)}%`;
  }

  // Manual Scanner Event Listener
  runManualScanBtn.addEventListener("click", () => {
    const urlVal = manualUrlInput.value.trim();
    const emailVal = manualEmailInput.value.trim();

    if (!urlVal && !emailVal) {
      alert("Please enter a custom URL or paste email text to analyze.");
      return;
    }

    runManualScanBtn.textContent = "⏳ Analyzing Threat Indicators...";
    runManualScanBtn.disabled = true;

    chrome.runtime.sendMessage(
      { type: "CHECK_HYBRID", url: urlVal, text: emailVal },
      (response) => {
        runManualScanBtn.textContent = "⚡ Run AI Threat Analysis";
        runManualScanBtn.disabled = false;

        if (!response || response.status === "error") {
          manualResultBox.classList.remove("hidden");
          manualResultHeader.textContent = "ANALYSIS ERROR";
          manualResultHeader.style.color = "#EF4444";
          manualResultDesc.textContent = response ? response.message : "Failed to connect to API server.";
          return;
        }

        manualResultBox.classList.remove("hidden");
        const isPhish = response.hybrid_prediction === "PHISHING" || response.url_prediction === "PHISHING" || response.email_prediction === "PHISHING";
        const confidence = response.hybrid_confidence || response.confidence || response.phishing_score || 99.0;

        manualResultHeader.textContent = `RESULT: ${isPhish ? 'PHISHING THREAT DETECTED' : 'LEGITIMATE & SAFE'} (${confidence.toFixed(1)}% Confidence)`;
        manualResultHeader.style.color = isPhish ? "#EF4444" : "#10B981";

        manualResultDesc.textContent = response.reasoning || (isPhish ? "High threat risk detected." : "Safe website.");

        // If Phishing detected, inject Top Security Alert Banner onto active tab
        if (isPhish) {
          chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
            if (activeTabs && activeTabs[0] && activeTabs[0].id) {
              chrome.tabs.sendMessage(activeTabs[0].id, {
                type: "URL_ANALYSIS_RESULT",
                data: { prediction: "PHISHING", confidence: confidence }
              }).catch(() => {});
            }
          });
        }
      }
    );
  });
});
