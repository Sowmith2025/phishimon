// PhishGuard AI - Content Script

(function () {
  console.log("PhishGuard AI Content Script Active");

  // Check current page URL on load
  chrome.runtime.sendMessage({ type: "CHECK_URL", url: window.location.href }, (response) => {
    if (response && response.prediction === "PHISHING") {
      showPhishingTopBanner(response);
    }
  });

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "URL_ANALYSIS_RESULT") {
      if (message.data && message.data.prediction === "PHISHING") {
        showPhishingTopBanner(message.data);
      }
    }
  });

  function showPhishingTopBanner(data) {
    if (document.getElementById("phishguard-alert-banner")) return;

    const confidence = (data.confidence || data.phishing_score || 99.0).toFixed(1);

    const banner = document.createElement("div");
    banner.id = "phishguard-alert-banner";
    banner.style.cssText = "position:fixed; top:0; left:0; width:100%; z-index:2147483647; background:linear-gradient(135deg, #DC2626, #991B1B); color:white; padding:14px 24px; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; box-shadow:0 10px 30px rgba(0,0,0,0.5); display:flex; align-items:center; justify-content:space-between; border-bottom:3px solid #EF4444; animation:slideDown 0.4s ease-out;";
    banner.innerHTML = `
      <div style="display:flex; align-items:center; gap:16px;">
        <span style="font-size:28px;">🚨</span>
        <div>
          <div style="font-weight:700; font-size:16px; letter-spacing:0.5px; margin-bottom:2px;">PHISHGUARD SECURITY ALERT: PHISHING WEBSITE DETECTED</div>
          <div style="font-size:13px; opacity:0.95;">This website has been flagged as a dangerous phishing threat with <strong>${confidence}% Threat Confidence</strong>. Do not enter passwords or personal credentials.</div>
        </div>
      </div>
      <button id="pg-close-banner-btn" style="background:rgba(255,255,255,0.25); border:1px solid rgba(255,255,255,0.4); color:white; padding:8px 18px; border-radius:6px; font-weight:700; font-size:13px; cursor:pointer; transition:all 0.2s ease;">I Understand the Risk</button>
    `;

    document.body.prepend(banner);

    document.getElementById("pg-close-banner-btn").addEventListener("click", () => {
      banner.remove();
    });
  }

  function extractRealUrl(href) {
    if (!href) return null;
    if (href.includes("google.com/url?")) {
      try {
        const urlObj = new URL(href);
        const target = urlObj.searchParams.get("q");
        if (target) return target;
      } catch (e) {}
    }
    return href;
  }

  function isSuspiciousPhishingLink(url) {
    if (!url) return false;
    let lower = url.toLowerCase();
    
    // Ignore safe image proxies, static content, and standard platforms
    if (lower.includes("googleusercontent.com") || lower.includes("gstatic.com") || lower.includes("schema.org") || lower.includes("w3.org")) {
      return false;
    }
    
    // Explicit suspicious phishing indicators: IP address, credential harvesting terms
    const hasIp = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(lower);
    const suspiciousKeywords = ["verify-auth", "update-login", "paypal-secure", "bank-billing", "account-verify", "login.php?user="];
    const hasSuspiciousKw = suspiciousKeywords.some(kw => lower.includes(kw));
    
    return hasIp || hasSuspiciousKw;
  }

  function extractSenderEmail(container) {
    const emailView = container.closest(".ii") || container;
    
    // Search in header parent nodes
    const headerNodes = [
      emailView.closest(".gE, .gs, .gK, [role='region']"),
      emailView.parentElement,
      document.body
    ];

    for (let parent of headerNodes) {
      if (!parent) continue;

      // Check attributes
      const attrEl = parent.querySelector("[email*='@'], [data-hovercard-id*='@']");
      if (attrEl) {
        const val = attrEl.getAttribute("email") || attrEl.getAttribute("data-hovercard-id");
        if (val && val.includes("@")) return val.toLowerCase().trim();
      }

      // Check text in sender class names
      const textEl = parent.querySelector(".gD, .go, [email]");
      if (textEl) {
        const text = textEl.innerText || textEl.textContent || "";
        const match = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (match && match[0]) return match[0].toLowerCase().trim();
      }
    }

    return "";
  }

  const SCRIPT_VERSION = "v7.0";

  function analyzeOpenEmail() {
    // Target email containers across Gmail, Outlook, Yahoo Mail
    const emailContainers = document.querySelectorAll(".a3s, [aria-label='Message body'], .ItemBody");
    
    emailContainers.forEach(container => {
      // Find top parent email container view to prevent duplicate injections
      const emailView = container.closest(".ii") || container;
      const emailText = (container.innerText || "").trim();

      if (emailText.length < 15) return;

      // If script version changed or not set, reset cached scanning state
      if (emailView.dataset.phishguardScriptVer !== SCRIPT_VERSION) {
        delete emailView.dataset.phishguardScannedText;
        emailView.dataset.phishguardScriptVer = SCRIPT_VERSION;
        const oldBanners = document.querySelectorAll(".phishguard-email-warning");
        oldBanners.forEach(b => b.remove());
      }

      // Extract sender email address from DOM
      const senderEmail = extractSenderEmail(container);

      // Skip if this exact email text is currently scanning or already processed
      if (emailView.dataset.phishguardScanning === "true") return;
      if (emailView.dataset.phishguardScannedText === emailText) return;

      // 1. Extract embedded link from DOM elements
      let extractedUrl = null;
      const links = container.querySelectorAll("a[href]");
      for (let a of links) {
        let realUrl = extractRealUrl(a.href);
        if (realUrl && realUrl.startsWith("http")) {
          let lower = realUrl.toLowerCase();
          if (!lower.includes("mail.google.com") && !lower.includes("gmail.com") && !lower.includes("google.com/mail")) {
            extractedUrl = realUrl;
            break;
          }
        }
      }

      // 2. Fallback: Extract plain text URLs inside email body using regex
      if (!extractedUrl) {
        const urlMatches = emailText.match(/https?:\/\/[^\s<>"]+/i);
        if (urlMatches && urlMatches[0]) {
          extractedUrl = urlMatches[0];
        }
      }

      emailView.dataset.phishguardScanning = "true";

      // Run Hybrid AI Threat Analysis (URL + Email Text + Sender Domain)
      chrome.runtime.sendMessage(
        { type: "CHECK_HYBRID", url: extractedUrl, text: emailText, sender: senderEmail },
        (response) => {
          emailView.dataset.phishguardScanning = "false";
          emailView.dataset.phishguardScannedText = emailText;

          // Clean up any existing banners in this view
          const oldBanners = document.querySelectorAll(".phishguard-email-warning");
          oldBanners.forEach(b => b.remove());

          if (!response || response.status === "error") return;

          const isEmailPhish = response.email_prediction === "PHISHING";
          const isHybridPhish = response.hybrid_prediction === "PHISHING";
          const isUrlPhish = response.url_prediction === "PHISHING";

          const isThreat = isEmailPhish || isHybridPhish || (extractedUrl && isUrlPhish);
          if (!isThreat) {
            return;
          }

          injectEmailWarningBanner(container, response);
        }
      );
    });
  }

  function injectEmailWarningBanner(container, result) {
    if (!result) return;
    
    const existing = container.querySelector(".phishguard-email-warning") || document.querySelector(".phishguard-email-warning");
    if (existing) existing.remove();

    const threatRisk = result.phishing_score !== undefined ? result.phishing_score : (result.probability_phishing || result.combined_score || 0);

    // Guard: Inject warning banner if Threat Risk is >= 50.0% OR hybrid prediction is PHISHING
    if (threatRisk < 50.0 && result.hybrid_prediction !== "PHISHING") {
      return;
    }

    const warningEl = document.createElement("div");
    warningEl.className = "phishguard-email-warning";
    warningEl.style.cssText = "margin:0 0 16px 0; padding:14px 18px; background:linear-gradient(135deg, #DC2626, #991B1B); color:white; border-radius:8px; font-weight:600; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display:flex; align-items:center; justify-content:space-between; box-shadow:0 4px 12px rgba(220,38,38,0.4); z-index:2147483647;";
    warningEl.innerHTML = `
      <div style="display:flex; align-items:center; gap:10px;">
        <span style="font-size:22px;">🚨</span>
        <div>
          <div style="font-size:14px; font-weight:700; letter-spacing:0.5px;">PHISHGUARD SECURITY ALERT: PHISHING EMAIL DETECTED</div>
          <div style="font-size:12px; font-weight:400; opacity:0.95; margin-top:2px;">This email contains suspicious phishing indicators (${threatRisk.toFixed(1)}% Threat Risk). Do not click links or enter passwords.</div>
        </div>
      </div>
    `;

    container.prepend(warningEl);
  }

  // Observe DOM changes and poll for Gmail / Outlook email navigation
  analyzeOpenEmail();
  setInterval(analyzeOpenEmail, 1000);

  const observer = new MutationObserver(() => {
    analyzeOpenEmail();
  });

  observer.observe(document.body, { childList: true, subtree: true });
})();
