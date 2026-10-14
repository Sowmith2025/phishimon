// PhishGuard AI - Background Service Worker (Manifest V3)

importScripts("config.js");

const API_BASE = self.PHISHGUARD_API_BASE || "http://127.0.0.1:5000/api";

// Cache for URL classification results
const urlCache = new Map();

async function checkUrlSafety(url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("chrome-extension://")) {
    return { status: "ignored" };
  }

  if (urlCache.has(url)) {
    return urlCache.get(url);
  }

  try {
    const response = await fetch(`${API_BASE}/predict/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) return { status: "error" };

    const data = await response.json();
    urlCache.set(url, data);
    return data;
  } catch (err) {
    console.error("PhishGuard API connection error:", err);
    return { status: "offline" };
  }
}

async function updateBadge(tabId, result) {
  // Messages initiated from extension/devtools contexts may not belong to a
  // browser tab. Chrome represents that situation with tabId -1.
  if (!Number.isInteger(tabId) || tabId < 0) {
    return;
  }

  if (!result || result.status === "ignored" || result.status === "offline") {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  if (result.prediction === "PHISHING") {
    chrome.action.setBadgeText({ tabId, text: "RISK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" }); // Red
  } else if (result.prediction === "LEGITIMATE") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" }); // Green
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// Monitor tab updates
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    const result = await checkUrlSafety(tab.url);
    await updateBadge(tabId, result);

    // Notify content script of page analysis result
    chrome.tabs.sendMessage(tabId, { type: "URL_ANALYSIS_RESULT", data: result }).catch(() => {
      // Content script may not be loaded yet
    });
  }
});

// Listen for messages from content.js or popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    checkUrlSafety(message.url).then(res => {
      if (sender.tab) updateBadge(sender.tab.id, res);
      sendResponse(res);
    });
    return true; // Keep async channel open
  }

  if (message.type === "CHECK_EMAIL") {
    fetch(`${API_BASE}/predict/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email_text: message.text, sender_email: message.sender })
    })
      .then(res => res.json())
      .then(data => sendResponse(data))
      .catch(err => sendResponse({ status: "error", message: err.message }));
    return true;
  }

  if (message.type === "CHECK_HYBRID") {
    fetch(`${API_BASE}/predict/hybrid`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: message.url, email_text: message.text, sender_email: message.sender })
    })
      .then(res => res.json())
      .then(data => sendResponse(data))
      .catch(err => sendResponse({ status: "error", message: err.message }));
    return true;
  }
});
