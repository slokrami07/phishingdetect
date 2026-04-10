// src/background/index.ts

const API_BASE = "http://127.0.0.1:5000";

// --- 1. Message Handling (Popup & Content Script Communication) ---
chrome.runtime.onMessage.addListener((msg: any, sender, sendResponse) => {
  
  // Feature: Close Tab Button
  if (msg.type === "closeCurrentTab") {
    if (sender.tab?.id) {
      chrome.tabs.remove(sender.tab.id);
    }
  }

  // Feature: Deep Scan Request
  if (msg.type === "triggerDeepScan" && msg.url) {
    fetch(`${API_BASE}/api/scan`, { // Check if your endpoint is /scan or /deep-scan
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: msg.url, deep_scan: true }),
    })
    .then(async (res) => {
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Scan failed");
      
      sendResponse({ ok: true, data });

      // If deep scan finds it malicious, alert the tab immediately
      if (data.verdict === "malicious" && sender.tab?.id) {
         chrome.tabs.sendMessage(sender.tab.id, { 
           type: "showPhishingWarning", 
           url: msg.url 
         });
      }
    })
    .catch((err) => {
      console.error("Deep scan failed:", err);
      sendResponse({ ok: false, message: "Server error" });
    });
    
    return true; // Keep channel open for async response
  }
});

// --- 2. Navigation Monitoring (Automatic Scanning) ---
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Filter out iframes and internal pages
  if (details.frameId !== 0) return;
  if (details.url.startsWith("chrome://") || details.url.startsWith("about:") || details.url.startsWith("http://localhost")) return;

  try {
    const res = await fetch(`${API_BASE}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: details.url }),
    });

    const data = await res.json();

    // Logic: If Malicious -> Block or Warn
    if (data.verdict === "malicious") {
       // Option A: Redirect to Blocked Page (Hard Block)
       // chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL("blocked.html") });

       // Option B: Show Overlay (Soft Block - User can ignore)
       // We wait 500ms to ensure content script is ready
       setTimeout(() => {
         chrome.tabs.sendMessage(details.tabId, { 
           type: "showPhishingWarning", 
           url: details.url 
         }).catch(() => console.log("Tab closed before warning could be shown"));
       }, 1000);
    }
    
    // Logic: If Suspicious/Unknown -> Suggest Deep Scan
    else if (data.suggestDeepScan) {
      setTimeout(() => {
        chrome.tabs.sendMessage(details.tabId, { 
          type: "suggestDeepScan", 
          url: details.url 
        }).catch(() => {});
      }, 1000);
    }

  } catch (err) {
    console.error("Background Scan Error:", err);
  }
});