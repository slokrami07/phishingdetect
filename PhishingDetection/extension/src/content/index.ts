// src/content/index.ts

console.log("SentinelGuard Content Script Active");

// Listen for messages from Background or Popup
chrome.runtime.onMessage.addListener((msg: { type: string; url?: string }, sender, sendResponse) => {
  if (msg.type === "suggestDeepScan" && msg.url) {
    injectBanner(msg.url);
  }
  
  if (msg.type === "showPhishingWarning" && msg.url) {
    showPhishingPopup(msg.url);
  }
});

function showPhishingPopup(url: string) {
  // Remove existing popup if present
  const existingPopup = document.getElementById("sentinelguard-phishing-popup");
  if (existingPopup) existingPopup.remove();

  const popup = document.createElement("div");
  popup.id = "sentinelguard-phishing-popup";
  
  // Create the HTML structure
  popup.innerHTML = `
    <div style="
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.9); z-index: 2147483647;
      display: flex; align-items: center; justify-content: center;
      font-family: system-ui, sans-serif; backdrop-filter: blur(5px);
    ">
      <div style="
        background: white; border-radius: 12px; padding: 32px;
        max-width: 500px; width: 90%; box-shadow: 0 20px 25px rgba(0, 0, 0, 0.5);
        text-align: center; border: 1px solid #dc2626;
      ">
        <div style="font-size: 48px; margin-bottom: 16px;">🚨</div>
        
        <h2 style="color: #dc2626; font-size: 24px; font-weight: 800; margin: 0 0 16px 0;">
          Phishing Threat Detected!
        </h2>
        
        <p style="color: #4b5563; font-size: 16px; line-height: 1.5; margin-bottom: 24px;">
          SentinelGuard has identified this page as unsafe. Entering data here may result in theft of your personal information.
        </p>
        
        <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 12px; margin-bottom: 24px; text-align: left;">
          <div style="font-size: 12px; color: #991b1b; font-weight: bold; margin-bottom: 4px;">SUSPICIOUS URL:</div>
          <div style="font-family: monospace; font-size: 13px; color: #7f1d1d; word-break: break-all;">
            ${url}
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: center;">
          <button id="sg-btn-close" style="
            background: #dc2626; color: white; border: none; padding: 12px 24px;
            border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer;
            transition: background 0.2s;
          ">Close Tab (Safety)</button>
          
          <button id="sg-btn-ignore" style="
            background: transparent; color: #6b7280; border: 1px solid #d1d5db;
            padding: 12px 24px; border-radius: 8px; font-size: 15px; font-weight: 500;
            cursor: pointer;
          ">I Trust This Site</button>
        </div>
        
        <div style="margin-top: 24px; font-size: 11px; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 16px;">
          Protected by SentinelGuard AI
        </div>
      </div>
    </div>
  `;
  
  document.body.appendChild(popup);

  // --- ATTACH EVENT LISTENERS (Crucial for Manifest V3) ---
  
  // Close Tab Button
  document.getElementById("sg-btn-close")?.addEventListener("click", () => {
    // Content scripts can't close tabs directly, ask Background script
    chrome.runtime.sendMessage({ type: "closeCurrentTab" });
  });

  // Ignore Button
  document.getElementById("sg-btn-ignore")?.addEventListener("click", () => {
    popup.remove();
  });
}

function injectBanner(url: string) {
  if (document.getElementById("sentinelguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "sentinelguard-banner";
  banner.innerHTML = `
    <div style="
      position: fixed; top: 0; left: 0; right: 0;
      background: linear-gradient(90deg, #fffbeb 0%, #fef3c7 100%);
      border-bottom: 1px solid #fcd34d;
      color: #92400e; padding: 12px 20px;
      font-family: system-ui, sans-serif; font-size: 14px;
      z-index: 2147483647; display: flex; align-items: center;
      justify-content: space-between; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    ">
      <div style="display:flex; align-items:center; gap: 10px;">
        <span style="font-size: 18px;">🛡️</span>
        <span>
          <strong>Unverified Site:</strong> We haven't scanned this specific page yet.
        </span>
      </div>
      <button id="sentinelguard-scan-btn" style="
        background: #b45309; color: white; border: none;
        padding: 8px 16px; border-radius: 6px; cursor: pointer;
        font-weight: 600; font-size: 13px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      ">Run Deep Scan</button>
    </div>
  `;
  
  document.body.prepend(banner);

  // Attach Listener
  document.getElementById("sentinelguard-scan-btn")?.addEventListener("click", () => {
    const btn = document.getElementById("sentinelguard-scan-btn") as HTMLButtonElement;
    btn.innerText = "Scanning...";
    btn.disabled = true;
    btn.style.opacity = "0.7";

    chrome.runtime.sendMessage({ type: "triggerDeepScan", url }, (res) => {
      if (res?.ok) {
        btn.innerText = "Scan Started";
        setTimeout(() => banner.remove(), 2000); // Remove banner after success
      } else {
        btn.innerText = "Failed";
        btn.style.background = "#dc2626";
      }
    });
  });
}