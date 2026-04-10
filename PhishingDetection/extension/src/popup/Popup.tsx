import { useEffect, useState } from "react";

// FORCE IPv4 to avoid localhost issues
const API_BASE = "http://127.0.0.1:5000";

export default function Popup() {
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    // 1. Get URL and Auto-Scan on Open
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const url = tabs[0]?.url;
      if (!url || url.startsWith("chrome://") || url.startsWith("about:")) {
        setCurrentUrl("System Page");
        return;
      }
      setCurrentUrl(url);
      performScan(url, false);
    });
  }, []);

  const performScan = async (url: string, isDeep: boolean) => {
    setStatus("loading");
    try {
      const endpoint = isDeep ? "/api/deep-scan" : "/api/check";
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) throw new Error("Backend unreachable");
      const result = await res.json();
      
      setData(result);
      setStatus("success");
    } catch (err) {
      console.error(err);
      setStatus("error");
    }
  };

  // --- UI HELPERS ---
  const getVerdictColor = (v: string) => {
    const verdict = v?.toLowerCase() || "";
    if (verdict.includes("safe")) return "#10b981"; // Emerald-500
    if (verdict.includes("malicious") || verdict.includes("phishing")) return "#ef4444"; // Red-500
    return "#eab308"; // Yellow-500
  };

  const getBgColor = (v: string) => {
    const verdict = v?.toLowerCase() || "";
    if (verdict.includes("safe")) return "#ecfdf5"; // Green-50
    if (verdict.includes("malicious")) return "#fef2f2"; // Red-50
    return "#fefce8"; // Yellow-50
  };

  if (status === "error") {
    return (
      <div style={{ width: 350, padding: 20, textAlign: "center", fontFamily: "sans-serif" }}>
        <h3 style={{ color: "#ef4444" }}>Connection Failed</h3>
        <p style={{ fontSize: 12, color: "#666" }}>Ensure <b>app.py</b> is running on port 5000.</p>
        <button onClick={() => window.location.reload()} style={{ padding: "8px 16px", marginTop: 10, cursor: "pointer" }}>Retry</button>
      </div>
    );
  }

  return (
    <div style={{ width: "360px", fontFamily: "'Segoe UI', sans-serif", fontSize: "13px", color: "#334155" }}>
      
      {/* HEADER */}
      <div style={{ padding: "16px", background: "#0f172a", color: "white", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "18px" }}>🛡️</span>
          <span style={{ fontWeight: 600, fontSize: "14px" }}>AntiPhish Sentinel</span>
        </div>
        <div style={{ fontSize: "10px", background: "#1e293b", padding: "2px 8px", borderRadius: "12px", border: "1px solid #334155" }}>
          <span style={{ color: "#10b981" }}>●</span> Online
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div style={{ padding: "16px" }}>
        
        {/* URL BAR */}
        <div style={{ background: "#f1f5f9", padding: "8px", borderRadius: "6px", marginBottom: "16px", wordBreak: "break-all", fontSize: "11px", color: "#64748b" }}>
          {currentUrl || "Loading..."}
        </div>

        {status === "loading" ? (
          <div style={{ textAlign: "center", padding: "20px" }}>
            <div style={{ display: "inline-block", width: "20px", height: "20px", borderRadius: "50%", border: "2px solid #ccc", borderTopColor: "#3b82f6", animation: "spin 1s linear infinite" }}></div>
            <p style={{ marginTop: "10px", color: "#64748b" }}>Analyzing Threats...</p>
          </div>
        ) : data ? (
          <>
            {/* VERDICT CARD */}
            <div style={{ 
              textAlign: "center", padding: "20px", borderRadius: "12px", marginBottom: "16px",
              backgroundColor: getBgColor(data.verdict), 
              border: `1px solid ${getVerdictColor(data.verdict)}` 
            }}>
              <h2 style={{ margin: 0, fontSize: "24px", fontWeight: 800, color: getVerdictColor(data.verdict), textTransform: "uppercase" }}>
                {data.verdict}
              </h2>
              <div style={{ fontSize: "11px", fontWeight: 600, color: "#64748b", marginTop: "4px" }}>
                RISK CONFIDENCE: {data.confidence}%
              </div>
            </div>

            {/* AI REASONING */}
            <div style={{ marginBottom: "16px" }}>
              <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", color: "#94a3b8", marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ color: "#a855f7" }}>✦</span> AI Reasoning
              </div>
              <div style={{ background: "#f8fafc", padding: "12px", borderRadius: "8px", border: "1px solid #e2e8f0", fontSize: "12px", lineHeight: "1.5" }}>
                {data.ai_analysis?.llm_reasoning || "No detailed reasoning provided."}
              </div>
            </div>

            {/* NETWORK INTELLIGENCE */}
            <div>
              <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", color: "#94a3b8", marginBottom: "6px" }}>
                🌐 Network Intelligence
              </div>
              <div style={{ background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0", overflow: "hidden" }}>
                <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 12px", borderBottom: "1px solid #f1f5f9" }}>
                  <span style={{ color: "#64748b" }}>IP Address</span>
                  <span style={{ fontWeight: 600 }}>{data.host_info?.ip || data.host_info?.ip_address || "N/A"}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 12px", borderBottom: "1px solid #f1f5f9" }}>
                  <span style={{ color: "#64748b" }}>Domain</span>
                  <span style={{ fontWeight: 600 }}>{new URL(data.url).hostname}</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 12px" }}>
                  <span style={{ color: "#64748b" }}>Action</span>
                  <button 
                    onClick={() => performScan(currentUrl, true)}
                    style={{ background: "none", border: "none", color: "#3b82f6", cursor: "pointer", fontSize: "11px", fontWeight: 700, padding: 0 }}
                  >
                    RUN DEEP SCAN &rarr;
                  </button>
                </div>
              </div>
            </div>
          </>
        ) : null}
      </div>
      
      <style>{`
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}