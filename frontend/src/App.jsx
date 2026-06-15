import { useEffect, useState, useRef } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip as ChartTooltip, Legend, Filler, ArcElement } from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';
import DriftDetails from './DriftDetails';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, ChartTooltip, Legend, Filler, ArcElement);

ChartJS.defaults.color = '#94a3b8';
ChartJS.defaults.font.family = 'Outfit, sans-serif';

// Determine API URL based on environment
const API_URL = import.meta.env.MODE === 'production' 
  ? 'https://cloud-gaurd.vercel.app/api'
  : 'http://localhost:8000/api';

const WS_URL = import.meta.env.MODE === 'production'
  ? 'wss://cloud-gaurd.vercel.app/ws'
  : 'ws://localhost:8000/ws';

function App() {
  const [status, setStatus] = useState('Initializing Server...');
  const [statusOnline, setStatusOnline] = useState(false);
  const [providers, setProviders] = useState({ AWS: 'Checking heartbeat...', Azure: 'Checking heartbeat...', GCP: 'Checking heartbeat...' });
  const [driftHistory, setDriftHistory] = useState([]);
  
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResult, setAuditResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiInsight, setAiInsight] = useState(null);
  const [isFixing, setIsFixing] = useState(false);
  const [toast, setToast] = useState(null);
  const [awsSparkline, setAwsSparkline] = useState(null);
  const [shadowIt, setShadowIt] = useState([]);
  const [logs, setLogs] = useState([]);
  const [activeProvider, setActiveProvider] = useState(null);
  const [awsLocalScore, setAwsLocalScore] = useState(null);
  const [azureLocalScore, setAzureLocalScore] = useState(null);
  const [compliance, setCompliance] = useState({
      GDPR: {score: 100, grade: 'A', color: 'emerald', missing_controls: []},
      HIPAA: {score: 100, grade: 'A', color: 'emerald', missing_controls: []},
      SOC2: {score: 100, grade: 'A', color: 'emerald', missing_controls: []}
  });

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 4000);
  };

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch(`${API_URL}/heartbeat`);
        if (!res.ok) throw new Error('API Error');
        const data = await res.json();
        setStatusOnline(data.status === 'online');
        setStatus(data.status === 'online' ? 'System Live' : 'Limited Connection');
        if (data.providers) setProviders(data.providers);
      } catch (err) {
        setStatusOnline(false);
        setStatus('API Offline');
      }
    };
    
    const fetchDrift = async () => {
      try {
        const res = await fetch(`${API_URL}/drift`);
        if (res.ok) {
          const data = await res.json();
          setDriftHistory(data.drift_history || []);
        }
      } catch (err) {}
    };

    const fetchSparklineAndShadow = async () => {
      try {
        const resSp = await fetch(`${API_URL}/aws/predictive-scaling`);
        if (resSp.ok) { const pay = await resSp.json(); if (pay.status === 'success') setAwsSparkline(pay.data); }
      } catch (e) {}
    };

    const fetchCompliance = async () => {
      try {
        const res = await fetch(`${API_URL}/compliance/status`);
        if (res.ok) {
           const data = await res.json();
           if(data.status === 'success') setCompliance(data.scorecard);
        }
      } catch (e) {}
    };

    fetchStatus(); fetchDrift(); fetchSparklineAndShadow(); fetchCompliance();
    
    // Connect WebSocket
    const ws = new WebSocket(WS_URL);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "connect") {
         setLogs(prev => [...prev, { source: "SYSTEM", severity: "INFO", timestamp: data.timestamp, msg: data.message }]);
      }
      else if (data.type === "dashboard_sync") {
         setStatusOnline(data.status === 'online');
         setStatus(data.status === 'online' ? 'System Live' : 'Limited Connection');
         if (data.providers) setProviders(data.providers);
         // Sub-sync logic to keep charts fresh without interval
         fetchSparklineAndShadow();
      }
      else {
         setLogs(prev => {
            const newLogs = [...prev, data];
            return newLogs.length > 50 ? newLogs.slice(newLogs.length - 50) : newLogs;
         });
         
         if (data.severity === "CRITICAL" && data.source === "AUDIT_ENGINE") {
            showToast("🛑 AI Threat detected pushed from Daemon!");
         }
      }
    };

    return () => ws.close();
  }, []);

  const runAudit = async (providerName) => {
    setIsAuditing(true); setAuditResult(null); setAiInsight(null); setActiveProvider(providerName);
    try {
      const endpoint = providerName.toLowerCase();
      const res = await fetch(`${API_URL}/${endpoint}/audit`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success') { 
        setAuditResult(data.finding); 
        if (data.risk_score !== undefined) {
            if (providerName === 'AWS') setAwsLocalScore(data.risk_score);
            if (providerName === 'Azure') setAzureLocalScore(data.risk_score);
        }
      } else { alert("Action failed: " + data.error); }
    } catch(err) { alert("Network err"); } finally { setIsAuditing(false); }
  };

  const runAiAnalysis = async () => {
    if (!auditResult) return;
    setIsAnalyzing(true);
    try {
      const res = await fetch(`${API_URL}/analyze-risk`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding: auditResult })
      });
      const data = await res.json();
      if (data.risk_story || data.status === 'success') {
        setAiInsight(data.analysis || data);
      } else { alert("AI error: " + (data.error || "Generation Failed")); }
    } catch(e) { alert("Failed to reach AI api"); } finally { setIsAnalyzing(false); }
  };

  const runRemediation = async () => {
    if (!auditResult || !activeProvider) return;
    setIsFixing(true);
    try {
      const endpoint = activeProvider.toLowerCase();
      
      let port = -1, protocol = "-1";
      if (activeProvider === 'AWS' && auditResult.IpPermissions) {
          for (let perm of auditResult.IpPermissions) {
              if (perm.IpRanges?.some(r => r.CidrIp === "0.0.0.0/0")) {
                  port = perm.FromPort || null;
                  protocol = perm.IpProtocol;
                  break;
              }
          }
      }
      
      const bodyPayload = activeProvider === 'AWS' 
          ? { group_id: auditResult.GroupId, port, protocol, region: auditResult.AwsRegion }
          : auditResult;

      const res = await fetch(`${API_URL}/${endpoint}/remediate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyPayload)
      });
      const data = await res.json();
      if (data.status === 'success') {
        showToast('🛡️ Threat Neutralized');
        setAuditResult(null);
      } else { alert("Remediation failed: " + data.error); }
    } catch (e) { alert("API Error"); } finally { setIsFixing(false); }
  };

  const [isShadowScanning, setIsShadowScanning] = useState(false);
  const runShadowItAudit = async () => {
      setIsShadowScanning(true);
      try {
        const resSh = await fetch(`${API_URL}/aws/shadow-it`);
        if (resSh.ok) { 
           const pay = await resSh.json(); 
           setShadowIt(pay.shadow_instances || []); 
        }
      } catch (e) {
          alert('Network err in Shadow Audit');
      } finally {
          setIsShadowScanning(false);
      }
  };

  const [isComplianceScanning, setIsComplianceScanning] = useState(false);
  const runComplianceAudit = async () => {
      setIsComplianceScanning(true);
      try {
        const res = await fetch(`${API_URL}/compliance/status`);
        if (res.ok) {
           const data = await res.json();
           if(data.status === 'success') setCompliance(data.scorecard);
        }
      } catch (e) {} finally {
          setIsComplianceScanning(false);
      }
  };

  const chartRef = useRef(null);
  const labels = driftHistory.length > 0 ? driftHistory.map(d => d.day) : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const riskScores = driftHistory.length > 0 ? driftHistory.map(d => d.aws) : [0,0,0,0,0,0,0];

  const driftData = {
    labels: labels,
    datasets: [{
      label: 'Cumulative Risk', data: riskScores, borderColor: '#4FD1C5',
      backgroundColor: (context) => {
        const ctx = context.chart?.ctx;
        if (!ctx) return 'rgba(79, 209, 197, 0.5)';
        const gradient = ctx.createLinearGradient(0, 0, 0, 400); gradient.addColorStop(0, 'rgba(79, 209, 197, 0.5)'); gradient.addColorStop(1, 'rgba(79, 209, 197, 0.0)');
        return gradient;
      },
      borderWidth: 3, 
      pointBackgroundColor: driftHistory.length > 0 ? driftHistory.map(d => d.has_drift ? '#f43f5e' : '#0B0F19') : '#0B0F19', 
      pointBorderColor: driftHistory.length > 0 ? driftHistory.map(d => d.has_drift ? '#f43f5e' : '#4FD1C5') : '#4FD1C5', 
      pointBorderWidth: 2, pointRadius: 4, fill: true, tension: 0.4
    }]
  };

  const driftOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { padding: 12 } }, scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, border: { display: false } }, x: { grid: { display: false }, border: { display: false } } } };
  const vulnData = { labels: ['Critical', 'High', 'Medium'], datasets: [{ data: [12, 28, 60], backgroundColor: ['#f43f5e', '#fb923c', '#fbbf24'], borderWidth: 0 }] };
  const vulnOptions = { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { display: false }} };

  return (
    <div className="bg-sentinel-base text-slate-200 min-h-screen relative overflow-x-hidden selection:bg-sentinel-accent selection:text-sentinel-base font-sans pb-16">
      
      {toast && (
        <div className="fixed bottom-8 right-8 z-[100] animate-fade-in flex items-center gap-3 px-6 py-4 rounded-xl bg-emerald-500/20 backdrop-blur-xl border border-emerald-400/50 shadow-[0_0_20px_rgba(52,211,153,0.3)] text-emerald-300 font-bold tracking-wide">
          <span>{toast}</span>
        </div>
      )}

      <div className="fixed top-[-10%] left-[-10%] w-[40%] h-[40%] bg-indigo-500/20 rounded-full blur-[120px] pointer-events-none"></div>
      <div className="fixed bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-sentinel-accent/10 rounded-full blur-[120px] pointer-events-none"></div>

      <nav className="sticky top-0 z-50 backdrop-blur-xl bg-sentinel-base/80 border-b border-white/5 px-8 py-4 flex justify-between items-center transition-all">
        <div className="flex items-center space-x-3 group">
          <div className="p-2 bg-gradient-to-br from-indigo-500 to-sentinel-accent rounded-lg shadow-[0_0_15px_rgba(79,209,197,0.3)]">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"></path></svg>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-wide">CloudGuard <span className="text-transparent bg-clip-text bg-gradient-to-r from-sentinel-accent to-indigo-400">Sentinel</span></h1>
        </div>
        
        <div className="flex items-center gap-5">
          <a href={`${API_URL}/report/export`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-sm font-bold text-white bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 px-5 py-2.5 rounded-full transition-all shadow-[0_0_15px_rgba(99,102,241,0.4)] hover:shadow-[0_0_20px_rgba(99,102,241,0.6)] hover:-translate-y-0.5">
             <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
             Export Executive Report
          </a>
          <div className="flex items-center space-x-3 bg-white/5 backdrop-blur-md px-4 py-2.5 rounded-full border border-white/10">
            <span className="relative flex h-3 w-3">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${statusOnline ? 'bg-emerald-400' : 'bg-rose-400'}`}></span>
              <span className={`relative inline-flex rounded-full h-3 w-3 ${statusOnline ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
            </span>
            <span className={`text-sm font-medium tracking-wide ${statusOnline ? 'text-emerald-400' : 'text-rose-400'}`}>{status}</span>
          </div>
        </div>
      </nav>

      <main className="relative z-10 p-8 max-w-7xl mx-auto space-y-8 mt-4">
        <header className="mb-10">
          <h2 className="text-3xl font-bold text-white mb-2 leading-tight">Security Posture <br/><span className="text-slate-400 text-lg font-medium tracking-wide">Multi-cloud visibility and autonomous defense.</span></h2>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <ProviderCard provider="AWS" score={awsLocalScore !== null ? awsLocalScore : (driftHistory[driftHistory.length-1]?.aws || 42)} statusText={providers.AWS} color="orange" onAction={() => runAudit("AWS")} isAuditing={isAuditing && activeProvider === 'AWS'} sparklineData={awsSparkline} />
          <ProviderCard provider="Azure" score={azureLocalScore !== null ? azureLocalScore : (driftHistory[driftHistory.length-1]?.azure || 18)} statusText={providers.Azure} color="blue" onAction={() => runAudit("Azure")} isAuditing={isAuditing && activeProvider === 'Azure'} />
          <ProviderCard provider="GCP" score={driftHistory[driftHistory.length-1]?.gcp || 5} statusText={providers.GCP} color="emerald" onAction={() => runAudit("GCP")} isAuditing={isAuditing && activeProvider === 'GCP'} />
        </div>

        {/* AI Insight Modal Section */}
        {auditResult && (
          <div className="cloud-card animate-fade-in lg:col-span-3 border border-sentinel-accent/30 shadow-[0_0_30px_rgba(79,209,197,0.15)] relative">
            <button onClick={() => setAuditResult(null)} className="absolute top-4 right-4 text-slate-400 hover:text-white">&times;</button>
            <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
               🚨 Security Audit Finding Detected
            </h3>
            <div className="bg-black/30 p-4 rounded-lg my-4 overflow-x-auto border border-white/5 max-h-40">
               <pre className="text-xs text-slate-300 font-mono">{JSON.stringify(auditResult, null, 2)}</pre>
            </div>
            
            {aiInsight ? (
              <div className="mt-6 bg-gradient-to-r from-indigo-500/10 to-sentinel-accent/10 p-5 rounded-lg border border-indigo-500/20">
                <h4 className="text-indigo-300 font-bold mb-2 flex items-center gap-2">
                  ✨ Gemini AI Prioritizer Insight
                </h4>
                <p className="text-sm text-slate-200 mb-4">{aiInsight.risk_story || "Risk context was not successfully generated."}</p>
                <div className="flex items-center justify-between">
                  <div className="inline-block px-3 py-1 bg-emerald-500/20 text-emerald-300 text-xs font-semibold rounded-md border border-emerald-500/20">
                    REMEDIATION: {aiInsight.remediation_hint || "Apply strict IP constraints."}
                  </div>
                  <button 
                    onClick={runRemediation} disabled={isFixing}
                    className="ml-4 flex items-center gap-2 font-bold px-6 py-2 bg-rose-500 hover:bg-rose-600 text-white rounded-lg transition-all shadow-[0_0_15px_rgba(244,63,94,0.4)] disabled:opacity-50 cursor-pointer"
                  >
                    {isFixing ? "Executing..." : "🔨 Fix Now"}
                  </button>
                </div>
              </div>
            ) : (
              <button 
                onClick={runAiAnalysis} disabled={isAnalyzing}
                className="mt-2 text-sm font-bold bg-gradient-to-r from-indigo-500 to-purple-600 px-6 py-3 rounded-lg text-white shadow-lg hover:shadow-indigo-500/50 hover:scale-[1.02] transition-all disabled:opacity-50 cursor-pointer"
              >
                {isAnalyzing ? "🧠 Running Gemini Analysis..." : "✨ Prioritize Risk Context via AI"}
              </button>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="cloud-card lg:col-span-2">
            <h3 className="text-xl font-semibold text-white mb-6">Security Drift Timeline</h3>
            <div className="relative h-64 w-full">
              <Line data={driftData} options={driftOptions} ref={chartRef} />
            </div>
          </div>
          
          <div className="space-y-6 flex flex-col justify-between">
            <div className="cloud-card border-rose-500/20 shadow-[0_0_20px_rgba(244,63,94,0.05)] h-full">
               <div className="flex justify-between items-start mb-6">
                   <h3 className="text-xl font-semibold text-white">Shadow IT Audit</h3>
                   <div className="flex items-center gap-3">
                      <span className="text-xs font-mono bg-rose-500/20 text-rose-400 px-2 py-1 border border-rose-500/30 rounded">Rogue Assets</span>
                      <button onClick={runShadowItAudit} disabled={isShadowScanning} className="action-btn text-xs py-1.5 px-3 disabled:opacity-50 !w-auto">
                          {isShadowScanning ? "Scanning..." : "Scan Env"}
                      </button>
                   </div>
               </div>
               {shadowIt.length > 0 ? (
                   <div className="space-y-3 max-h-48 overflow-y-auto custom-scrollbar pr-2">
                      {shadowIt.map(inst => (
                         <div key={inst} className="flex items-center gap-3 bg-black/40 p-3 rounded-lg border border-white/5 text-sm text-slate-300">
                            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
                            <span className="font-mono text-xs">{inst}</span>
                            <span className="ml-auto text-[10px] text-rose-400 uppercase tracking-widest font-bold">Untagged</span>
                         </div>
                      ))}
                   </div>
               ) : (
                  <p className="text-sm text-emerald-400">No shadow IT detected across environments.</p>
               )}
            </div>
          </div>
        </div>

        {/* Compliance Overview Section */}
        <ComplianceScorecard data={compliance} onScan={runComplianceAudit} isScanning={isComplianceScanning} />

        {/* Terminal Command Center */}
        <div className="cloud-card border border-slate-700/50 bg-[#0a0a0e]/90 backdrop-blur-xl shadow-[0_0_40px_rgba(0,0,0,0.6)] overflow-hidden rounded-xl font-mono relative">
          <div className="flex items-center justify-between bg-[#050508] border-b border-white/10 px-4 py-3">
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.6)]"></div>
              <div className="w-3 h-3 rounded-full bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.6)]"></div>
              <div className="w-3 h-3 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.6)]"></div>
            </div>
            <span className="text-xs text-slate-500 tracking-[0.3em] font-bold">DAEMON LOG_STREAM</span>
          </div>
          <div className="p-5 h-64 overflow-y-auto space-y-2 text-[13px] flex flex-col flex-col-reverse custom-scrollbar">
            <div className="flex flex-col gap-1.5 justify-end w-full">
              {logs.length === 0 ? (
                <div className="text-slate-600 italic">Listening for inbound WebSocket telemetry on {WS_URL}...</div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="flex gap-4 fade-in">
                    <span className="text-slate-500 w-20 shrink-0">[{log.timestamp}]</span>
                    <span className={`w-32 shrink-0 tracking-wider ${
                      log.severity === 'CRITICAL' ? 'text-rose-500 font-bold' :
                      log.severity === 'WARNING' ? 'text-amber-500 font-bold' :
                      'text-indigo-400 font-bold'
                    }`}>
                      [{log.source}]
                    </span>
                    <span className={`${log.severity === 'CRITICAL' ? 'text-rose-300 bg-rose-500/10 px-2 rounded' : 'text-slate-300'}`}>{log.msg}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* The Time Machine Component */}
        <div className="mt-8">
           <DriftDetails />
        </div>

      </main>
    </div>
  );
}

function ProviderCard({ provider, score, statusText, color, onAction, isAuditing, sparklineData }) {
  const isConnected = statusText && statusText.includes("Connected");
  const colorMap = { orange: 'text-orange-400 bg-orange-500', blue: 'text-blue-400 bg-blue-500', emerald: 'text-emerald-400 bg-emerald-500' };
  const iconColor = colorMap[color].split(' ')[0];
  const bulletColor = colorMap[color].split(' ')[1];

  const sparklineChartData = sparklineData ? {
    labels: Array((sparklineData.historical?.length || 0) + (sparklineData.predicted?.length || 0)).fill(''),
    datasets: [{
      data: [...(sparklineData.historical || []), ...(sparklineData.predicted || [])],
      borderColor: sparklineData.exceeds_threshold ? '#f43f5e' : '#4FD1C5',
      borderWidth: 2, pointRadius: 0, tension: 0.4
    }]
  } : null;

  return (
    <div className="cloud-card group flex flex-col justify-between">
      <div>
        <div className="relative z-10 flex justify-between items-start mb-6">
          <div>
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${bulletColor}`}></span> {provider}
            </h3>
            <p className={`text-sm mt-1 ${isConnected ? 'text-emerald-400' : 'text-slate-500'}`}>{statusText}</p>
          </div>
          <div className="p-2 bg-white/5 rounded-lg border border-white/10">
            <svg className={`w-6 h-6 ${iconColor}`} fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 14.5v-9l6 4.5-6 4.5z"/></svg> 
          </div>
        </div>
        <div className="relative z-10 flex justify-between items-end">
          <div>
            <p className="text-xs text-slate-500 font-semibold tracking-wider uppercase mb-1">Risk Score</p>
            <p className={`text-4xl font-light ${iconColor}`}>{score}</p>
          </div>
          <button onClick={onAction} disabled={isAuditing} className="action-btn disabled:opacity-50">
            {isAuditing ? 'Scanning...' : 'Run Audit'}
          </button>
        </div>
      </div>
      
    </div>
  );
}

function ComplianceScorecard({ data, onScan, isScanning }) {
  if (!data) return null;
  const standards = ["GDPR", "HIPAA", "SOC2"];
  
  return (
    <div className="cloud-card mt-8">
        <div className="flex justify-between items-start mb-6">
            <h3 className="text-xl font-semibold text-white">Compliance Scorecard</h3>
            <button onClick={onScan} disabled={isScanning} className="action-btn text-xs py-1.5 px-3 disabled:opacity-50 !w-auto">
                {isScanning ? "Evaluating..." : "Evaluate Posture"}
            </button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
           {standards.map(std => {
              const info = data[std];
              let pathColor = 'text-emerald-400';
              if(info.color === 'amber') pathColor = 'text-amber-400';
              if(info.color === 'rose') pathColor = 'text-rose-400';
              
              // Map score to stroke offset (251.2 is circumference for r=40)
              const strokeOffset = 251.2 - (251.2 * info.score) / 100;
              
              return (
                 <div key={std} className="bg-black/20 rounded-xl p-6 flex flex-col items-center relative border border-white/5 shadow-[0_0_15px_rgba(0,0,0,0.2)]">
                    <div className="relative w-32 h-32 flex items-center justify-center">
                        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                           <circle cx="50" cy="50" r="40" className="text-slate-700 stroke-current outline-none" strokeWidth="8" fill="none" />
                           <circle cx="50" cy="50" r="40" className={`${pathColor} stroke-current transition-all duration-1000 ease-out outline-none`} strokeWidth="8" strokeDasharray="251.2" strokeDashoffset={strokeOffset} strokeLinecap="round" fill="none" />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <span className={`text-3xl font-bold ${pathColor}`}>{info.grade}</span>
                            <span className="text-xs text-slate-400 mt-1">{info.score}%</span>
                        </div>
                    </div>
                    <h4 className="text-lg font-bold text-white mt-4">{std}</h4>
                    {info.missing_controls.length > 0 ? (
                        <div className="mt-4 text-xs bg-rose-500/10 text-rose-300 border border-rose-500/20 px-3 py-2 rounded-lg w-full">
                           <span className="font-bold flex items-center gap-1 mb-1 text-rose-500">
                               <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg> 
                               Missing Controls:
                           </span>
                           <ul className="list-disc pl-4 space-y-1 mt-2 mb-1">
                               {info.missing_controls.map((mc, idx) => <li key={idx}>{mc}</li>)}
                           </ul>
                        </div>
                    ) : (
                        <div className="mt-4 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-2 rounded-lg w-full text-center font-bold flex items-center justify-center gap-1">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>
                            Fully Compliant
                        </div>
                    )}
                 </div>
              );
           })}
        </div>
    </div>
  );
}

export default App;
