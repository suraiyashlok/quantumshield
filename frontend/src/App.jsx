import { useState, useEffect, useRef } from "react"
import { io } from "socket.io-client"
import { Shield, Search, AlertTriangle, CheckCircle, XCircle, Download, ChevronDown, ChevronRight, Zap } from "lucide-react"
import { RadialBarChart, RadialBar, ResponsiveContainer } from "recharts"

const SOCKET_URL = "https://quantumshield-production.up.railway.app"

// ─── RISK HELPERS ───────────────────────────
function getRiskColor(score) {
  if (score <= 20) return "#00ff88"
  if (score <= 40) return "#00d4ff"
  if (score <= 70) return "#ffaa00"
  return "#ff4444"
}

function getRiskLabel(score) {
  if (score <= 20) return "Fully Quantum Safe"
  if (score <= 40) return "PQC Ready"
  if (score <= 70) return "Medium Quantum Risk"
  return "High Quantum Risk"
}

function getRiskBg(score) {
  if (score <= 20) return "border-green-400 bg-green-400/10"
  if (score <= 40) return "border-cyan-400 bg-cyan-400/10"
  if (score <= 70) return "border-yellow-400 bg-yellow-400/10"
  return "border-red-400 bg-red-400/10"
}

// ─── SCORE GAUGE ────────────────────────────
function ScoreGauge({ score }) {
  const color = getRiskColor(score)
  const data = [{ value: score }, { value: 100 - score }]
  return (
    <div className="flex flex-col items-center">
      <div className="relative w-40 h-40">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart cx="50%" cy="50%" innerRadius="70%" outerRadius="90%"
            startAngle={180} endAngle={0} data={[{ value: score, fill: color }]}>
            <RadialBar dataKey="value" cornerRadius={6} background={{ fill: "#1a2235" }} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold font-mono" style={{ color }}>{score}</span>
          <span className="text-xs text-gray-400">/ 100</span>
        </div>
      </div>
      <span className="mt-2 text-sm font-semibold" style={{ color }}>
        {getRiskLabel(score)}
      </span>
    </div>
  )
}

// ─── FIPS BADGE ─────────────────────────────
function FIPSBadge({ id, compliant }) {
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-mono font-semibold
      ${compliant ? "border-green-400 bg-green-400/10 text-green-400" : "border-red-400 bg-red-400/10 text-red-400"}`}>
      {compliant ? <CheckCircle size={12} /> : <XCircle size={12} />}
      {id}
    </div>
  )
}

// ─── SCORE BREAKDOWN ────────────────────────
function ScoreBreakdown({ breakdown }) {
  return (
    <div className="space-y-2">
      {Object.entries(breakdown).map(([key, val]) => {
        const pct = (val.score / val.max) * 100
        const color = pct === 0 ? "#00ff88" : pct <= 30 ? "#00d4ff" : pct <= 70 ? "#ffaa00" : "#ff4444"
        return (
          <div key={key}>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-300 font-mono">{key} <span className="text-gray-500">({val.weight})</span></span>
              <span className="font-mono font-bold" style={{ color }}>{val.score}/{val.max}</span>
            </div>
            <div className="h-1.5 bg-navy rounded-full overflow-hidden">
              <div className="h-full rounded-full transition-all duration-700"
                style={{ width: `${pct}%`, backgroundColor: color }} />
            </div>
            <div className="text-xs text-gray-500 mt-0.5 font-mono">{val.note}</div>
          </div>
        )
      })}
    </div>
  )
}

// ─── CRYPTO STACK TABLE ─────────────────────
function CryptoStack({ scan, fips }) {
  const rows = [
    {
      component: "Key Exchange", weight: "40%",
      current: scan.key_exchange,
      threat: scan.key_exchange?.includes("ML-KEM") ? null : "Shor's Algorithm",
      fipsId: "FIPS 203", compliant: fips["FIPS 203"],
      recommended: "ML-KEM-768"
    },
    {
      component: "Digital Signature", weight: "30%",
      current: `${scan.cert_key_algo} ${scan.cert_key_size}`,
      threat: scan.cert_key_algo?.includes("ML-DSA") ? null : "Shor's Algorithm",
      fipsId: "FIPS 204", compliant: fips["FIPS 204"],
      recommended: "ML-DSA-65"
    },
    {
      component: "TLS Version", weight: "15%",
      current: scan.tls_versions?.join(", ") || "Unknown",
      threat: scan.tls_versions?.some(v => ["TLS 1.0","TLS 1.1"].includes(v)) ? "Downgrade Attack" : null,
      fipsId: "—", compliant: null,
      recommended: "TLS 1.3 only"
    },
    {
      component: "Cipher Suite", weight: "10%",
      current: scan.symmetric,
      threat: scan.symmetric === "3DES" ? "Classically Broken" : "Grover's (minor)",
      fipsId: "—", compliant: null,
      recommended: "AES-256-GCM"
    },
    {
      component: "Certificate", weight: "5%",
      current: `${scan.cert_key_algo} ${scan.cert_key_size} bits`,
      threat: scan.cert_key_algo?.includes("ML-DSA") ? null : "Shor's Algorithm",
      fipsId: "FIPS 204/205", compliant: fips["FIPS 204"] || fips["FIPS 205"],
      recommended: "ML-DSA cert"
    },
  ]

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/10 text-gray-400 text-xs uppercase tracking-wider">
            <th className="text-left py-2 px-3">Component</th>
            <th className="text-left py-2 px-3">Weight</th>
            <th className="text-left py-2 px-3 font-mono">Current</th>
            <th className="text-left py-2 px-3">Quantum Threat</th>
            <th className="text-left py-2 px-3">FIPS</th>
            <th className="text-left py-2 px-3 text-green-400">Recommended</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-white/5 hover:bg-white/5 transition-colors">
              <td className="py-2 px-3 font-semibold text-white">{row.component}</td>
              <td className="py-2 px-3 text-gray-400 font-mono text-xs">{row.weight}</td>
              <td className="py-2 px-3 font-mono text-xs text-cyan-300">{row.current}</td>
              <td className="py-2 px-3">
                {row.threat
                  ? <span className="flex items-center gap-1 text-red-400 text-xs"><XCircle size={12}/>{row.threat}</span>
                  : <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle size={12}/>None</span>}
              </td>
              <td className="py-2 px-3">
                {row.compliant === null
                  ? <span className="text-gray-500 text-xs">N/A</span>
                  : row.compliant
                    ? <span className="text-green-400 text-xs font-mono">✅ {row.fipsId}</span>
                    : <span className="text-red-400 text-xs font-mono">❌ {row.fipsId}</span>}
              </td>
              <td className="py-2 px-3 text-green-400 font-mono text-xs">{row.recommended}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── MIGRATION ROADMAP ──────────────────────
function MigrationRoadmap({ roadmap }) {
  const colors = ["#ff4444", "#ffaa00", "#00d4ff", "#00ff88"]
  return (
    <div className="space-y-3">
      {roadmap.map((phase, i) => (
        <div key={i} className="glass rounded-lg p-4 border-l-4" style={{ borderLeftColor: colors[i] }}>
          <div className="flex items-center justify-between mb-2">
            <div>
              <span className="font-bold text-white">Phase {phase.phase}: {phase.title}</span>
              <span className="ml-2 text-xs text-gray-400 font-mono">{phase.timeframe}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-xs px-2 py-0.5 rounded bg-white/10 text-gray-300">
                Effort: {phase.effort}
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-white/10 text-gray-300">
                Risk: {phase.risk}
              </span>
            </div>
          </div>
          <ul className="space-y-1">
            {phase.tasks.map((task, j) => (
              <li key={j} className="flex items-start gap-2 text-sm text-gray-300">
                <span className="mt-0.5 w-4 h-4 rounded border border-gray-600 flex-shrink-0" />
                {task}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}

// ─── ASSET CARD ─────────────────────────────
function AssetCard({ asset }) {
  const [expanded, setExpanded] = useState(false)
  const color = getRiskColor(asset.score)
  const fips = asset.fips_compliance

  return (
    <div className={`glass rounded-xl border ${getRiskBg(asset.score)} overflow-hidden`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 cursor-pointer"
        onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
          <div>
            <div className="font-mono font-bold text-white">{asset.host}</div>
            <div className="text-xs text-gray-400 font-mono">{asset.ip}</div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {/* FIPS mini badges */}
          <div className="hidden md:flex gap-1">
            {["FIPS 203","FIPS 204","FIPS 205"].map(f => (
              <span key={f} className={`text-xs px-1.5 py-0.5 rounded font-mono
                ${fips[f] ? "bg-green-400/20 text-green-400" : "bg-red-400/20 text-red-400"}`}>
                {f.replace("FIPS ","")}
              </span>
            ))}
          </div>
          <div className="text-right">
            <div className="text-xl font-bold font-mono" style={{ color }}>{asset.score}</div>
            <div className="text-xs text-gray-400">/100 risk</div>
          </div>
          {expanded ? <ChevronDown size={18} className="text-gray-400" /> : <ChevronRight size={18} className="text-gray-400" />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-white/10 p-4 space-y-6">
          {/* Score + Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="text-xs uppercase tracking-wider text-gray-400 mb-3">Quantum Risk Score</h4>
              <ScoreGauge score={asset.score} />
            </div>
            <div>
              <h4 className="text-xs uppercase tracking-wider text-gray-400 mb-3">Score Breakdown</h4>
              <ScoreBreakdown breakdown={asset.breakdown} />
            </div>
          </div>

          {/* FIPS Compliance */}
          <div>
            <h4 className="text-xs uppercase tracking-wider text-gray-400 mb-3">NIST FIPS Compliance</h4>
            <div className="grid grid-cols-3 gap-3">
              {[
                { id: "FIPS 203", name: "ML-KEM", fn: "Key Exchange" },
                { id: "FIPS 204", name: "ML-DSA", fn: "Signatures" },
                { id: "FIPS 205", name: "SLH-DSA", fn: "Hash Signatures" },
              ].map(f => (
                <div key={f.id} className={`rounded-lg p-3 border text-center
                  ${fips[f.id] ? "border-green-400/30 bg-green-400/5" : "border-red-400/30 bg-red-400/5"}`}>
                  <div className={`text-lg mb-1 ${fips[f.id] ? "text-green-400" : "text-red-400"}`}>
                    {fips[f.id] ? "✅" : "❌"}
                  </div>
                  <div className="font-mono font-bold text-xs text-white">{f.id}</div>
                  <div className="text-xs text-gray-400">{f.name}</div>
                  <div className="text-xs text-gray-500">{f.fn}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Crypto Stack */}
          <div>
            <h4 className="text-xs uppercase tracking-wider text-gray-400 mb-3">Cryptographic Stack Analysis</h4>
            <CryptoStack scan={asset.scan} fips={fips} />
          </div>

          {/* Certificate */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: "Issuer", value: asset.scan.cert_issuer },
              { label: "Key Algorithm", value: `${asset.scan.cert_key_algo} ${asset.scan.cert_key_size}` },
              { label: "Sig Algorithm", value: asset.scan.cert_sig_algo },
              { label: "Expires", value: asset.scan.cert_expiry },
            ].map((item, i) => (
              <div key={i} className="glass rounded-lg p-3">
                <div className="text-xs text-gray-400 mb-1">{item.label}</div>
                <div className="text-sm font-mono text-cyan-300 truncate">{item.value}</div>
              </div>
            ))}
          </div>

          {/* Recommendations */}
          <div>
            <h4 className="text-xs uppercase tracking-wider text-gray-400 mb-3">Recommendations</h4>
            <div className="space-y-2">
              {asset.recommendations.map((rec, i) => {
                const colors = {
                  critical: "border-red-400/50 bg-red-400/10 text-red-400",
                  high: "border-orange-400/50 bg-orange-400/10 text-orange-400",
                  medium: "border-yellow-400/50 bg-yellow-400/10 text-yellow-400",
                  info: "border-green-400/50 bg-green-400/10 text-green-400"
                }
                return (
                  <div key={i} className={`flex items-start gap-2 p-2 rounded border text-sm ${colors[rec.priority] || colors.info}`}>
                    <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
                    <span>{rec.action}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Migration Roadmap */}
          <div>
            <h4 className="text-xs uppercase tracking-wider text-gray-400 mb-3">Migration Roadmap</h4>
            <MigrationRoadmap roadmap={asset.migration_roadmap} />
          </div>
        </div>
      )}
    </div>
  )
}

// ─── PROGRESS LOG ───────────────────────────
function ProgressLog({ logs }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [logs])

  const icons = {
    discovery: "🔍",
    connectivity: "🌐",
    scanning: "🔐",
    result: "✅",
    error: "❌"
  }

  return (
    <div ref={ref} className="h-48 overflow-y-auto font-mono text-xs space-y-1 p-3 bg-black/30 rounded-lg border border-white/10">
      {logs.length === 0
        ? <div className="text-gray-500">Waiting for scan to start...</div>
        : logs.map((log, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-gray-500 flex-shrink-0">
                {new Date(log.time).toLocaleTimeString()}
              </span>
              <span>{icons[log.step] || "•"}</span>
              <span className={log.step === "result" ? "text-green-400" : "text-gray-300"}>
                {log.message}
              </span>
            </div>
          ))}
    </div>
  )
}

// ─── MAIN APP ───────────────────────────────
export default function App() {
  const [domain, setDomain] = useState("")
  const [scanning, setScanning] = useState(false)
  const [logs, setLogs] = useState([])
  const [assets, setAssets] = useState([])
  const [cbom, setCbom] = useState(null)
  const [connected, setConnected] = useState(false)
  const socketRef = useRef(null)

  useEffect(() => {
    const socket = io(SOCKET_URL, { transports: ["websocket"] })
    socketRef.current = socket

    socket.on("connect", () => setConnected(true))
    socket.on("disconnect", () => setConnected(false))

    socket.on("scan_progress", (data) => {
      setLogs(prev => [...prev, { ...data, time: Date.now() }])
      if (data.step === "result" && data.data?.asset) {
        setAssets(prev => [...prev, data.data.asset])
      }
    })

    socket.on("scan_complete", (data) => {
      setCbom(data.cbom)
      setScanning(false)
      setLogs(prev => [...prev, {
        step: "result",
        message: `Scan complete — ${data.cbom.total_assets} assets scanned`,
        time: Date.now()
      }])
    })

    socket.on("scan_error", (data) => {
      setScanning(false)
      setLogs(prev => [...prev, { step: "error", message: data.message, time: Date.now() }])
    })

    return () => socket.disconnect()
  }, [])

  const startScan = () => {
    if (!domain.trim() || scanning) return
    setAssets([])
    setLogs([])
    setCbom(null)
    setScanning(true)
    socketRef.current?.emit("start_scan", { domain: domain.trim() })
  }

  const exportCBOM = () => {
    if (!cbom) return
    const blob = new Blob([JSON.stringify(cbom, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `CBOM_${cbom.target_domain}_${new Date().toISOString().slice(0,10)}.json`
    a.click()
  }

  const avgScore = assets.length
    ? Math.round(assets.reduce((s, a) => s + a.score, 0) / assets.length)
    : null

  return (
    <div className="min-h-screen bg-navy">
      {/* Header */}
      <div className="border-b border-white/10 bg-navy-card/50 sticky top-0 z-50 backdrop-blur">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="text-cyan-400" size={28} />
            <div>
              <h1 className="text-xl font-bold text-white">QuantumShield</h1>
              <p className="text-xs text-gray-400">PQC Readiness Scanner — PNB Hackathon 2025-26</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {cbom && (
              <button onClick={exportCBOM}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-400/10 border border-cyan-400/30 rounded-lg text-cyan-400 text-sm hover:bg-cyan-400/20 transition-colors">
                <Download size={14} /> Export CBOM
              </button>
            )}
            <div className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border
              ${connected ? "border-green-400/30 text-green-400" : "border-red-400/30 text-red-400"}`}>
              <div className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-green-400 pulse-cyan" : "bg-red-400"}`} />
              {connected ? "Connected" : "Disconnected"}
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">

        {/* Scan Input */}
        <div className="glass rounded-2xl p-6 glow-cyan">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <Search size={18} className="text-cyan-400" />
            Scan Target Domain
          </h2>
          <div className="flex gap-3">
            <input
              type="text"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && startScan()}
              placeholder="e.g. sbi.co.in or pnb.co.in"
              className="flex-1 bg-black/30 border border-white/20 rounded-xl px-4 py-3 font-mono text-white placeholder-gray-600 focus:outline-none focus:border-cyan-400/50 transition-colors"
            />
            <button
              onClick={startScan}
              disabled={scanning || !domain.trim()}
              className={`px-8 py-3 rounded-xl font-bold flex items-center gap-2 transition-all
                ${scanning || !domain.trim()
                  ? "bg-gray-700 text-gray-500 cursor-not-allowed"
                  : "bg-cyan-400 text-navy hover:bg-cyan-300 active:scale-95"}`}>
              {scanning
                ? <><div className="w-4 h-4 border-2 border-navy/30 border-t-navy rounded-full animate-spin" /> Scanning...</>
                : <><Zap size={16} /> Scan</>}
            </button>
          </div>

          {/* Progress Steps */}
          {scanning && (
            <div className="mt-4 flex gap-2 text-xs flex-wrap">
              {["Subdomain Discovery", "Connectivity Check", "TLS Scanning", "Risk Analysis", "Report"].map((step, i) => (
                <div key={i} className="flex items-center gap-1 text-gray-400">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 pulse-cyan" />
                  {step}
                  {i < 4 && <ChevronRight size={10} className="text-gray-600" />}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Live Progress Log */}
        {(scanning || logs.length > 0) && (
          <div className="glass rounded-2xl p-4">
            <h3 className="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wider">Live Progress</h3>
            <ProgressLog logs={logs} />
          </div>
        )}

        {/* Summary Stats */}
        {assets.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Assets Scanned", value: assets.length, color: "text-cyan-400" },
              { label: "Avg Risk Score", value: avgScore + "/100", color: avgScore > 70 ? "text-red-400" : avgScore > 40 ? "text-yellow-400" : "text-green-400" },
              { label: "High Risk Assets", value: assets.filter(a => a.score > 70).length, color: "text-red-400" },
              { label: "FIPS Compliant", value: assets.filter(a => Object.values(a.fips_compliance).every(Boolean)).length, color: "text-green-400" },
            ].map((stat, i) => (
              <div key={i} className="glass rounded-xl p-4 text-center">
                <div className={`text-3xl font-bold font-mono mb-1 ${stat.color}`}>{stat.value}</div>
                <div className="text-xs text-gray-400 uppercase tracking-wider">{stat.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Asset Results */}
        {assets.length > 0 && (
          <div className="space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Shield size={18} className="text-cyan-400" />
              Scanned Assets ({assets.length})
            </h2>
            {assets.map((asset, i) => (
              <AssetCard key={i} asset={asset} />
            ))}
          </div>
        )}

        {/* PQC Certificate */}
        {cbom && (() => {
          const safe = assets.filter(a => a.score <= 20)
          if (safe.length === 0) return null
          return (
            <div className="glass rounded-2xl p-6 border border-yellow-400/30 bg-yellow-400/5 text-center">
              <div className="text-4xl mb-3">🏆</div>
              <h3 className="text-xl font-bold text-yellow-400 mb-2">PQC READY CERTIFICATE</h3>
              <p className="text-gray-300 text-sm mb-4">
                The following assets implement NIST-standardized Post-Quantum Cryptography
              </p>
              {safe.map((a, i) => (
                <div key={i} className="inline-flex items-center gap-2 px-4 py-2 bg-green-400/10 border border-green-400/30 rounded-full text-green-400 text-sm font-mono m-1">
                  <CheckCircle size={14} /> {a.host}
                </div>
              ))}
              <p className="text-gray-500 text-xs mt-4 font-mono">
                Issued: {new Date().toISOString().slice(0,10)} • Standards: FIPS 203 | FIPS 204 | FIPS 205
              </p>
            </div>
          )
        })()}

        {/* Empty state */}
        {!scanning && assets.length === 0 && (
          <div className="text-center py-20 text-gray-600">
            <Shield size={64} className="mx-auto mb-4 opacity-20" />
            <p className="text-lg">Enter a domain above to start scanning</p>
            <p className="text-sm mt-2">Try: sbi.co.in · pnb.co.in · hdfcbank.com</p>
          </div>
        )}
      </div>
    </div>
  )
}
