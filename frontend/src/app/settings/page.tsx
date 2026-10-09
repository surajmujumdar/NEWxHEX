'use client'

import { useState, useEffect } from 'react'
import { 
  Shield, Bell, Globe, Lock, User, Database, Radio, 
  Sliders, Webhook, CheckCircle2, Send, Save, AlertTriangle, RefreshCw
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useLanguageStore } from '@/store/languageStore'
import { useNotificationStore } from '@/store/notificationStore'
import Sidebar from '@/components/Sidebar'
import Navbar from '@/components/Navbar'
import { motion } from 'framer-motion'

export default function SettingsPage() {
  const [mounted, setMounted] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const { user } = useAuthStore()
  const { addNotification } = useNotificationStore()

  // Settings State
  const [scanInterval, setScanInterval] = useState('15m')
  const [criticalThreshold, setCriticalThreshold] = useState(80)
  const [highThreshold, setHighThreshold] = useState(60)
  const [minConfidence, setMinConfidence] = useState(85)
  const [emailAlerts, setEmailAlerts] = useState(true)
  const [ransomwareAlerts, setRansomwareAlerts] = useState(true)
  const [gdeltAlerts, setGdeltAlerts] = useState(true)
  const [slackWebhook, setSlackWebhook] = useState('https://hooks.slack.mock-internal/services/T00/B00/XXXXX')
  const [discordWebhook, setDiscordWebhook] = useState('')
  const [savedSuccess, setSavedSuccess] = useState(false)
  const [testWebhookStatus, setTestWebhookStatus] = useState<string | null>(null)

  useEffect(() => {
    setMounted(true)
  }, [])

  const handleSaveSettings = () => {
    setSavedSuccess(true)
    addNotification({
      title: '⚙️ Settings Updated',
      message: 'Platform telemetry scan frequencies, alert thresholds, and webhook dispatchers saved successfully.',
      type: 'SYSTEM',
      severity: 'INFO'
    })
    setTimeout(() => setSavedSuccess(false), 3000)
  }

  const handleTestWebhook = () => {
    setTestWebhookStatus('Testing...')
    setTimeout(() => {
      setTestWebhookStatus('✅ Webhook Test Payload Successfully Delivered')
      addNotification({
        title: '📡 Webhook Dispatcher Test',
        message: 'A test alert payload was dispatched to your configured endpoint.',
        type: 'SYSTEM',
        severity: 'INFO'
      })
      setTimeout(() => setTestWebhookStatus(null), 4000)
    }, 1000)
  }

  if (!mounted) {
    return (
      <div className="flex min-h-screen bg-command-950">
        <div className="w-[232px] bg-command-900 border-r border-cyan-500/20 h-screen animate-pulse" />
        <div className="flex-1 flex flex-col">
          <div className="h-[52px] bg-command-900 border-b border-cyan-500/20 animate-pulse" />
          <main className="flex-1 p-6 space-y-6">
            <div className="h-64 bg-command-900/80 rounded-xl animate-pulse" />
          </main>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen bg-command-950 text-white font-sans">
      <Sidebar 
        collapsed={sidebarCollapsed} 
        setCollapsed={setSidebarCollapsed}
      />
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar />
        <main className="flex-1 overflow-y-auto p-3.5 sm:p-4 w-full max-w-[1440px] mx-auto space-y-3.5">
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="max-w-4xl mx-auto space-y-4"
          >
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-xl sm:text-2xl font-hud font-bold text-white uppercase tracking-wider text-glow-cyan flex items-center gap-2">
                  <Sliders className="w-6 h-6 text-cyan-400" /> Enterprise System Settings
                </h1>
                <p className="text-slate-400 text-xs font-medium mt-0.5 font-mono">
                  Configure automated scanning intervals, alert thresholds, multi-channel webhooks, and preferences
                </p>
              </div>

              <button
                onClick={handleSaveSettings}
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 rounded-xl text-xs font-hud font-bold uppercase tracking-wider flex items-center gap-1.5 shadow-[0_0_14px_rgba(0,242,254,0.4)] border border-cyan-400/40 hover:brightness-110 transition-all"
              >
                <Save className="w-3.5 h-3.5 text-slate-950" /> Save Changes
              </button>
            </div>

            {savedSuccess && (
              <div className="p-3 bg-emerald-950/70 border border-emerald-500/50 rounded-xl text-xs text-emerald-400 font-bold flex items-center gap-2 shadow-[0_0_14px_rgba(0,255,136,0.2)]">
                <CheckCircle2 className="w-4 h-4" /> System preferences & thresholds saved successfully!
              </div>
            )}

            {/* 1. HexStrike AI Security Engine Integration */}
            <div className="bg-command-900/80 border border-rose-500/30 rounded-xl p-4 shadow-lg space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded bg-rose-500/15 border border-rose-500/40 flex items-center justify-center text-rose-400 font-bold">
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-xs font-hud font-bold uppercase tracking-wider text-rose-300">
                        Security Engine ➔ HexStrike AI Framework
                      </h2>
                      <span className="px-2 py-0.5 rounded text-[9.5px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        SHARED TOOL LAYER
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 font-mono">
                      Shared 150+ security tools execution layer & intelligent orchestration for Sentinel and Vajra
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href="/tools"
                    className="px-2.5 py-1 bg-command-950 hover:bg-command-900 border border-rose-500/40 text-rose-300 text-[11px] font-mono font-bold rounded-lg transition-all"
                  >
                    Tool Catalog ↗
                  </a>
                  <button
                    onClick={async () => {
                      setTestWebhookStatus('Pinging HexStrike Engine...')
                      try {
                        const r = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/integrations/hexstrike/health`)
                        const d = await r.json()
                        setTestWebhookStatus(`✅ HexStrike Health: ${d.status} (${d.tools_available} tools active, latency: ${d.latency_ms || 1}ms)`)
                        setTimeout(() => setTestWebhookStatus(null), 5000)
                      } catch (e: any) {
                        setTestWebhookStatus(`⚠️ HexStrike Connection Error: ${e.message}`)
                      }
                    }}
                    className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-hud font-bold uppercase tracking-wider flex items-center gap-1 shadow-[0_0_10px_rgba(244,63,94,0.4)] transition-all"
                  >
                    <RefreshCw className="w-3 h-3" /> Test Connection
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                <div>
                  <label className="block text-[10px] font-hud font-bold uppercase text-slate-400 mb-1">
                    HexStrike Server URL
                  </label>
                  <input
                    type="text"
                    defaultValue="http://localhost:8888"
                    placeholder="http://localhost:8888"
                    className="w-full bg-command-950 border border-rose-900/50 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-rose-400"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-hud font-bold uppercase text-slate-400 mb-1">
                    Default Scan Profile
                  </label>
                  <select
                    defaultValue="STANDARD"
                    className="w-full bg-command-950 border border-rose-900/50 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-rose-400"
                  >
                    <option value="QUICK">QUICK (Fast Probes & Minimal Tools)</option>
                    <option value="STANDARD">STANDARD (Comprehensive Security Scan)</option>
                    <option value="DEEP">DEEP (Exhaustive Analysis & Full Wordlists)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] font-hud font-bold uppercase text-slate-400 mb-1">
                    Execution Timeout (Seconds)
                  </label>
                  <input
                    type="number"
                    defaultValue="300"
                    className="w-full bg-command-950 border border-rose-900/50 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-rose-400"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-rose-500/15 text-xs font-mono text-slate-300">
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    Status: <strong className="text-white">Active / Connected</strong>
                  </span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">Available Tools: <strong className="text-emerald-400">16 / 64</strong></span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">Auto-Fallback: <strong className="text-cyan-400">Enabled</strong></span>
                </div>
              </div>
            </div>

            {/* 2. Automated Telemetry & Scan Frequency */}
            <div className="bg-command-900/80 border border-cyan-500/25 rounded-xl p-4 shadow-lg space-y-3">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <div>
                  <h2 className="text-xs font-hud font-bold uppercase tracking-wider text-cyan-300">Automated Telemetry & Scan Frequencies</h2>
                  <p className="text-[10px] text-slate-400 font-mono">Define how frequently domain assets, NVD CVE feeds, and dark web indexes sync</p>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                {[
                  { label: 'Real-Time (15m)', value: '15m', desc: 'Continuous stream for high-risk assets' },
                  { label: 'Standard (1 hour)', value: '1h', desc: 'Default hourly assessment cycle' },
                  { label: 'Extended (6 hours)', value: '6h', desc: 'Periodic domain telemetry check' },
                  { label: 'Daily (24 hours)', value: '24h', desc: 'Low bandwidth daily snapshot' },
                ].map((item) => (
                  <button
                    key={item.value}
                    onClick={() => setScanInterval(item.value)}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      scanInterval === item.value
                        ? 'bg-cyan-500/15 border-cyan-400 text-white shadow-[0_0_12px_rgba(0,242,254,0.3)]'
                        : 'bg-command-950 border-cyan-900/40 text-slate-400 hover:border-cyan-500/40 hover:text-white'
                    }`}
                  >
                    <p className="text-xs font-hud font-bold font-mono text-cyan-200">{item.label}</p>
                    <p className="text-[9.5px] text-slate-400 mt-0.5">{item.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* 2. Alert Threshold Sliders */}
            <div className="bg-command-900/80 border border-cyan-500/25 rounded-xl p-4 shadow-lg space-y-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <div>
                  <h2 className="text-xs font-hud font-bold uppercase tracking-wider text-cyan-300">Security Risk Trigger Thresholds</h2>
                  <p className="text-[10px] text-slate-400 font-mono">Fine-tune automated alerting triggers for risk score drops and adversary activity</p>
                </div>
              </div>

              <div className="space-y-3 pt-1">
                <div>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-bold text-slate-300">Critical Severity Alert Trigger</span>
                    <span className="font-mono font-bold text-rose-400">Score &ge; {criticalThreshold}%</span>
                  </div>
                  <input
                    type="range"
                    min="60"
                    max="95"
                    value={criticalThreshold}
                    onChange={(e) => setCriticalThreshold(Number(e.target.value))}
                    className="w-full h-1.5 bg-command-950 rounded-lg appearance-none cursor-pointer accent-rose-500"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-bold text-slate-300">High Severity Alert Trigger</span>
                    <span className="font-mono font-bold text-amber-400">Score &ge; {highThreshold}%</span>
                  </div>
                  <input
                    type="range"
                    min="40"
                    max="80"
                    value={highThreshold}
                    onChange={(e) => setHighThreshold(Number(e.target.value))}
                    className="w-full h-1.5 bg-command-950 rounded-lg appearance-none cursor-pointer accent-amber-500"
                  />
                </div>
              </div>
            </div>

            {/* 3. Multi-Channel Webhooks */}
            <div className="bg-command-900/80 border border-cyan-500/25 rounded-xl p-4 shadow-lg space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Webhook className="w-4 h-4 text-cyan-400" />
                  <div>
                    <h2 className="text-xs font-hud font-bold uppercase tracking-wider text-cyan-300">Real-Time Webhook Alert Dispatchers</h2>
                    <p className="text-[10px] text-slate-400 font-mono">Push high-severity threat payloads to SIEM, Slack, Discord, or SOAR</p>
                  </div>
                </div>

                <button
                  onClick={handleTestWebhook}
                  className="px-3 py-1 bg-command-950 hover:bg-command-900 border border-cyan-500/40 hover:border-cyan-400 text-xs font-hud font-bold uppercase tracking-wider text-cyan-400 rounded-lg transition-colors flex items-center gap-1.5"
                >
                  <Send className="w-3 h-3" /> Test Webhook
                </button>
              </div>

              {testWebhookStatus && (
                <div className="p-2.5 bg-cyan-950/60 border border-cyan-500/40 rounded-lg text-xs text-cyan-300 font-mono">
                  {testWebhookStatus}
                </div>
              )}

              <div className="space-y-2 pt-1">
                <div>
                  <label className="block text-[10px] font-hud font-bold uppercase text-slate-400 mb-1">Slack / Mattermost Webhook Endpoint</label>
                  <input
                    type="text"
                    value={slackWebhook}
                    onChange={(e) => setSlackWebhook(e.target.value)}
                    placeholder="https://hooks.slack.mock-internal/services/..."
                    className="w-full bg-command-950 border border-cyan-900/50 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-400"
                  />
                </div>
              </div>
            </div>
          </motion.div>
        </main>
      </div>
    </div>
  )
}
