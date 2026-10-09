'use client'

import { useState, useEffect } from 'react'
import {
  Wrench,
  Shield,
  Activity,
  CheckCircle2,
  XCircle,
  AlertCircle,
  RefreshCw,
  Search,
  Filter,
  Terminal,
  Cpu,
  Layers,
  Zap,
  Globe,
  Lock,
  Radio,
  Code2,
  Package
} from 'lucide-react'
import Sidebar from '@/components/Sidebar'
import Navbar from '@/components/Navbar'
import { motion, AnimatePresence } from 'framer-motion'

interface ToolItem {
  name: string
  category: string
  capabilities: string[]
  hexstrike_supported: boolean
  installed: boolean
  version?: string | null
  description?: string | null
  binary_path?: string | null
  execution_type?: string
  last_checked?: string | null
}

interface HealthData {
  status: string
  reachable: boolean
  api_available: boolean
  mcp_available: boolean
  tools_available: number
  tools_unavailable: number
  total_tools: number
  latency_ms?: number | null
  version?: string | null
  url?: string
  error?: string | null
}

const CATEGORIES = [
  'ALL',
  'WEB',
  'NETWORK',
  'RECON',
  'DNS',
  'TLS',
  'SAST',
  'SCA',
  'OSINT',
  'CLOUD',
  'CONTAINER'
]

export default function ToolHealthPage() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [tools, setTools] = useState<ToolItem[]>([])
  const [health, setHealth] = useState<HealthData | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('ALL')
  const [filterInstalled, setFilterInstalled] = useState(false)
  const [activeTestTool, setActiveTestTool] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<any>(null)
  const [testing, setTesting] = useState(false)

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

  const fetchData = async () => {
    try {
      setLoading(true)
      const [healthRes, toolsRes] = await Promise.all([
        fetch(`${apiUrl}/api/integrations/hexstrike/health`).then(r => r.json()).catch(() => null),
        fetch(`${apiUrl}/api/integrations/hexstrike/tools`).then(r => r.json()).catch(() => [])
      ])
      if (healthRes) setHealth(healthRes)
      if (Array.isArray(toolsRes)) setTools(toolsRes)
    } catch (e) {
      console.error('Error fetching tool registry:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleRefresh = async () => {
    try {
      setRefreshing(true)
      await fetch(`${apiUrl}/api/integrations/hexstrike/refresh-tools`, { method: 'POST' })
      await fetchData()
    } catch (e) {
      console.error(e)
    } finally {
      setRefreshing(false)
    }
  }

  const handleRunQuickTest = async (toolName: string) => {
    try {
      setActiveTestTool(toolName)
      setTesting(true)
      setTestResult(null)
      const res = await fetch(`${apiUrl}/api/integrations/hexstrike/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: toolName,
          target: 'https://ginandjuice.shop',
          profile: 'QUICK'
        })
      })
      const data = await res.json()
      setTestResult(data)
    } catch (e: any) {
      setTestResult({ error: e.toString() })
    } finally {
      setTesting(false)
    }
  }

  const filteredTools = tools.filter(t => {
    const matchCat = selectedCategory === 'ALL' || t.category.toUpperCase() === selectedCategory
    const matchSearch =
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.description && t.description.toLowerCase().includes(searchQuery.toLowerCase())) ||
      t.capabilities.some(c => c.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchInst = !filterInstalled || t.installed
    return matchCat && matchSearch && matchInst
  })

  const getCategoryIcon = (cat: string) => {
    switch (cat.toUpperCase()) {
      case 'WEB': return Globe
      case 'NETWORK': return Radio
      case 'RECON': return Search
      case 'DNS': return Layers
      case 'TLS': return Lock
      case 'SAST': return Code2
      case 'SCA': return Package
      default: return Terminal
    }
  }

  return (
    <div className="flex min-h-screen bg-command-950 text-white font-sans">
      <Sidebar collapsed={sidebarCollapsed} setCollapsed={setSidebarCollapsed} />

      <div className="flex-1 flex flex-col min-w-0">
        <Navbar />

        <main className="flex-1 overflow-y-auto p-4 sm:p-6 w-full max-w-[1440px] mx-auto space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-rose-500/20 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  HEXSTRIKE AI ENGINE
                </span>
                <span className="text-xs text-slate-400 font-mono">SHARED SECURITY TOOL LAYER</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-hud font-bold text-white uppercase tracking-wider flex items-center gap-2 mt-1">
                <Wrench className="w-6 h-6 text-rose-500" /> Security Tool Registry & Health
              </h1>
              <p className="text-slate-400 text-xs font-mono mt-0.5">
                Normalized orchestration catalog of 150+ security tools across SAST, DAST, SCA, Recon, DNS, and TLS
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="px-3.5 py-2 bg-command-900 border border-rose-500/30 text-rose-300 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 hover:bg-rose-500/10 hover:border-rose-400 transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                {refreshing ? 'Rescanning Host...' : 'Rescan Binaries'}
              </button>
            </div>
          </div>

          {/* Health Status Ribbon */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            {/* Status Card */}
            <div className="bg-command-900/80 border border-rose-500/25 rounded-xl p-3.5 shadow-lg flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Engine Status</p>
                <div className="flex items-center gap-2 mt-1">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      health?.status === 'Connected'
                        ? 'bg-emerald-400 animate-pulse shadow-[0_0_8px_#10b981]'
                        : health?.status === 'Partial'
                        ? 'bg-amber-400 shadow-[0_0_8px_#f59e0b]'
                        : 'bg-rose-500 shadow-[0_0_8px_#f43f5e]'
                    }`}
                  />
                  <span className="text-sm font-hud font-bold uppercase text-white">
                    {health?.status || 'Checking...'}
                  </span>
                </div>
              </div>
              <Activity className="w-5 h-5 text-rose-400 opacity-60" />
            </div>

            {/* Available Tools */}
            <div className="bg-command-900/80 border border-rose-500/25 rounded-xl p-3.5 shadow-lg flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Available Tools</p>
                <p className="text-xl font-hud font-bold text-emerald-400 mt-0.5">
                  {health?.tools_available ?? tools.filter(t => t.installed).length}
                  <span className="text-xs font-mono text-slate-400 font-normal ml-1.5">
                    / {health?.total_tools ?? tools.length}
                  </span>
                </p>
              </div>
              <CheckCircle2 className="w-5 h-5 text-emerald-400 opacity-60" />
            </div>

            {/* Unavailable Tools */}
            <div className="bg-command-900/80 border border-rose-500/25 rounded-xl p-3.5 shadow-lg flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Fallback Handlers</p>
                <p className="text-xl font-hud font-bold text-amber-400 mt-0.5">
                  {health?.tools_unavailable ?? tools.filter(t => !t.installed).length}
                  <span className="text-xs font-mono text-slate-400 font-normal ml-1.5">Active</span>
                </p>
              </div>
              <AlertCircle className="w-5 h-5 text-amber-400 opacity-60" />
            </div>

            {/* API Latency */}
            <div className="bg-command-900/80 border border-rose-500/25 rounded-xl p-3.5 shadow-lg flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Server Latency</p>
                <p className="text-xl font-hud font-bold text-cyan-400 mt-0.5">
                  {health?.latency_ms ? `${health.latency_ms} ms` : 'Local Host'}
                </p>
              </div>
              <Zap className="w-5 h-5 text-cyan-400 opacity-60" />
            </div>
          </div>

          {/* Search and Filters */}
          <div className="bg-command-900/60 border border-rose-500/20 rounded-xl p-3.5 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              {/* Search Bar */}
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search tools by name, capability (e.g. nuclei, xss, sqli, cve, port_scanning)..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="w-full bg-command-950 border border-rose-900/40 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-rose-400 transition-all"
                />
              </div>

              {/* Installed Only Checkbox */}
              <label className="flex items-center gap-2 cursor-pointer select-none text-xs font-mono text-slate-300">
                <input
                  type="checkbox"
                  checked={filterInstalled}
                  onChange={e => setFilterInstalled(e.target.checked)}
                  className="rounded border-rose-800 text-rose-500 focus:ring-0 bg-command-950"
                />
                Installed Binaries Only
              </label>
            </div>

            {/* Category Pills */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              {CATEGORIES.map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-bold uppercase transition-all ${
                    selectedCategory === cat
                      ? 'bg-rose-500 text-white shadow-[0_0_10px_rgba(244,63,94,0.4)]'
                      : 'bg-command-950 border border-rose-900/40 text-slate-400 hover:border-rose-500/40 hover:text-white'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Tools Grid / Table */}
          <div className="bg-command-900/80 border border-rose-500/25 rounded-xl overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-command-950/90 text-slate-400 border-b border-rose-500/20 text-[10px] uppercase font-hud tracking-wider">
                  <tr>
                    <th className="py-3 px-4">Tool</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Installed</th>
                    <th className="py-3 px-4">Status & Execution</th>
                    <th className="py-3 px-4">Capabilities</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rose-500/10">
                  {filteredTools.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                        No security tools found matching criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredTools.map(tool => {
                      const CatIcon = getCategoryIcon(tool.category)
                      return (
                        <tr key={tool.name} className="hover:bg-command-800/40 transition-colors">
                          {/* Tool Name & Description */}
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2.5">
                              <div className="w-7 h-7 rounded bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 font-bold">
                                <CatIcon className="w-3.5 h-3.5" />
                              </div>
                              <div>
                                <span className="font-bold text-white text-sm tracking-wide">
                                  {tool.name}
                                </span>
                                {tool.description && (
                                  <p className="text-[10px] text-slate-400 max-w-xs truncate">
                                    {tool.description}
                                  </p>
                                )}
                              </div>
                            </div>
                          </td>

                          {/* Category */}
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 border border-slate-700 text-slate-300 uppercase">
                              {tool.category}
                            </span>
                          </td>

                          {/* Installed Badge */}
                          <td className="py-3 px-4">
                            {tool.installed ? (
                              <span className="inline-flex items-center gap-1 text-emerald-400 font-bold text-[11px]">
                                <CheckCircle2 className="w-3.5 h-3.5" /> Ready
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-amber-400 font-bold text-[11px]">
                                <AlertCircle className="w-3.5 h-3.5" /> Python Fallback
                              </span>
                            )}
                          </td>

                          {/* Status / Binary */}
                          <td className="py-3 px-4">
                            <div className="text-[10.5px]">
                              <span className="text-slate-300">
                                {tool.installed ? tool.binary_path || 'PATH Binary' : 'Native Emulation Engine'}
                              </span>
                              {tool.version && (
                                <p className="text-[9.5px] text-slate-500">{tool.version}</p>
                              )}
                            </div>
                          </td>

                          {/* Capabilities */}
                          <td className="py-3 px-4">
                            <div className="flex flex-wrap gap-1 max-w-md">
                              {tool.capabilities.slice(0, 3).map((cap, i) => (
                                <span
                                  key={i}
                                  className="px-1.5 py-0.5 rounded text-[9.5px] bg-rose-500/10 border border-rose-500/20 text-rose-300 font-mono"
                                >
                                  {cap}
                                </span>
                              ))}
                              {tool.capabilities.length > 3 && (
                                <span className="text-[9.5px] text-slate-500">
                                  +{tool.capabilities.length - 3}
                                </span>
                              )}
                            </div>
                          </td>

                          {/* Test Trigger */}
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => handleRunQuickTest(tool.name)}
                              disabled={testing && activeTestTool === tool.name}
                              className="px-2.5 py-1 bg-command-950 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 hover:border-cyan-400 rounded text-[10.5px] font-mono transition-all disabled:opacity-50"
                            >
                              {testing && activeTestTool === tool.name ? 'Running...' : 'Run Test'}
                            </button>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Test Execution Output Modal */}
          <AnimatePresence>
            {activeTestTool && testResult && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="bg-command-900/90 border border-cyan-500/40 rounded-xl p-4 shadow-2xl space-y-3"
              >
                <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span className="font-hud font-bold text-sm text-cyan-300 uppercase">
                      Test Execution: {activeTestTool} ({testResult.provider})
                    </span>
                  </div>
                  <button
                    onClick={() => {
                      setActiveTestTool(null)
                      setTestResult(null)
                    }}
                    className="text-xs text-slate-400 hover:text-white font-mono"
                  >
                    Close [X]
                  </button>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-400">Duration:</span>{' '}
                    <span className="text-white font-bold">{testResult.duration_seconds}s</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Findings:</span>{' '}
                    <span className="text-emerald-400 font-bold">{testResult.findings_count}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Status:</span>{' '}
                    <span className="text-cyan-400 font-bold">{testResult.status}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Provider:</span>{' '}
                    <span className="text-amber-300 font-bold">{testResult.provider}</span>
                  </div>
                </div>

                <div className="bg-black/60 border border-cyan-900/50 rounded-lg p-3 max-h-48 overflow-y-auto font-mono text-[11px] text-slate-300 whitespace-pre-wrap">
                  {testResult.raw_output || JSON.stringify(testResult, null, 2)}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>
    </div>
  )
}
