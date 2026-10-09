'use client'

import React, { Component, ErrorInfo, ReactNode } from 'react'
import { AlertTriangle, RefreshCw, ShieldAlert, Home, Terminal } from 'lucide-react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
}

export default class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('CRITICAL: React Client-Side Exception Caught by ErrorBoundary:', error, errorInfo)
    this.setState({ error, errorInfo })
  }

  private handleReset = () => {
    try {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('platform-mode-storage')
        window.location.reload()
      }
    } catch {
      window.location.reload()
    }
  }

  private handleHardReset = () => {
    try {
      if (typeof window !== 'undefined') {
        localStorage.clear()
        sessionStorage.clear()
        window.location.href = '/'
      }
    } catch {
      window.location.href = '/'
    }
  }

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      return (
        <div className="min-h-screen bg-[#060205] text-white flex items-center justify-center p-4 font-main select-none relative overflow-hidden">
          {/* Cosmic background glow */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-red-600/10 rounded-full blur-3xl pointer-events-none" />

          <div className="max-w-xl w-full bg-[#090308]/95 border border-[#2a1228] rounded-3xl p-6 sm:p-8 shadow-[0_0_50px_rgba(0,0,0,0.9)] relative overflow-hidden backdrop-blur-xl z-10">
            {/* Top red laser accent */}
            <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-red-600 via-rose-600 to-red-500" />

            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-red-950/60 border border-red-900/40 flex items-center justify-center text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
                <ShieldAlert className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h1 className="text-base font-hud font-bold text-white uppercase tracking-wider">
                  TELEMETRY SUBSYSTEM EXCEPTION
                </h1>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">
                  An isolated component error was intercepted by VAJRA AI Guard
                </p>
              </div>
            </div>

            <div className="bg-[#060205] border border-[#2a1228] rounded-2xl p-4 my-4 text-xs font-mono">
              <div className="flex items-center gap-1.5 text-red-400 font-bold mb-1.5">
                <Terminal className="w-3.5 h-3.5" />
                <span>EXCEPTION DIAGNOSTIC:</span>
              </div>
              <p className="text-zinc-300 break-all text-[11px] leading-relaxed">
                {this.state.error?.message || 'An unexpected client-side rendering exception occurred.'}
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-3 mt-6">
              <button
                onClick={this.handleReset}
                className="w-full sm:flex-1 py-3 px-4 bg-gradient-to-r from-red-600 via-rose-600 to-red-500 hover:from-red-500 hover:to-rose-500 text-white font-hud font-bold text-xs uppercase tracking-wider rounded-full transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(239,68,68,0.35)] cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Subsystem</span>
              </button>

              <button
                onClick={this.handleHardReset}
                className="w-full sm:flex-1 py-3 px-4 bg-[#060205] hover:bg-[#160a18] text-red-300 hover:text-white font-hud font-bold text-xs uppercase tracking-wider rounded-full transition-all flex items-center justify-center gap-2 border border-[#2a1228] hover:border-red-500/40 cursor-pointer"
              >
                <Home className="w-3.5 h-3.5" />
                <span>Clear Cache & Reset</span>
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
