'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function SentinelRedirect() {
  const router = useRouter()

  useEffect(() => {
    router.replace('/')
  }, [router])

  return (
    <div className="flex min-h-screen bg-[#060205] items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <div className="w-12 h-12 rounded-2xl bg-red-950/40 border border-red-900/40 flex items-center justify-center animate-pulse">
          <span className="text-red-500 font-hud font-bold text-lg">V</span>
        </div>
        <p className="text-zinc-400 text-xs font-mono tracking-widest uppercase">Redirecting to VAJRA Platform...</p>
      </div>
    </div>
  )
}
