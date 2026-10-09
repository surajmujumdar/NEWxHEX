'use client'

import React, { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/authStore'
import { usePlatformStore } from '@/store/platformStore'
import Sidebar from '@/components/Sidebar'
import Navbar from '@/components/Navbar'
import HexStrikeCockpit from '@/components/HexStrikeCockpit'

export default function HexStrikePage() {
  const router = useRouter()
  const { isAuthenticated } = useAuthStore()
  const { setPlatform } = usePlatformStore()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    setPlatform('HEXSTRIKE')
  }, [setPlatform])

  useEffect(() => {
    if (mounted && !isAuthenticated) {
      router.push('/login')
    }
  }, [isAuthenticated, router, mounted])

  if (!mounted || !isAuthenticated) {
    return null
  }

  return (
    <div className="flex min-h-screen bg-[#060205] text-white selection:bg-red-500/30 selection:text-red-200">
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar />

        <main className="flex-1 overflow-y-auto p-2.5 sm:p-4 mx-auto w-full max-w-[1720px] space-y-3">
          <HexStrikeCockpit />
        </main>
      </div>
    </div>
  )
}
