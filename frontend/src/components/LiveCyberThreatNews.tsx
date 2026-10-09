'use client'

import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Newspaper, Radio, Clock, Globe, ArrowRight, X } from 'lucide-react'
import { newsService } from '../services/news.service'
import { useNotificationStore } from '@/store/notificationStore'

export default function LiveCyberThreatNews() {
  const [news, setNews] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showAllNews, setShowAllNews] = useState(false)
  const [selectedArticle, setSelectedArticle] = useState<any>(null)
  const { addNotification } = useNotificationStore()

  useEffect(() => {
    let isMounted = true

    const fetchData = async () => {
      try {
        const data = await newsService.getNews()
        if (isMounted && Array.isArray(data) && data.length > 0) {
          const enrichedNews = data.map((item: any) => ({
            ...item,
            source: item.source || 'GDELT Cyber Telemetry',
            category: item.category || (item.title.toLowerCase().includes('ransomware') ? 'Ransomware' : item.title.toLowerCase().includes('cve') ? 'Vulnerability' : 'Cyber Attack'),
            severity: item.severity || (item.title.toLowerCase().includes('critical') || item.title.toLowerCase().includes('zero-day') ? 'Critical' : 'High'),
            impact: item.impact || 'High'
          }))
          setNews(enrichedNews)

          const topBreaking = enrichedNews[0]
          if (topBreaking) {
            addNotification({
              title: `📰 Live Threat News: ${topBreaking.title.slice(0, 55)}...`,
              message: topBreaking.content || topBreaking.title,
              type: 'GDELT_NEWS',
              severity: topBreaking.severity === 'Critical' ? 'CRITICAL' : 'HIGH',
              link: '/updates',
              article: topBreaking
            }, true)
          }
        }
      } catch (error) {
        console.error('Error fetching cyber threat news:', error)
      } finally {
        if (isMounted) setLoading(false)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 60000)

    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [addNotification])

  if (loading) {
    return (
      <div className="bg-[#0c050d] border border-red-500/20 rounded-xl p-3 animate-pulse shadow-sm font-hud">
        <div className="flex items-center justify-between mb-2">
          <div className="h-4 w-40 bg-[#090308] rounded" />
          <div className="h-3 w-14 bg-[#090308] rounded" />
        </div>
        <div className="space-y-1.5">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-8 bg-[#090308] rounded-lg" />
          ))}
        </div>
      </div>
    )
  }

  const displayedNews = showAllNews ? news : news.slice(0, 4)

  return (
    <>
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-[#0c050d] border border-red-500/20 shadow-sm rounded-xl p-3 sm:p-3.5 hover:border-red-500/40 transition-all duration-200 font-hud flex flex-col justify-between"
      >
        <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-red-500/15">
          <div className="flex items-center gap-1.5">
            <Newspaper className="w-3.5 h-3.5 text-red-500 animate-pulse" />
            <h2 className="text-[11px] font-hud font-bold text-white uppercase tracking-widest">
              LIVE CYBER THREAT NEWS
            </h2>
            <span className="text-[8.5px] text-slate-300 bg-[#090308] px-1.5 py-0.5 rounded-full font-mono font-bold flex items-center gap-1 border border-red-500/20">
              <Radio className="w-2 h-2 text-red-500 animate-pulse" /> GDELT
            </span>
          </div>
          <button
            onClick={() => setShowAllNews(!showAllNews)}
            className="text-[9.5px] text-slate-300 hover:text-white font-hud font-bold uppercase tracking-wider transition-colors px-2 py-0.5 bg-[#090308] border border-red-500/25 rounded-full cursor-pointer"
          >
            {showAllNews ? 'Show Less' : `View (${news.length})`}
          </button>
        </div>

        <div className="space-y-1.5">
          {displayedNews.map((item, index) => (
            <div
              key={item.id || index}
              onClick={() => setSelectedArticle(item)}
              className="p-2 bg-[#090308] hover:bg-red-950/20 border border-red-500/15 hover:border-red-500/40 rounded-lg transition-all duration-150 cursor-pointer group flex flex-col justify-between"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <h4 className="text-[11px] font-bold text-slate-200 group-hover:text-red-400 transition-colors line-clamp-1 flex items-center gap-1">
                    <span>{item.title}</span>
                    <ArrowRight className="w-2.5 h-2.5 text-slate-500 group-hover:text-red-400 group-hover:translate-x-0.5 transition-transform flex-shrink-0" />
                  </h4>
                  
                  <div className="flex items-center gap-1.5 mt-0.5 text-[8.5px] text-slate-400 font-medium font-mono">
                    <span className="text-slate-300 font-bold">{item.source}</span>
                    <span>•</span>
                    <span>{item.time_ago || 'Recent'}</span>
                    <span>•</span>
                    <span className={`text-[8px] px-1.5 py-0.2 rounded border font-hud font-bold uppercase ${
                      item.severity?.toLowerCase() === 'critical' ? 'bg-red-950/60 text-red-400 border-red-500/40' : 'bg-amber-950/60 text-amber-400 border-amber-500/40'
                    }`}>
                      {item.severity || 'HIGH'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* In-Portal News Article Reader Modal */}
      {selectedArticle && (
        <div 
          className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-3 animate-fadeIn font-hud"
          onClick={() => setSelectedArticle(null)}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            className="bg-[#0c050d] border border-red-500/30 rounded-xl max-w-2xl w-full max-h-[85vh] overflow-y-auto shadow-2xl p-4 sm:p-5 custom-scrollbar"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-start justify-between gap-3 pb-2.5 border-b border-red-500/20 mb-3">
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className={`text-[9px] font-hud font-bold px-2 py-0.5 rounded-full border uppercase tracking-wider ${
                    selectedArticle.severity?.toLowerCase() === 'critical' ? 'bg-red-950/60 text-red-400 border-red-500/40' : 'bg-amber-950/60 text-amber-400 border-amber-500/40'
                  }`}>
                    {selectedArticle.severity || 'HIGH'} SEVERITY
                  </span>
                  <span className="text-[9px] font-mono font-bold px-2 py-0.5 bg-red-950/40 text-red-400 rounded border border-red-500/30 uppercase">
                    {selectedArticle.category || 'CYBER_ATTACK'}
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono font-bold flex items-center gap-1">
                    <Clock className="w-3 h-3 text-red-500" /> {selectedArticle.time_ago || 'Recent Telemetry'}
                  </span>
                </div>
                <h2 className="text-sm sm:text-base font-hud font-black text-white leading-snug tracking-wide uppercase">
                  {selectedArticle.title}
                </h2>
                <p className="text-[10px] text-slate-400 flex items-center gap-1 font-mono">
                  <Globe className="w-3 h-3 text-red-500" /> Source: <strong className="text-white font-hud font-bold">{selectedArticle.source}</strong>
                </p>
              </div>

              <button
                onClick={() => setSelectedArticle(null)}
                className="p-1 rounded-lg bg-[#090308] border border-red-500/20 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="space-y-3 font-main text-xs text-slate-300 leading-relaxed">
              <p>{selectedArticle.content || selectedArticle.description || selectedArticle.title}</p>
            </div>
          </motion.div>
        </div>
      )}
    </>
  )
}
