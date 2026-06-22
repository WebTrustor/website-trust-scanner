'use client'

import { useState } from 'react'

export default function CopyButton({
  text,
  label,
  copiedLabel,
}: {
  text: string
  label: string
  copiedLabel: string
}) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard not available — silently ignore
    }
  }

  return (
    <button
      onClick={handleCopy}
      className={`
        text-xs px-3 py-1.5 rounded-lg border transition-colors
        ${copied
          ? 'border-emerald-700 bg-emerald-950/40 text-emerald-400'
          : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-slate-100'
        }
      `}
    >
      {copied ? copiedLabel : label}
    </button>
  )
}
