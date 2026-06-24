'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'

const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

const ADMIN_ROLES = new Set(['admin', 'super_admin'])

type PageState = 'loading' | 'authorized' | 'error'

export default function AdminPage() {
  const params = useParams()
  const locale = params.locale as string
  const router = useRouter()
  const t = useTranslations('admin')

  const [state, setState] = useState<PageState>('loading')

  useEffect(() => {
    async function checkAuth() {
      try {
        const res = await fetch(`${BACKEND}/api/v1/auth/me`, {
          credentials: 'include',
        })
        if (res.status === 401 || res.status === 403) {
          router.replace(`/${locale}/login`)
          return
        }
        if (!res.ok) {
          setState('error')
          return
        }
        const user = (await res.json()) as { role: string }
        if (!ADMIN_ROLES.has(user.role)) {
          router.replace(`/${locale}`)
          return
        }
        setState('authorized')
      } catch {
        setState('error')
      }
    }
    checkAuth()
  }, [locale, router])

  if (state === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (state === 'error') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <p className="text-slate-400 text-sm text-center">{t('error')}</p>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-xl space-y-2">
        <h1 className="text-xl font-semibold text-slate-100">{t('title')}</h1>
        <p className="text-slate-400 text-sm">{t('subtitle')}</p>
      </div>
    </div>
  )
}
