import React, { createContext, useContext, useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import './styles.css'
import { get, post, setCSRF } from './lib/api'
import { AuthValue, User } from './lib/types'
import { Loading, ToastProvider, setDisplayTimezone } from './components/ui'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Reviews from './pages/Reviews'
import NewReview from './pages/NewReview'
import ReviewDetail from './pages/ReviewDetail'
import Templates from './pages/Templates'
import TemplateDetail from './pages/TemplateDetail'
import ImportWizard from './pages/ImportWizard'
import RuleSimulator from './pages/RuleSimulator'
import UsersPage from './pages/Users'
import SettingsPage from './pages/Settings'
import AuditPage from './pages/Audit'
import Reports from './pages/Reports'
import LogsPage from './pages/Logs'
import JobsPage from './pages/Jobs'
import ProfilePage from './pages/Profile'
import KeysPage from './pages/Keys'
import SecurityPage from './pages/Security'
import Integrations from './pages/Integrations'
import Notifications from './pages/Notifications'
import ControlsPage from './pages/Controls'

const AuthContext = createContext<AuthValue | null>(null)
export function useAuth() { const value = useContext(AuthContext); if (!value) throw new Error('Auth context missing'); return value }

function App() {
  const [publicConfig, setPublicConfig] = useState({ service_name: 'SecCheck', version: 'dev', oidc_enabled: false, timezone: '' })
  const [me, setMe] = useState<{ user: User; version: string; totp_enrollment_required?: boolean } | null | undefined>(undefined)
  const refresh = async () => { try { const value = await get<{ user: User; csrf_token: string; version: string; totp_enrollment_required?: boolean; timezone?: string }>('/api/v1/me'); setCSRF(value.csrf_token); setDisplayTimezone(value.timezone || ''); setMe(value) } catch { setCSRF(''); setMe(null) } }
  useEffect(() => { get<typeof publicConfig>('/api/v1/public/config').then(value => { setDisplayTimezone(value.timezone || ''); setPublicConfig(value) }).catch(() => undefined); refresh() }, [])
  if (me === undefined) return <Loading />
  if (!me) return <Login config={publicConfig} onLogin={(user) => setMe({ user, version: publicConfig.version })} />
  const logout = async () => { try { await post('/api/v1/auth/logout') } finally { setCSRF(''); setMe(null) } }
  // Policy can require a second factor before anything else is reachable, so
  // the router collapses to the enrolment screen until it exists.
  if (me.totp_enrollment_required) {
    return <AuthContext.Provider value={{ user: me.user, version: me.version, refresh, logout }}><Routes><Route element={<Layout />}><Route path="*" element={<SecurityPage />} /></Route></Routes></AuthContext.Provider>
  }
  return <AuthContext.Provider value={{ user: me.user, version: me.version, refresh, logout }}><Routes><Route element={<Layout />}><Route index element={<Dashboard />} /><Route path="reviews" element={<Reviews />} /><Route path="reviews/new" element={<NewReview />} /><Route path="reviews/:id" element={<ReviewDetail />} /><Route path="security" element={<Reviews security />} /><Route path="controls" element={<ControlsPage />} /><Route path="reports" element={<Reports />} /><Route path="templates" element={<Templates />} /><Route path="templates/import" element={<ImportWizard />} /><Route path="templates/rules" element={<RuleSimulator />} /><Route path="templates/:id" element={<TemplateDetail />} /><Route path="admin/users" element={<UsersPage />} /><Route path="admin/settings" element={<SettingsPage />} /><Route path="admin/audit" element={<AuditPage />} /><Route path="admin/logs" element={<LogsPage />} /><Route path="admin/jobs" element={<JobsPage />} /><Route path="profile" element={<ProfilePage />} /><Route path="profile/keys" element={<KeysPage />} /><Route path="profile/security" element={<SecurityPage />} /><Route path="integrations" element={<Integrations />} /><Route path="notifications" element={<Notifications />} /><Route path="*" element={<Navigate to="/" replace />} /></Route></Routes></AuthContext.Provider>
}

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><ToastProvider><App /></ToastProvider></BrowserRouter></React.StrictMode>)
