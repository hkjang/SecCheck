import React, { createContext, useContext, useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import './styles.css'
import { get, post, setCSRF } from './lib/api'
import { AuthValue, User } from './lib/types'
import { Loading, ToastProvider } from './components/ui'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Reviews from './pages/Reviews'
import NewReview from './pages/NewReview'
import ReviewDetail from './pages/ReviewDetail'
import Templates from './pages/Templates'
import TemplateDetail from './pages/TemplateDetail'
import ImportWizard from './pages/ImportWizard'
import UsersPage from './pages/Users'
import SettingsPage from './pages/Settings'
import AuditPage from './pages/Audit'
import LogsPage from './pages/Logs'
import ProfilePage from './pages/Profile'
import KeysPage from './pages/Keys'
import Integrations from './pages/Integrations'
import Notifications from './pages/Notifications'
import ControlsPage from './pages/Controls'

const AuthContext = createContext<AuthValue | null>(null)
export function useAuth() { const value = useContext(AuthContext); if (!value) throw new Error('Auth context missing'); return value }

function App() {
  const [publicConfig, setPublicConfig] = useState({ service_name: 'SecCheck', version: 'dev', oidc_enabled: false })
  const [me, setMe] = useState<{ user: User; version: string } | null | undefined>(undefined)
  const refresh = async () => { try { const value = await get<{ user: User; csrf_token: string; version: string }>('/api/v1/me'); setCSRF(value.csrf_token); setMe(value) } catch { setCSRF(''); setMe(null) } }
  useEffect(() => { get<typeof publicConfig>('/api/v1/public/config').then(setPublicConfig).catch(() => undefined); refresh() }, [])
  if (me === undefined) return <Loading />
  if (!me) return <Login config={publicConfig} onLogin={(user) => setMe({ user, version: publicConfig.version })} />
  const logout = async () => { try { await post('/api/v1/auth/logout') } finally { setCSRF(''); setMe(null) } }
  return <AuthContext.Provider value={{ user: me.user, version: me.version, refresh, logout }}><Routes><Route element={<Layout />}><Route index element={<Dashboard />} /><Route path="reviews" element={<Reviews />} /><Route path="reviews/new" element={<NewReview />} /><Route path="reviews/:id" element={<ReviewDetail />} /><Route path="security" element={<Reviews security />} /><Route path="controls" element={<ControlsPage />} /><Route path="templates" element={<Templates />} /><Route path="templates/import" element={<ImportWizard />} /><Route path="templates/:id" element={<TemplateDetail />} /><Route path="admin/users" element={<UsersPage />} /><Route path="admin/settings" element={<SettingsPage />} /><Route path="admin/audit" element={<AuditPage />} /><Route path="admin/logs" element={<LogsPage />} /><Route path="profile" element={<ProfilePage />} /><Route path="profile/keys" element={<KeysPage />} /><Route path="integrations" element={<Integrations />} /><Route path="notifications" element={<Notifications />} /><Route path="*" element={<Navigate to="/" replace />} /></Route></Routes></AuthContext.Provider>
}

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><ToastProvider><App /></ToastProvider></BrowserRouter></React.StrictMode>)
