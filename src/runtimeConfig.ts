const configuredApiBase = import.meta.env.VITE_API_BASE_URL?.trim()

export const API_BASE = (configuredApiBase || '/api').replace(/\/+$/, '')
export const PUBLIC_DEMO_MODE = import.meta.env.VITE_PUBLIC_DEMO?.trim().toLowerCase() === 'true'
