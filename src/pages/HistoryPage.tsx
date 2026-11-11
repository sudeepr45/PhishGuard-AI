import { useCallback, useEffect, useState } from 'react'
import { AnalysisResultView } from '../components/analysis/AnalysisResultView'
import {
  clearAnalysisHistory,
  deleteAnalysis,
  getAnalysisById,
  getAnalysisHistory,
  type AnalysisHistoryPage as HistoryPageResult,
  type AnalysisHistoryRecord,
} from '../services/urlAnalysis'

const PAGE_SIZE = 10

type HistoryPageProps = {
  analysisId?: number
  navigate: (to: string) => void
}

function savedDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function HistoryDetail({ analysisId, navigate }: { analysisId: number; navigate: (to: string) => void }) {
  const [record, setRecord] = useState<AnalysisHistoryRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadRecord = useCallback(async () => {
    try {
      const savedRecord = await getAnalysisById(analysisId)
      setError('')
      setRecord(savedRecord)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not load this saved analysis.')
      setRecord(null)
    } finally {
      setLoading(false)
    }
  }, [analysisId])

  useEffect(() => {
    let active = true
    getAnalysisById(analysisId).then((savedRecord) => {
      if (!active) return
      setRecord(savedRecord)
      setError('')
    }).catch((caught: unknown) => {
      if (!active) return
      setError(caught instanceof Error ? caught.message : 'Could not load this saved analysis.')
      setRecord(null)
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [analysisId])

  async function removeRecord() {
    if (!window.confirm('Delete this saved analysis? This cannot be undone.')) return
    try {
      await deleteAnalysis(analysisId)
      setRecord(null)
      setNotice('Saved analysis deleted.')
    } catch (caught) {
      setNotice(caught instanceof Error ? caught.message : 'Could not delete this analysis.')
    }
  }

  return (
    <section className="history-page history-detail-page" aria-labelledby="history-title">
      <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD AI / RECORDS</div>
      <button className="text-button history-back" type="button" onClick={() => navigate('/history')}>← All history</button>
      <p className="kicker">SAVED ANALYSIS / {analysisId}</p>
      <h1 id="history-title">Original model result.</h1>
      {loading && <p className="history-feedback" role="status">Loading the saved analysis…</p>}
      {!loading && error && <div className="history-error" role="alert"><p>{error}</p><button className="button button-secondary" type="button" onClick={() => { setError(''); setLoading(true); void loadRecord() }}>TRY AGAIN</button></div>}
      {!loading && record && <>
        <AnalysisResultView result={record} archived createdAt={record.created_at} />
        <button className="button button-danger-outline" type="button" onClick={() => void removeRecord()}>DELETE THIS RECORD</button>
      </>}
      {notice && <p className="history-feedback" role="status">{notice}</p>}
    </section>
  )
}

export function HistoryPage({ analysisId, navigate }: HistoryPageProps) {
  if (analysisId !== undefined) return <HistoryDetail key={analysisId} analysisId={analysisId} navigate={navigate} />
  return <HistoryList navigate={navigate} />
}

function HistoryList({ navigate }: { navigate: (to: string) => void }) {
  const [page, setPage] = useState<HistoryPageResult | null>(null)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const fetchPage = useCallback(async (nextOffset: number) => {
    try {
      const nextPage = await getAnalysisHistory(PAGE_SIZE, nextOffset)
      setError('')
      setPage(nextPage)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not load analysis history.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    let active = true
    getAnalysisHistory(PAGE_SIZE, offset).then((nextPage) => {
      if (!active) return
      setPage(nextPage)
      setError('')
    }).catch((caught: unknown) => {
      if (active) setError(caught instanceof Error ? caught.message : 'Could not load analysis history.')
    }).finally(() => {
      if (active) setLoading(false)
    })
    return () => { active = false }
  }, [offset])

  async function removeRecord(record: AnalysisHistoryRecord) {
    if (!window.confirm(`Delete this saved analysis for ${record.normalized_url}?`)) return
    setNotice('')
    try {
      await deleteAnalysis(record.id)
      setNotice('Saved analysis deleted.')
      const nextOffset = page && page.items.length === 1 && offset > 0 ? Math.max(0, offset - PAGE_SIZE) : offset
      setLoading(true)
      if (nextOffset !== offset) setOffset(nextOffset)
      else await fetchPage(offset)
    } catch (caught) {
      setNotice(caught instanceof Error ? caught.message : 'Could not delete this analysis.')
    }
  }

  async function clearAll() {
    if (!window.confirm('Clear all saved analyses from this local device? This cannot be undone.')) return
    setNotice('')
    try {
      const response = await clearAnalysisHistory()
      setLoading(true)
      if (offset !== 0) setOffset(0)
      else await fetchPage(0)
      setNotice(`${response.deleted_count ?? 0} saved analyses cleared.`)
    } catch (caught) {
      setNotice(caught instanceof Error ? caught.message : 'Could not clear analysis history.')
    }
  }

  return (
    <section className="history-page" aria-labelledby="history-title">
      <div className="eyebrow"><span className="eyebrow-line" /> PHISHGUARD AI / RECORDS</div>
      <p className="kicker">LOCAL SQLITE HISTORY</p>
      <div className="history-title-row">
        <div><h1 id="history-title">Your analysis history.</h1><p className="page-lede">Completed URL analyses saved on this device. Records are shown newest first.</p></div>
        <div className="history-actions">
          <button className="button button-secondary" type="button" onClick={() => { setError(''); setLoading(true); void fetchPage(offset) }} disabled={loading}>REFRESH</button>
          {Boolean(page?.total) && <button className="button button-danger-outline" type="button" onClick={() => void clearAll()} disabled={loading}>CLEAR ALL</button>}
        </div>
      </div>
      {notice && <p className="history-notice" role="status">{notice}</p>}
      {loading && <p className="history-feedback" role="status">Loading saved analyses…</p>}
      {!loading && error && <div className="history-error" role="alert"><p>{error}</p><button className="button button-secondary" type="button" onClick={() => { setError(''); setLoading(true); void fetchPage(offset) }}>TRY AGAIN</button></div>}
      {!loading && !error && page?.total === 0 && <div className="history-empty"><span className="section-index">NO SAVED RECORDS</span><h2>Your completed analyses will appear here.</h2><p>Submit a URL from the analyzer. Successful predictions are stored in the local database.</p><button className="button button-primary" type="button" onClick={() => navigate('/analyze')}>OPEN ANALYZER <span aria-hidden="true">→</span></button></div>}
      {!loading && !error && page && page.total > 0 && <>
        <div className="history-summary"><span>{page.total.toLocaleString()} saved {page.total === 1 ? 'analysis' : 'analyses'}</span><span>PAGE {Math.floor(offset / PAGE_SIZE) + 1}</span></div>
        <div className="history-list">
          {page.items.map((record) => (
            <article className="history-record" key={record.id}>
              <button className="history-record-main" type="button" onClick={() => navigate(`/history/${record.id}`)} aria-label={`Open saved ${record.prediction} result for ${record.normalized_url}`}>
                <span className={`history-prediction prediction-${record.prediction}`}>{record.prediction === 'phishing' ? 'Phishing' : 'Legitimate'}</span>
                <span className="history-url">{record.normalized_url}</span>
                <span className="history-record-meta"><span>{savedDate(record.created_at)}</span><span>{record.model_version} · {record.model_algorithm.replaceAll('_', ' ')}</span></span>
                <span className="history-record-score">Phishing model score <strong>{(record.phishing_score * 100).toFixed(1)}%</strong></span>
              </button>
              <button className="history-delete" type="button" onClick={() => void removeRecord(record)} aria-label={`Delete saved analysis ${record.id}`}>DELETE</button>
            </article>
          ))}
        </div>
        <nav className="history-pagination" aria-label="History pages">
          <button className="button button-secondary" type="button" onClick={() => { setError(''); setLoading(true); setOffset(Math.max(0, offset - PAGE_SIZE)) }} disabled={offset === 0 || loading}>← NEWER</button>
          <span>{offset + 1}–{Math.min(offset + page.items.length, page.total)} of {page.total}</span>
          <button className="button button-secondary" type="button" onClick={() => { setError(''); setLoading(true); setOffset(offset + PAGE_SIZE) }} disabled={!page.has_more || loading}>OLDER →</button>
        </nav>
      </>}
      <p className="history-privacy">History is stored locally by the backend. Clear individual records or use Clear all to remove saved analyses; this does not delete the database itself.</p>
    </section>
  )
}
