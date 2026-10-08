export type AnalysisSource = 'url' | 'website' | 'email'

const sources: { id: AnalysisSource; label: string }[] = [
  { id: 'url', label: 'URL' },
  { id: 'website', label: 'WEBSITE' },
  { id: 'email', label: 'EMAIL' },
]

type AnalysisSourceSelectorProps = {
  selected: AnalysisSource
  onSelect: (source: AnalysisSource) => void
}

export function AnalysisSourceSelector({ selected, onSelect }: AnalysisSourceSelectorProps) {
  return (
    <div className="analysis-source-selector" role="group" aria-label="Analysis source">
      {sources.map(({ id, label }) => (
        <button key={id} type="button" aria-pressed={selected === id}
          className={selected === id ? 'source-option is-selected' : 'source-option'}
          onClick={() => onSelect(id)}>
          <span className="source-option-indicator" aria-hidden="true" />{label}
        </button>
      ))}
    </div>
  )
}
