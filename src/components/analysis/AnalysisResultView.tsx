import {
  FEATURE_DESCRIPTIONS,
  FEATURE_NAMES,
  FEATURE_NOTES,
  type AnalysisResult,
  type AnalysisHistoryRecord,
  type FeatureName,
} from '../../services/urlAnalysis'

type ResultFields = Pick<AnalysisResult,
  'normalized_url' | 'prediction' | 'model_version' | 'model_algorithm' |
  'phishing_score' | 'legitimate_score' | 'decision_threshold' | 'measured_features' | 'explanation'> &
  Partial<Pick<AnalysisResult, 'novelty_detection'>> &
  Partial<Pick<AnalysisResult, 'model_scope' | 'interpretation'>>

type Props = {
  result: ResultFields | AnalysisHistoryRecord
  archived?: boolean
  createdAt?: string
}

function formatScore(score: number) {
  return `${(score * 100).toFixed(1)}%`
}

function formatLogit(value: number) {
  return `${value >= 0 ? '+' : ''}${value.toFixed(4)}`
}

function displayFeature(name: FeatureName, value: number) {
  if (['uses_https', 'is_ip_hostname', 'authority_has_at_sign', 'path_has_dot_segment', 'has_fragment'].includes(name)) {
    return value ? 'Yes' : 'No'
  }
  return value.toLocaleString()
}

function formatAlgorithm(value: string) {
  if (value === 'random_forest') return 'Random Forest'
  if (value === 'logistic_regression') return 'Logistic Regression'
  return value.replaceAll('_', ' ')
}

export function AnalysisResultView({ result, archived = false, createdAt }: Props) {
  const scope = 'model_scope' in result ? result.model_scope : undefined
  const interpretation = 'interpretation' in result ? result.interpretation : undefined
  const novelty = 'novelty_detection' in result ? result.novelty_detection : undefined

  return (
    <div className={`result-content${archived ? ' result-content-archived' : ''}`}>
      {archived && <p className="archive-label">SAVED RESULT · NOT REANALYZED</p>}
      <p className={`prediction prediction-${result.prediction}`}>
        {result.prediction === 'phishing' ? 'Phishing prediction' : 'Legitimate prediction'}
      </p>
      <p className="result-url">{result.normalized_url}</p>
      {createdAt && <p className="result-created-at">Saved {new Date(createdAt).toLocaleString()}</p>}

      <div className="score-grid" aria-label="Uncalibrated model scores">
        <div className="score-item score-phishing">
          <div><span>PHISHING MODEL SCORE</span><strong>{formatScore(result.phishing_score)}</strong></div>
          <div className="score-track" aria-hidden="true"><span style={{ width: formatScore(result.phishing_score) }} /></div>
        </div>
        <div className="score-item score-legitimate">
          <div><span>LEGITIMATE MODEL SCORE</span><strong>{formatScore(result.legitimate_score)}</strong></div>
          <div className="score-track" aria-hidden="true"><span style={{ width: formatScore(result.legitimate_score) }} /></div>
        </div>
      </div>
      <p className="score-disclaimer">Uncalibrated outputs from the classifier; they are not calibrated real-world probabilities or guarantees.</p>

      <dl className="result-metadata">
        <div><dt>MODEL VERSION</dt><dd>{result.model_version}</dd></div>
        <div><dt>ALGORITHM</dt><dd>{formatAlgorithm(result.model_algorithm)}</dd></div>
        <div><dt>DECISION THRESHOLD</dt><dd>{formatScore(result.decision_threshold)}</dd></div>
      </dl>
      {scope && <p className="result-scope">{scope}</p>}
      {interpretation && <p className="result-caveat">{interpretation}</p>}
      {archived && <p className="result-caveat">This view uses the values saved with the original analysis. Opening it does not rerun the model.</p>}

      <section className="novelty-section" aria-labelledby="novelty-title">
        <div className="feature-heading novelty-heading"><h3 id="novelty-title">NOVELTY DETECTION</h3><span>SEPARATE FROM PHISHING CLASSIFICATION</span></div>
        {!novelty ? <><p className="novelty-verdict">Unavailable</p><p className="novelty-note">No novelty result was saved with this historical analysis.</p></> : !novelty.available ? <>
          <p className="novelty-verdict">Unavailable</p><p className="novelty-note">{novelty.interpretation}</p>
        </> : <>
          <p className="novelty-verdict">{novelty.is_unusual ? 'Unusual' : 'Within familiar training patterns'}</p>
          <p className="novelty-note">{novelty.interpretation}</p>
          <dl className="novelty-metadata">
            <div><dt>ANOMALY SCORE</dt><dd>{novelty.anomaly_score!.toFixed(6)}</dd></div>
            <div><dt>THRESHOLD</dt><dd>{novelty.threshold!.toFixed(6)}</dd></div>
            <div><dt>DETECTOR VERSION</dt><dd>{novelty.detector_version}</dd></div>
          </dl>
          <p className="novelty-note">Novelty measures structural deviation from legitimate training URLs. An unusual URL is not automatically phishing; a familiar pattern is not proof of legitimacy.</p>
        </>}
      </section>

      {result.explanation && <section className="explanation-section" aria-labelledby="explanation-title">
        <div className="feature-heading explanation-heading">
          <h3 id="explanation-title">WHY THE MODEL DECIDED</h3>
          <span>LOGISTIC REGRESSION / LOGIT</span>
        </div>
        <p className="explanation-note">
          These are additive mathematical contributions to this model's phishing logit, not causal explanations.
          Positive values move the logit toward phishing; negative values move it toward legitimate. No contribution
          proves that a URL is malicious. The measured URL characteristics are listed separately below.
        </p>
        <dl className="explanation-summary">
          <div><dt>INTERCEPT</dt><dd>{formatLogit(result.explanation.intercept)}</dd></div>
          <div><dt>RECONSTRUCTED PHISHING LOGIT</dt><dd>{formatLogit(result.explanation.reconstructed_logit)}</dd></div>
          <div><dt>PIPELINE DECISION FUNCTION</dt><dd>{formatLogit(result.explanation.decision_function_logit)}</dd></div>
        </dl>
        <ol className="contribution-list">
          {[...result.explanation.feature_contributions]
            .sort((left, right) => Math.abs(right.logit_contribution) - Math.abs(left.logit_contribution))
            .map((item) => (
              <li key={item.feature_name} className={`contribution-item contribution-${item.direction}`}>
                <div className="contribution-main">
                  <div>
                    <strong>{FEATURE_DESCRIPTIONS[item.feature_name]}</strong>
                    <code>{item.feature_name}</code>
                    <span className="contribution-direction">{item.direction.replaceAll('_', ' ')}</span>
                  </div>
                  <strong className="contribution-value">{formatLogit(item.logit_contribution)}</strong>
                </div>
                <p>Measured {item.measured_value.toLocaleString()} · standardized {item.standardized_value.toFixed(4)} × coefficient {item.coefficient.toFixed(4)}</p>
              </li>
            ))}
        </ol>
        <p className="explanation-reconciliation">
          Intercept plus all 17 contributions reconstructs the pipeline decision function
          (absolute difference {result.explanation.reconstruction_error.toExponential(2)}).
        </p>
        <p className="explanation-model-version">Explanation generated by {result.explanation.model_version}.</p>
      </section>}

      <div className="feature-heading"><h3>Measured URL features</h3><span>17 MODEL INPUTS</span></div>
      <p className="feature-note">These measurements describe URL characteristics. They are not individual explanations of the model decision and do not prove malicious intent.</p>
      <dl className="feature-list">
        {FEATURE_NAMES.map((name) => (
          <div key={name}>
            <dt>{FEATURE_DESCRIPTIONS[name]}<small>{FEATURE_NOTES[name]}</small></dt>
            <dd>{displayFeature(name, result.measured_features[name])}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
