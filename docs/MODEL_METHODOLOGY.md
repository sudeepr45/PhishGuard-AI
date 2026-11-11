# Model methodology and results

This document records the Phase 1 URL-classification pipeline implemented in `backend/src/training.py`, `backend/src/features.py`, and the saved `outputs/phase-a/final_test_evaluation.json`. The dataset and generated model/evaluation artifacts are local and Git-ignored. The reported values below were checked against the current saved evaluation JSON.

## Dataset and target

The source is the UCI PhiUSIIL Phishing URL (Website) Dataset, UCI ID 967. The raw snapshot has **235,795** rows. The code reads only the `URL` and `label` columns; source `label=1` means legitimate and source `label=0` means phishing. The pipeline maps these to `is_phishing=0` for legitimate and `is_phishing=1` for phishing.

| Audit item | Count |
|---|---:|
| Source records | 235,795 |
| Invalid URLs removed | 0 |
| Invalid labels removed | 0 |
| Exact duplicate `(URL, label)` rows removed | 425 |
| Same-label normalized URL duplicates removed | 474 |
| Conflicting normalized URL groups | 1 |
| Rows removed from conflicting group | 2 |
| Retained records | 234,894 |
| Retained legitimate | 134,849 |
| Retained phishing | 100,045 |
| Registrable-domain groups | 175,508 |
| Domains containing both labels | 119 |

Cleaning strips surrounding whitespace from URL text, validates explicit HTTP(S) URL syntax and source labels, removes exact duplicates, then builds a canonical URL using scheme/hostname casing, IDNA hostname form, default ports and empty-path rules. Path, query and fragment are preserved. Same-label canonical URL duplicates are collapsed. Every row in a conflicting URL group is excluded; the pipeline does not choose a label based on row order. Feature rows are computed from the canonical URL used for deduplication, matching runtime inference. Original trimmed source URLs remain available during dataset loading for audit/domain processing. Scheme-less dataset records are rejected by the existing validation policy rather than assigned an invented scheme; the inspected dataset contains zero scheme-less records.

The dataset also contains precomputed fields such as `FILENAME` and `URLSimilarityIndex`. They are excluded because they are not among the deterministic URL-string inputs available at inference and can encode information beyond the submitted URL. The trainer explicitly loads only `URL` and `label`.

## Runtime feature set

The API and model use these 17 integer-valued measurements in the listed order. All are computed from the submitted URL text; there are no DNS lookups, HTTP requests or page parsing.

| # | Feature | Meaning |
|---:|---|---|
| 1 | `url_length` | Unicode code-point count of the canonical URL passed to the extractor by both training and API inference. |
| 2 | `hostname_length` | Parsed hostname length, excluding user information and port. |
| 3 | `hostname_dot_count` | Literal dots in the hostname. |
| 4 | `subdomain_count` | Public Suffix List-aware subdomain label count; zero for IP addresses or absent hosts. |
| 5 | `hyphen_count` | Hyphens across the URL. |
| 6 | `digit_count` | Digits across the URL. |
| 7 | `is_ip_hostname` | Whether the hostname parses as an IP address (0/1). |
| 8 | `uses_https` | Whether the URL scheme is HTTPS (0/1); does not test live TLS. |
| 9 | `authority_has_at_sign` | Whether the URL authority contains `@` (0/1). |
| 10 | `percent_encoding_count` | Valid percent escapes followed by two hexadecimal digits. |
| 11 | `malformed_percent_count` | Percent signs not followed by two hexadecimal digits. |
| 12 | `path_length` | Parsed path length. |
| 13 | `path_segment_count` | Number of nonempty slash-separated path segments. |
| 14 | `path_has_dot_segment` | Whether a literal path segment is `.` or `..` (0/1); encoded forms are not decoded. |
| 15 | `query_length` | Query length, excluding `?`. |
| 16 | `query_parameter_count` | Number of nonempty `&`-separated query components. |
| 17 | `has_fragment` | Whether the URL has a nonempty fragment (0/1). |

These are measured input characteristics, not feature attribution or proof of intent. Definitions are maintained in [backend/FEATURES.md](../backend/FEATURES.md).

**Training/serving normalization:** the active `url-classifier-3` artifact and API both use canonical URLs with the same 17-feature extractor. The earlier `url-classifier-2` Random Forest and its evaluation used trimmed source representations for training/evaluation while runtime inference used canonical URLs; those results are historical and do not describe the current runtime model. The original candidate files remain under `outputs/phase-a-parity-candidate/`; the approved model was promoted with a new version identifier.

## Grouped data split

The pipeline groups records by registrable domain using a bundled Public Suffix List snapshot and a fixed seed of **412**. It uses `GroupShuffleSplit` to form approximate 60/20/20 training, validation and test partitions. Eight fixed candidate shuffles are compared at each split stage using split-size deviation and phishing-prevalence deviation; the candidate with the smallest combined deviation is selected. Registrable domains are checked to ensure no group crosses partitions. Mixed-label domains remain together in one partition.

Grouping by registrable domain reduces leakage from URL patterns tied to the same domain appearing in both training and evaluation partitions. It does not remove every source of dataset or temporal bias.

| Partition | Rows | Legitimate | Phishing |
|---|---:|---:|---:|
| Training | 141,463 | 81,153 | 60,310 |
| Validation | 47,135 | 26,896 | 20,239 |
| Final test | 46,296 | 26,800 | 19,496 |

**Evaluation limitation:** labels, including the held-out test labels, are used to compare candidate grouped partitions for size and phishing-prevalence balance. Thus test-set prevalence participates in partition construction. After construction, the test partition is held out from fitting and algorithm selection: the code selects the model on validation, then evaluates the selected model once on test. This is not equivalent to an externally fixed or temporal test set and should be considered when interpreting the metrics.

## Candidate models and selection

Both candidates use class balancing and a `StandardScaler` fitted on the training partition only.

- **Logistic Regression baseline:** `liblinear`, `max_iter=2000`, `class_weight="balanced"`, seed 412.
- **Random Forest challenger:** 100 trees, maximum depth 24, minimum leaf size 2, `class_weight="balanced"`, seed 412, all available CPU workers.

Random Forest is selected only if its validation phishing precision, recall and F1 are each no lower than Logistic Regression, its validation legitimate-as-phishing false-positive rate is no higher, and either phishing recall or F1 improves by at least 0.005. Accuracy and ROC-AUC are reported but not selection criteria.

### Corrected validation results

| Model | Accuracy | Precision (phishing) | Recall (phishing) | F1 (phishing) | Legitimate-as-phishing FPR | ROC-AUC | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---|
| Logistic Regression, selected | 0.93415 | 0.98043 | 0.86388 | 0.91847 | 0.012976 | 0.97007 | `[[26547, 349], [2755, 17484]]` |
| Random Forest, challenger | 0.93357 | 0.98170 | 0.86136 | 0.91760 | 0.012084 | 0.97185 | `[[26571, 325], [2806, 17433]]` |

Random Forest had slightly higher precision and ROC-AUC and a lower false-positive rate, but its recall and F1 were lower than Logistic Regression's; neither recall nor F1 improved by 0.005. It therefore failed the documented non-inferiority condition and Logistic Regression was selected as `url-classifier-3`. The rule operated as specified.

## Final held-out test results

| Metric | Corrected Logistic Regression |
|---|---:|
| Accuracy | 0.93427 |
| Phishing precision | 0.98055 |
| Phishing recall | 0.86100 |
| Phishing F1 | 0.91689 |
| Legitimate-as-phishing false-positive rate | 0.012425 |
| ROC-AUC | 0.96306 |

Confusion matrix (rows: actual legitimate, actual phishing; columns: predicted legitimate, predicted phishing):

```text
                 Predicted legitimate  Predicted phishing
Actual legitimate              26,467                 333
Actual phishing                 2,710              16,786
```

Only the validation-selected Logistic Regression was evaluated on the final test partition. **No corrected Random Forest final-test metrics are available or reported.** The old `url-classifier-2` Random Forest final-test result was accuracy 0.99231, precision 0.99932, recall 0.98241, F1 0.99079, FPR 0.000485 and ROC-AUC 0.99654, with confusion matrix `[[26787, 13], [343, 19153]]`. That historical model was evaluated on raw trimmed URL features, unlike runtime inference, and its result is not current runtime performance or directly comparable to the corrected canonical-URL model.

These measurements describe this dataset snapshot and this split only. The split is random, not temporal. No future or live-web generalization is established. The source documentation does not give enough per-record provenance to independently verify every label.

## Runtime inference and score interpretation

The API loads `outputs/phase-a/url_model.joblib` at startup. It validates the artifact's model version, algorithm, Python/scikit-learn/`tldextract` versions, feature order, estimator classes, feature count and decision threshold. A missing or incompatible artifact leaves the API running but reports the model as unavailable; startup does not train a replacement.

For a valid request, the API normalizes the URL, extracts the ordered 17 features from that normalized string, builds the model input, calls `predict` and `predict_proba`, maps output scores by the model's class labels, and applies the artifact's threshold (0.5 for this run). It writes the completed result and measurements to local SQLite before returning the response.

## Separate Isolation Forest novelty detector

The novelty detector is an independent research output. It does not replace, refit, or influence `url-classifier-3`, its prediction, scores, threshold, or explanation. It uses the same canonical URLs and exact ordered 17 URL features. No scaler is used: Isolation Forest uses tree partitions, for which monotonic feature scaling does not change split ordering.

The detector was fit only on the **81,153 legitimate rows in the existing training partition**. It did not fit on training phishing rows, validation rows, or final-test rows. The existing domain-grouped split was reused unchanged: train 141,463 records (81,153 legitimate; 60,310 phishing), validation 47,135 (26,896; 20,239), final test 46,296 (26,800; 19,496). The detector uses 300 trees, `max_samples=256`, `contamination="auto"`, `max_features=1.0`, `bootstrap=false`, `random_state=412`, and `n_jobs=-1`. Its separate artifact is `outputs/phase-a-novelty/novelty_detector.joblib`, version `url-novelty-1`; the dataset SHA-256 is the same recorded UCI CSV hash.

The anomaly score is `-IsolationForest.score_samples(X)`, where a larger value means more structurally unusual. The predeclared threshold policy selects on validation only the threshold that maximizes phishing recall subject to a configurable maximum false-positive rate among legitimate URLs. The documented default is **5%** (`--max-fpr 0.05`); ties prefer lower validation FPR and then a higher threshold. The selected validation threshold is **0.6134916036**. Validation accuracy was **0.75277**, precision **0.88475**, recall **0.48777**, F1 **0.62885**, legitimate URL alert/FPR **0.04781**, and ROC-AUC **0.78660**. Its confusion matrix (rows actual legitimate/phishing; columns predicted familiar/unusual) was `[[25610, 1286], [10367, 9872]]`.

After freezing detector parameters, feature schema, FPR limit, and threshold, the detector was evaluated once on the existing final-test partition. Accuracy was **0.78737**, phishing precision **0.90548**, phishing recall/detection rate **0.55278**, F1 **0.68648**, legitimate URL alert/FPR **0.04198**, and ROC-AUC **0.81819**. The confusion matrix (rows actual legitimate/phishing; columns predicted familiar/unusual) was `[[25675, 1125], [8719, 10777]]`. The final-test legitimate alert rate was 4.20%. These novelty metrics are separate from the Logistic Regression metrics and do not establish phishing intent or live-web generalization.

An unusual URL means its measured structure deviates from the legitimate training distribution under this detector; it is not automatically phishing. A URL within familiar patterns is not automatically legitimate. The results are shown independently and are never combined into the classifier prediction.

`phishing_score` and `legitimate_score` are uncalibrated outputs from `predict_proba`. They are not calibrated real-world probabilities or guarantees. For `url-classifier-3`, the API also returns and saves the exact standardized Logistic Regression logit contributions, tied to the model version that produced them. The contributions reconstruct the pipeline `decision_function`; they describe the model's arithmetic, not causal effects. The separate measured-feature display remains a list of observed URL characteristics, not an explanation or proof of intent. A legitimate prediction does not establish that a destination is safe.

## Scope and future work

The classifiers and novelty detector use URL strings only. The application also offers offline email header parsing and link triage, but has no email classifier. It does not fetch URLs, inspect webpage source or DOM, consult domain reputation, verify SPF/DKIM/DMARC, or use real-time threat feeds. Such capabilities are not implemented and would require separate design, data, evaluation and privacy review.
