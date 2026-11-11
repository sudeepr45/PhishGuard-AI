# Independent external URL evaluation

## Dataset and provenance

The evaluation uses **Phishing URL dataset**, Mendeley Data version 1, DOI [10.17632/vfszbj9b36.1](https://data.mendeley.com/datasets/vfszbj9b36/1). The record was published on 2 April 2024 by Jishnu K. S. Kaitholikkal and Arthi B and declares **CC BY 4.0**. Its description reports that the 450,176-row `URL dataset.csv` collection was sourced from PhishTank, Majestic Million, and other sources. The Mendeley record does not identify an associated peer-reviewed publication or provide per-row source lineage. It reports 104,438 phishing and 345,738 legitimate rows. The source record, its provenance claims, and license are available on the [Mendeley dataset page](https://data.mendeley.com/datasets/vfszbj9b36/1).

Retrieved 11 November 2026 from [the versioned public file URL](https://data.mendeley.com/public-files/datasets/vfszbj9b36/files/f0de314f-ea72-4385-9faa-f06593bb0a2d/file_downloaded). Downloaded file SHA-256:

```text
accb2dfbfd3329a8b5cb1b85dcad90314a660c272be755cb45d0f6865014b466
```

The dataset fields used are `url` and `type`; `phishing` maps to project label 1 and `legitimate` to 0. All precomputed fields are ignored. The evaluator canonicalizes URLs using the existing API normalization behavior and recomputes the exact ordered 17 features with `backend.src.features.extract_url_features`.

## Independence and overlap controls

The comparison reference is the repository's retained PhiUSIIL URL/label corpus after the same URL validation, normalization, duplicate/conflict handling, and the already-defined grouped split. No model fitting or split selection occurs in this evaluation. To avoid URL/domain memorization, the evaluator excludes every external row whose registrable domain appears anywhere in that retained PhiUSIIL corpus. Exact canonical URL overlaps and overlaps with the classifier's actual fit partition are counted separately. Registrable domains use the existing bundled Public Suffix List behavior.

This gives record- and domain-disjoint evaluation rows relative to the complete local PhiUSIIL corpus. It does **not** establish fully independent collection provenance: the external record names PhishTank, also among common phishing-feed sources, and omits row-level lineage. Thus these results are useful external corpus evidence with an explicit source-lineage limitation; they should not be described as a prospective, feed-independent, or independently re-labeled trial. We cannot rule out shared source observations whose URLs and domains differ.

## Data audit

| Check | Result |
|---|---:|
| Source rows | 450,176 |
| Missing URL / label | 0 / 0 |
| Invalid label values | 0 |
| Exact duplicate URL-label rows | 0 |
| Malformed URLs rejected | 621 |
| Normalized label-conflict groups / affected rows | 0 / 0 |
| Same-label normalized duplicate rows excluded | 314 |
| Valid unique records before overlap exclusion | 449,241 |
| Class counts before overlap exclusion | 345,584 legitimate; 103,657 phishing |
| Canonical URL overlap with full retained PhiUSIIL corpus | 1,711 |
| Canonical URL overlap with classifier fit partition | 1,014 |
| Shared registrable domains with full retained PhiUSIIL corpus | 7,754 |
| Shared registrable domains with classifier fit partition | 4,670 |
| Rows removed due to any full-corpus domain overlap | 77,644 |
| Rows after overlap exclusion | 371,597 |
| Final class counts | 276,674 legitimate; 94,923 phishing |

Counts are generated from the downloaded file by `outputs/external-evaluation/evaluation.json`. The canonical overlap count is a subset of excluded overlap-domain records. Exact duplicates use the source URL and label fields; normalized duplicate checks use canonical URLs.

## Frozen model results

Metrics are calculated on the same 371,597 domain-disjoint rows. Positive means phishing. Confusion matrix axes are `[[TN, FP], [FN, TP]]`, with legitimate then phishing labels.

### Logistic Regression classifier

Artifact: `url-classifier-3`, Logistic Regression, frozen decision threshold 0.5. Artifact SHA-256: `638dcbadf27792784483fc1daa48fa1e857fb465ccdad02db16c3c49a927ef71`.

| Metric | Result |
|---|---:|
| Accuracy | 0.3575 |
| Precision (phishing) | 0.2841 |
| Recall (phishing) | 0.9968 |
| F1 (phishing) | 0.4422 |
| FPR (legitimate classified phishing) | 0.8619 |
| ROC-AUC | 0.7711 |
| Confusion matrix | `[[38211, 238463], [300, 94623]]` |

The high recall comes with a very high false-positive rate on this corpus; accuracy is also low. These figures do not support interpreting a positive output as proof of maliciousness.

### Isolation Forest novelty detector

Artifact: `url-novelty-1`, frozen anomaly threshold 0.6134916035535135. The detector's unusual/not-unusual output is treated as a phishing-alert proxy **only for metric calculation**; the detector is not a phishing classifier. Artifact SHA-256: `bca2b732893dc9a04958560bd2cbf109b878a26381e2cb459055394267527994`.

| Metric | Result |
|---|---:|
| Accuracy | 0.4073 |
| Precision (phishing proxy) | 0.2263 |
| Recall (phishing proxy) | 0.5460 |
| F1 (phishing proxy) | 0.3200 |
| FPR (legitimate flagged unusual) | 0.6402 |
| ROC-AUC (anomaly score) | 0.4413 |
| Confusion matrix | `[[99538, 177136], [43098, 51825]]` |

Higher anomaly score means more unusual. The frozen threshold is applied as-is; no calibration or tuning was performed. Here the anomaly ranking is below chance against these source labels, underscoring that novelty and phishing are different concepts.

## Scope and limitations

- These results are separate from the original PhiUSIIL grouped final-test evaluation; no results are combined and no model-selection decision is made from this external set.
- URL and registrable-domain overlap was removed against the full retained local source corpus. Other shared provenance or campaign relationships cannot be assessed without row-level source and time metadata.
- The dataset supplies binary source labels, but this evaluation does not independently re-verify their truth or reference time. Labels can be stale or disputed; the legitimate class may reflect source collection criteria rather than a point-in-time safety guarantee.
- Excluding whole registrable domains changes the tested population. Metrics characterize only the remaining records and this dataset version.
- Features are lexical measurements of normalized URL strings only. No website is fetched and no HTML, DNS, reputation, or browser behavior is used.

## Reproduction

From the repository root, with the backend environment active:

```powershell
python -m backend.src.evaluate_external --external outputs/external-evaluation/input/URL-dataset.csv
```

The evaluator checks both frozen artifact hashes before and after scoring and writes the machine-readable record to `outputs/external-evaluation/evaluation.json`. It loads the classifier through the production artifact validator and the novelty detector through its existing validator. The evaluator contains no fit, retraining, threshold-selection, or artifact-writing call.

Other downloaded candidates were not used for metrics: the 2024 Frontiers/Mendeley dataset file in this output folder has no raw URL column, so its precomputed features cannot be substituted for canonical features; LegitPhish includes the UCI repository among cited source inputs, so its source lineage cannot establish independence from PhiUSIIL. Neither candidate's metrics are presented here.
