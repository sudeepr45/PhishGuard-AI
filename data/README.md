# Phase A dataset

## Source and license

Phase A uses the **PhiUSIIL Phishing URL (Website) Dataset**, UCI Machine Learning Repository dataset 967:

- Record and download: <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset>
- Citation: Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository. <https://doi.org/10.1016/j.cose.2023.103545>
- License listed by UCI: Creative Commons Attribution 4.0 International (CC BY 4.0). Attribution is retained here. UCI describes 235,795 instances, with 134,850 legitimate URLs and 100,945 phishing URLs.
- Dataset donated to UCI on 2024-03-03. Retrieved from UCI on **2026-10-12**.
- UCI's class definition: source `label=1` is legitimate; source `label=0` is phishing. Training maps these to project target `0=legitimate`, `1=phishing` so phishing is the positive class in reported metrics.
- UCI describes rows as URLs and their corresponding webpages, and says its feature table contains measurements extracted from both URL strings and webpage source code. The published record says most analyzed URLs were recent at construction time.

The associated paper describes the dataset as part of a URL and webpage feature pipeline. The public UCI record and paper do not provide a per-row timestamp or enough detail to independently audit every source label in this local snapshot. The dataset is a research benchmark, not a current threat feed or a representative sample of all URLs.

## Local source files

The archive and extracted CSV are stored under `data/raw/`, which is ignored by Git. Do not commit them unless the project makes a separate, explicit decision to redistribute the data. UCI's CC BY 4.0 record permits sharing/adaptation with attribution, but keeping the 54 MB raw file out of the repository avoids accidental distribution and keeps the code checkout small.

UCI download URL: <https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip>

SHA-256 at retrieval:

- `PhiUSIIL_Phishing_URL_Dataset.csv`: `A236549CD369CD80BD478FF8E1779CBF44C58D5C3F79F7A51A1ADBED7D06D1C6`
- `phiusiil-uci-967.zip`: `0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A`

## Processing and limits

Training reads only `URL` and `label`. It ignores all supplied precomputed columns, including webpage-derived fields, and computes the documented features in `backend/src/features.py` from URL text. It does not fetch URLs or execute content. The training pipeline records invalid URL and label exclusions, exact and normalized duplicate counts, conflicting duplicate labels, mixed-label registrable domains, retained class counts, and split class counts in its ignored evaluation output.

Before splitting, invalid source labels and invalid HTTP(S) URLs are counted and excluded; exact duplicate `(URL, label)` rows are removed. URL normalization is intentionally limited to lowercasing scheme and hostname, IDNA hostname conversion, removing the default HTTP(S) port, and representing an empty path as `/`; path, query, and fragment remain unchanged. `GroupShuffleSplit` then groups by registrable domain using the bundled Public Suffix List snapshot. For each partition, eight fixed-seed grouped shuffles are compared using only split size and phishing-class prevalence; the closest is selected, with no model score involved. This yields approximate 60/20/20 train/validation/test portions and prevents a registrable domain from crossing partitions. The final test split is held out from fitting and algorithm selection. A domain appearing with both labels is recorded and stays in one partition. If the same normalized URL has conflicting labels, every record for that URL is excluded and the conflict/group counts are reported in the audit; no source label is chosen by ordering. Logistic Regression and a fixed-configuration Random Forest are compared using validation only, with the selection policy and separate final test result recorded in the report.

Even with duplicate and registrable-domain grouping, this is a random split from one dataset snapshot. It does not establish performance on future URLs, unseen sources, changed label policies, or live websites. The dataset documentation does not provide enough per-record provenance to audit source decisions independently; collection/source artifacts may affect results. Classification from URL text alone cannot establish that a current destination is safe or malicious.
