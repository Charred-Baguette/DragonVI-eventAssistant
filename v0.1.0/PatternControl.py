from __future__ import annotations

import copy
import math
from collections import Counter, defaultdict
from datetime import datetime

try:
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score
    import numpy as np
    SKLEARN_AVAILABLE = True
    NP_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    try:
        import numpy as np
        NP_AVAILABLE = True
    except ImportError:
        NP_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────
#  Stopwords for cluster label extraction
# ─────────────────────────────────────────────────────────────────

_STOPWORDS = {
    'the', 'a', 'an', 'is', 'it', 'to', 'of', 'in', 'for', 'on', 'at',
    'by', 'or', 'and', 'not', 'no', 'has', 'was', 'are', 'be', 'been',
    'with', 'from', 'that', 'this', 'have', 'had', 'as', 'but', 'its',
    'log', 'source', 'host', 'pid', 'event', 'id', 'facility', 'info',
    'error', 'warning', 'debug', 'notice', 'unknown',
}


class PatternControl:
    """
    Detects patterns in vectorized log datasets and produces two output
    datasets that get written back into the Vectorizer store:

        pattern  – full records annotated with:
                     cluster_id, pattern_label, pattern_confidence,
                     is_burst, burst_window
        sample   – one representative record per cluster (embedding stripped)

    Also detects:
        • Semantic clusters  — KMeans on embeddings (or label-grouping fallback)
        • Burst patterns     — frequency spikes within a sliding time window
        • Escalation chains  — INFO → WARNING → ERROR from the same source
        • Repeat offenders   — sources/IPs generating many errors
    """

    def __init__(self, logger):
        self.logger   = logger
        self.patterns = []   # list of pattern summary dicts from last run

    def _log(self, msg, level='INFO', save=False):
        self.logger.log(f'[PatternControl] {msg}', level, save=save, loud=True)

    # ─────────────────────────────────────────────────────────────
    #  Main pipeline
    # ─────────────────────────────────────────────────────────────

    def run(self, vectorizer, dataset_name, n_clusters=None, n_per_cluster=2,
            burst_window_secs=60, burst_threshold=3):
        """
        Full pattern-detection pipeline.  Adds ``pattern`` and ``sample``
        variants into ``vectorizer.store[dataset_name]``.

        Parameters
        ----------
        vectorizer       : Vectorizer instance with dataset already vectorized.
        dataset_name     : key in vectorizer.store.
        n_clusters       : KMeans k.  None = auto (sqrt heuristic).
        n_per_cluster    : records to include in the sample per cluster.
        burst_window_secs: sliding window in seconds for burst detection.
        burst_threshold  : minimum events in window to flag a burst.

        Returns
        -------
        (pattern_records, sample_records, patterns_summary)
        """
        entry = vectorizer.store.get(dataset_name)
        if not entry:
            self._log(f'Dataset "{dataset_name}" not found in Vectorizer.', 'ERROR')
            return [], [], []

        vectorized = entry.get('vectorized', [])
        matrix     = entry.get('matrix')

        if not vectorized:
            self._log(f'No vectorized records for "{dataset_name}".', 'WARNING')
            return [], [], []

        self._log(f'Running pattern detection on {len(vectorized)} records...')

        # ── 1. Cluster ───────────────────────────────────────────
        k          = n_clusters or self._auto_k(len(vectorized))
        clusters   = self._cluster(matrix, vectorized, k)
        centroids  = clusters['centroids']    # list of centroid vectors
        labels     = clusters['labels']       # list[int] length N
        self._log(f'Clustered into {k} groups.')

        # ── 2. Build cluster metadata ────────────────────────────
        cluster_records = defaultdict(list)
        for rec, cid in zip(vectorized, labels):
            cluster_records[cid].append(rec)

        cluster_meta = {}
        for cid, recs in cluster_records.items():
            cluster_meta[cid] = {
                'label':      self._label_cluster(cid, recs),
                'count':      len(recs),
                'confidence': self._cluster_confidence(matrix, labels, cid, centroids),
            }

        # ── 3. Burst detection ───────────────────────────────────
        burst_ids = self._detect_bursts(vectorized, burst_window_secs, burst_threshold)

        # ── 4. Escalation chains ─────────────────────────────────
        escalation_sources = self._detect_escalations(vectorized)

        # ── 5. Repeat offenders ──────────────────────────────────
        repeat_sources = self._detect_repeat_offenders(vectorized)

        # ── 6. Annotate pattern records ──────────────────────────
        pattern_records = []
        for rec, cid in zip(vectorized, labels):
            p = copy.deepcopy(rec)
            meta = cluster_meta[cid]
            p['cluster_id']          = int(cid)
            p['pattern_label']       = meta['label']
            p['pattern_confidence']  = round(meta['confidence'], 4)
            p['is_burst']            = rec.get('id', '') in burst_ids
            p['is_escalation_source'] = rec.get('source', '') in escalation_sources
            p['is_repeat_offender']  = rec.get('source', '') in repeat_sources
            pattern_records.append(p)

        # ── 7. Build sample ──────────────────────────────────────
        sample_records = self._make_sample(
            pattern_records, labels, matrix, centroids, n_per_cluster
        )

        # ── 8. Collect pattern summaries ─────────────────────────
        self.patterns = self._summarize(
            cluster_meta, burst_ids, escalation_sources, repeat_sources, vectorized
        )

        # ── 9. Write back into vectorizer store ──────────────────
        entry['pattern'] = pattern_records
        entry['sample']  = sample_records

        self._log(
            f'Pattern detection complete: {len(pattern_records)} annotated, '
            f'{len(sample_records)} in sample, {len(self.patterns)} patterns.'
        )
        return pattern_records, sample_records, self.patterns

    # ─────────────────────────────────────────────────────────────
    #  Clustering
    # ─────────────────────────────────────────────────────────────

    def _auto_k(self, n):
        """Heuristic: k = max(2, min(10, sqrt(n/2)))."""
        return max(2, min(10, int(math.sqrt(n / 2))))

    def _cluster(self, matrix, records, k):
        """
        KMeans on embeddings when sklearn is available;
        falls back to grouping by (level, source) otherwise.
        """
        n = len(records)
        k = min(k, n)

        if SKLEARN_AVAILABLE and NP_AVAILABLE and matrix is not None:
            arr = matrix if hasattr(matrix, 'shape') else np.array(matrix, dtype=float)
            km = KMeans(n_clusters=k, random_state=42, n_init=10)
            labels    = km.fit_predict(arr).tolist()
            centroids = km.cluster_centers_.tolist()
            return {'labels': labels, 'centroids': centroids}

        # Fallback: group by (level, source) combo
        key_to_id = {}
        labels    = []
        for rec in records:
            key = (rec.get('level', ''), rec.get('source', ''))
            if key not in key_to_id:
                key_to_id[key] = len(key_to_id)
            labels.append(key_to_id[key])

        # Fake centroids: None (handled gracefully downstream)
        return {'labels': labels, 'centroids': [None] * len(key_to_id)}

    def _cluster_confidence(self, matrix, labels, target_cid, centroids):
        """
        Mean cosine similarity of cluster members to their centroid.
        Returns 1.0 if numpy/centroid not available.
        """
        centroid = centroids[target_cid] if target_cid < len(centroids) else None
        if centroid is None or not NP_AVAILABLE:
            return 1.0
        centroid = np.array(centroid)
        arr = matrix if hasattr(matrix, 'shape') else np.array(matrix, dtype=float)
        member_idx = [i for i, l in enumerate(labels) if l == target_cid]
        if not member_idx:
            return 0.0
        members = arr[member_idx]
        norm_c = np.linalg.norm(centroid)
        if norm_c == 0:
            return 1.0
        sims = members.dot(centroid) / (
            np.linalg.norm(members, axis=1) * norm_c + 1e-9
        )
        return float(np.mean(sims))

    # ─────────────────────────────────────────────────────────────
    #  Cluster labelling
    # ─────────────────────────────────────────────────────────────

    def _label_cluster(self, cid, recs):
        """Generate a human-readable label from the records in a cluster."""
        level   = Counter(r.get('level', '')   for r in recs).most_common(1)[0][0]
        source  = Counter(r.get('source', '')  for r in recs).most_common(1)[0][0]
        os_src  = Counter(r.get('os_source', '') for r in recs).most_common(1)[0][0]
        keywords = self._top_keywords(recs, n=3)
        kw_str   = ', '.join(keywords) if keywords else ''
        parts    = [f'[{level}]', source]
        if os_src:
            parts.append(f'({os_src})')
        if kw_str:
            parts.append(f'| {kw_str}')
        return ' '.join(parts)

    @staticmethod
    def _top_keywords(recs, n=3):
        """Extract top non-stopword tokens from messages in a cluster."""
        freq = Counter()
        for rec in recs:
            for tok in rec.get('message', '').lower().split():
                tok = tok.strip('[]():,;.')
                if tok and tok not in _STOPWORDS and len(tok) > 2:
                    freq[tok] += 1
        return [w for w, _ in freq.most_common(n)]

    # ─────────────────────────────────────────────────────────────
    #  Sample extraction
    # ─────────────────────────────────────────────────────────────

    def _make_sample(self, pattern_records, labels, matrix, centroids, n_per_cluster):
        """
        Select the N records per cluster closest to their centroid.
        Strips the ``embedding`` field so samples are clean for LLM prompting.
        """
        cluster_groups = defaultdict(list)   # cid -> list of (distance, rec)
        arr = None
        if NP_AVAILABLE and matrix is not None:
            arr = matrix if hasattr(matrix, 'shape') else np.array(matrix, dtype=float)

        for idx, (rec, cid) in enumerate(zip(pattern_records, labels)):
            centroid = centroids[cid] if cid < len(centroids) else None
            if arr is not None and centroid is not None:
                c = np.array(centroid)
                v = arr[idx]
                nc = np.linalg.norm(c)
                nv = np.linalg.norm(v)
                if nc > 0 and nv > 0:
                    dist = 1.0 - float(v.dot(c) / (nv * nc))
                else:
                    dist = 0.0
            else:
                dist = 0.0
            cluster_groups[cid].append((dist, rec))

        sample = []
        for cid in sorted(cluster_groups):
            members = sorted(cluster_groups[cid], key=lambda x: x[0])
            for _, rec in members[:n_per_cluster]:
                s = {k: v for k, v in rec.items() if k != 'embedding'}
                sample.append(s)

        return sample

    # ─────────────────────────────────────────────────────────────
    #  Burst detection
    # ─────────────────────────────────────────────────────────────

    def _detect_bursts(self, records, window_secs, threshold):
        """
        Returns a set of record IDs that belong to a burst window
        (≥ threshold events from the same source within window_secs).
        """
        burst_ids = set()

        # Group by source, sort by timestamp
        by_source = defaultdict(list)
        for rec in records:
            ts = self._parse_ts(rec.get('timestamp', ''))
            if ts is not None:
                by_source[rec.get('source', '__unknown__')].append((ts, rec.get('id', '')))

        for source, events in by_source.items():
            events.sort(key=lambda x: x[0])
            for i in range(len(events)):
                t0 = events[i][0]
                window = [e for e in events[i:] if (e[0] - t0) <= window_secs]
                if len(window) >= threshold:
                    for _, eid in window:
                        burst_ids.add(eid)

        self._log(f'Burst detection: {len(burst_ids)} records in burst windows.')
        return burst_ids

    @staticmethod
    def _parse_ts(ts_str):
        """Parse ISO-8601 timestamp to seconds since epoch. Returns None on failure."""
        if not ts_str:
            return None
        for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
            try:
                dt = datetime.strptime(ts_str[:26], fmt)
                return (dt - datetime(1970, 1, 1)).total_seconds()
            except ValueError:
                continue
        return None

    # ─────────────────────────────────────────────────────────────
    #  Escalation detection
    # ─────────────────────────────────────────────────────────────

    def _detect_escalations(self, records):
        """
        Find sources that produced INFO → WARNING → ERROR in sequence.
        Returns set of source names.
        """
        _SEVERITY = {'DEBUG': 0, 'INFO': 1, 'NOTICE': 2, 'WARNING': 3,
                     'ERROR': 4, 'CRITICAL': 5, 'EMERGENCY': 6}
        by_source = defaultdict(list)
        for rec in records:
            ts = self._parse_ts(rec.get('timestamp', ''))
            sev = _SEVERITY.get(rec.get('level', ''), -1)
            if ts is not None:
                by_source[rec.get('source', '__unknown__')].append((ts, sev))

        escalating = set()
        for source, events in by_source.items():
            events.sort(key=lambda x: x[0])
            sevs = [s for _, s in events]
            # Look for any upward step ≥ 2 levels (e.g. INFO→ERROR)
            for i in range(len(sevs) - 1):
                if sevs[i + 1] - sevs[i] >= 2:
                    escalating.add(source)
                    break

        self._log(f'Escalation detection: {len(escalating)} escalating sources.')
        return escalating

    # ─────────────────────────────────────────────────────────────
    #  Repeat offender detection
    # ─────────────────────────────────────────────────────────────

    def _detect_repeat_offenders(self, records, threshold=3):
        """
        Return set of source names that produced ≥ threshold ERROR records.
        """
        error_counts = Counter(
            r.get('source', '')
            for r in records
            if r.get('level', '') in ('ERROR', 'CRITICAL', 'AUDIT_FAILURE', 'EMERGENCY', 'ALERT')
        )
        offenders = {src for src, cnt in error_counts.items() if cnt >= threshold}
        self._log(f'Repeat offenders (≥{threshold} errors): {offenders or "none"}.')
        return offenders

    # ─────────────────────────────────────────────────────────────
    #  Summarise
    # ─────────────────────────────────────────────────────────────

    def _summarize(self, cluster_meta, burst_ids, escalation_sources,
                   repeat_sources, records):
        """Build a list of human-readable pattern summary dicts."""
        patterns = []

        # Cluster patterns
        for cid, meta in cluster_meta.items():
            patterns.append({
                'type':       'cluster',
                'id':          f'cluster_{cid}',
                'label':       meta['label'],
                'count':       meta['count'],
                'confidence':  meta['confidence'],
                'description': (
                    f"Semantic cluster #{cid}: {meta['count']} similar records. "
                    f"Label: {meta['label']}"
                ),
            })

        # Burst pattern
        if burst_ids:
            patterns.append({
                'type':        'burst',
                'id':          'burst_0',
                'label':       f'Event burst ({len(burst_ids)} records)',
                'count':       len(burst_ids),
                'confidence':  1.0,
                'description': (
                    f'{len(burst_ids)} records were part of rapid-fire bursts '
                    f'(≥3 events from same source within 60 s).'
                ),
            })

        # Escalation
        for src in escalation_sources:
            patterns.append({
                'type':        'escalation',
                'id':          f'escalation_{src}',
                'label':       f'Severity escalation: {src}',
                'count':       sum(1 for r in records if r.get('source') == src),
                'confidence':  1.0,
                'description': (
                    f'Source "{src}" showed a severity escalation '
                    f'(jumped ≥2 levels, e.g. INFO → ERROR).'
                ),
            })

        # Repeat offenders
        for src in repeat_sources:
            cnt = sum(
                1 for r in records
                if r.get('source') == src
                and r.get('level', '') in ('ERROR', 'CRITICAL', 'AUDIT_FAILURE')
            )
            patterns.append({
                'type':        'repeat_offender',
                'id':          f'repeat_{src}',
                'label':       f'Repeat offender: {src}',
                'count':       cnt,
                'confidence':  1.0,
                'description': f'Source "{src}" generated {cnt} error-level events.',
            })

        return patterns

    # ─────────────────────────────────────────────────────────────
    #  Display helpers
    # ─────────────────────────────────────────────────────────────

    def display_patterns(self, console=None):
        """Print a summary of detected patterns using a console or plain print."""
        lines = [
            '',
            '=' * 70,
            f'  Pattern Detection Results  ({len(self.patterns)} patterns)',
            '=' * 70,
        ]
        for p in self.patterns:
            lines.append(
                f"  [{p['type'].upper():<16}] {p['label']:<40} "
                f"count={p['count']} conf={p['confidence']:.2f}"
            )
            lines.append(f"    {p['description']}")
        lines.append('=' * 70)

        for line in lines:
            if console:
                console.log(line, 'INFO', loud=True)
            else:
                print(line)
