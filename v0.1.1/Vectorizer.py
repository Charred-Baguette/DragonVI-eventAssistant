from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from collections import defaultdict

# ── optional heavy deps ───────────────────────────────────────────
try:
    from sentence_transformers import SentenceTransformer
    ST_AVAILABLE = True
except ImportError:
    ST_AVAILABLE = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer as _TfidfVec
    from sklearn.decomposition import TruncatedSVD
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

_BACKEND_PRIORITY = ['sentence_transformers', 'tfidf', 'hash']


class Vectorizer:
    """
    Embeds log records and maintains four in-memory dataset variants:

        original    – plain records (no embedding); the source-of-truth
        vectorized  – records with ``embedding: [float, ...]`` added
        pattern     – records with embedding + cluster/burst annotations
                      (populated by PatternControl.run())
        sample      – representative subset, embedding stripped
                      (populated by PatternControl.run())

    All four are kept under ``self.store[dataset_name]`` and can be
    saved to / loaded from disk.

    Embedding backends (tried in order):
        1. sentence-transformers  all-MiniLM-L6-v2  (384-dim, best quality)
        2. sklearn TF-IDF + TruncatedSVD            (64-dim, no model download)
        3. hash embedding                            (128-dim, zero deps)
    """

    def __init__(self, logger, model_name='all-MiniLM-L6-v2'):
        self.logger     = logger
        self.model_name = model_name
        self.data_dir   = Path('event_logs')
        self.data_dir.mkdir(exist_ok=True)

        # store[dataset_name] = {
        #   'original': list[dict],
        #   'vectorized': list[dict],
        #   'pattern': list[dict],   # added by PatternControl
        #   'sample': list[dict],    # added by PatternControl
        #   'matrix': np.ndarray,    # (N, D) — parallel to original
        # }
        self.store = {}

        self._backend  = None   # set on first embed call
        self._st_model = None   # sentence-transformers model
        self._tfidf_pipe = None # (TfidfVec, SVD) tuple — fit per dataset

    # ─────────────────────────────────────────────────────────────
    #  Logger helper
    # ─────────────────────────────────────────────────────────────

    def _log(self, msg, level='INFO', save=False):
        self.logger.log(f'[Vectorizer] {msg}', level, save=save, loud=True)

    # ─────────────────────────────────────────────────────────────
    #  Backend init
    # ─────────────────────────────────────────────────────────────

    def _init_backend(self):
        if self._backend:
            return
        if ST_AVAILABLE:
            self._log(f'Loading sentence-transformers model: {self.model_name}')
            try:
                self._st_model = SentenceTransformer(self.model_name)
                self._backend  = 'sentence_transformers'
                self._log('Backend: sentence-transformers (384-dim)')
                return
            except Exception as e:
                self._log(f'sentence-transformers load failed ({e}), falling back.', 'WARNING')
        if SKLEARN_AVAILABLE:
            self._backend = 'tfidf'
            self._log('Backend: TF-IDF + TruncatedSVD (64-dim)')
            return
        self._backend = 'hash'
        self._log('Backend: hash embedding (128-dim) — install sentence-transformers for best results.', 'WARNING')

    # ─────────────────────────────────────────────────────────────
    #  Embedding
    # ─────────────────────────────────────────────────────────────

    def _embed(self, texts):
        """Return a list-of-lists of floats, shape (N, D)."""
        self._init_backend()
        if self._backend == 'sentence_transformers':
            result = self._st_model.encode(texts, show_progress_bar=False)
            # encode() may return a numpy array or a list depending on version
            if hasattr(result, 'tolist'):
                return result.tolist()
            return [v.tolist() if hasattr(v, 'tolist') else list(v) for v in result]
        if self._backend == 'tfidf':
            return self._embed_tfidf(texts)
        return self._embed_hash(texts)

    def _embed_tfidf(self, texts):
        tfidf = _TfidfVec(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)
        svd   = TruncatedSVD(n_components=min(64, len(texts) - 1 if len(texts) > 1 else 1),
                             random_state=42)
        X = tfidf.fit_transform(texts)
        X = svd.fit_transform(X).astype(float)
        norms = np.linalg.norm(X, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        X = X / norms
        self._tfidf_pipe = (tfidf, svd)
        return X.tolist()

    @staticmethod
    def _embed_hash(texts, dim=128):
        import hashlib
        results = []
        for text in texts:
            vec = [0.0] * dim
            for word in text.lower().split():
                h = int(hashlib.md5(word.encode()).hexdigest(), 16)
                idx  = h % dim
                sign = 1.0 if (h % 2) == 0 else -1.0
                vec[idx] += sign
            norm = math.sqrt(sum(x * x for x in vec)) or 1.0
            results.append([x / norm for x in vec])
        return results

    # ─────────────────────────────────────────────────────────────
    #  Vectorize — main public entry
    # ─────────────────────────────────────────────────────────────

    def vectorize(self, records, dataset_name='default'):
        """
        Embed every record's ``text`` field and store all variants.

        Parameters
        ----------
        records      : list of log dicts (must have a ``text`` field).
        dataset_name : key under ``self.store``.

        Returns
        -------
        list of record dicts with an added ``embedding`` field.
        """
        if not records:
            self._log(f'No records to vectorize for "{dataset_name}".', 'WARNING')
            return []

        self._log(f'Vectorizing {len(records)} records for dataset "{dataset_name}"...')

        texts = [r.get('text') or r.get('message', '') for r in records]
        embeddings = self._embed(texts)

        # original: deep copy without embedding
        original = [copy.deepcopy(r) for r in records]
        for rec in original:
            rec.pop('embedding', None)

        # vectorized: deep copy with embedding
        vectorized = []
        for rec, emb in zip(original, embeddings):
            v = copy.deepcopy(rec)
            v['embedding'] = emb
            vectorized.append(v)

        # matrix: np.ndarray if numpy available
        if NP_AVAILABLE:
            matrix = np.array(embeddings, dtype=float)
        else:
            matrix = embeddings  # plain list-of-lists

        # initialise store entry (pattern/sample filled later by PatternControl)
        self.store[dataset_name] = {
            'original':   original,
            'vectorized': vectorized,
            'pattern':    [],
            'sample':     [],
            'matrix':     matrix,
        }

        self._log(
            f'Done. Embedding dim={len(embeddings[0])}, '
            f'backend={self._backend}, dataset="{dataset_name}"'
        )
        return vectorized

    # ─────────────────────────────────────────────────────────────
    #  Accessors
    # ─────────────────────────────────────────────────────────────

    def get_matrix(self, dataset_name):
        """Return the (N, D) embedding matrix for a dataset."""
        entry = self.store.get(dataset_name)
        if entry is None:
            raise KeyError(f'Dataset "{dataset_name}" not found. Call vectorize() first.')
        return entry['matrix']

    def get(self, dataset_name, variant='original'):
        """Return one of: original | vectorized | pattern | sample."""
        return self.store.get(dataset_name, {}).get(variant, [])

    def list_datasets(self):
        return list(self.store.keys())

    # ─────────────────────────────────────────────────────────────
    #  Level / field split datasets
    # ─────────────────────────────────────────────────────────────

    def split_by_level(self, dataset_name, levels=None):
        """
        Create sub-datasets split by severity level.

        Each sub-dataset is vectorized independently and stored as
        ``"{dataset_name}__{level.lower()}"`` (e.g. ``"demo__error"``).

        Parameters
        ----------
        dataset_name : source dataset (must already be vectorized).
        levels       : list of level strings to split on.
                       Defaults to ERROR, WARNING, INFO, AUDIT_FAILURE, AUDIT_SUCCESS.

        Returns
        -------
        dict of {level: dataset_name} for all non-empty splits.
        """
        if levels is None:
            levels = ['ERROR', 'CRITICAL', 'EMERGENCY', 'ALERT',
                      'WARNING', 'NOTICE',
                      'INFO', 'AUDIT_SUCCESS', 'AUDIT_FAILURE', 'DEBUG']

        original = self.get(dataset_name, 'original')
        if not original:
            self._log(f'No original records for "{dataset_name}".', 'WARNING')
            return {}

        created = {}
        for level in levels:
            subset = [r for r in original if r.get('level', '').upper() == level]
            if not subset:
                continue
            sub_name = f'{dataset_name}__{level.lower()}'
            self._log(f'Splitting: {len(subset)} {level} records -> "{sub_name}"')
            self.vectorize(subset, sub_name)
            created[level] = sub_name

        self._log(
            f'Level split complete: {len(created)} sub-datasets from "{dataset_name}". '
            f'Levels: {list(created.keys())}'
        )
        return created

    def split_by_field(self, dataset_name, field='os_source'):
        """
        Create sub-datasets split by any record field (e.g. os_source, source).

        Sub-datasets stored as ``"{dataset_name}__{field_value}"``.

        Returns dict of {field_value: sub_dataset_name}.
        """
        original = self.get(dataset_name, 'original')
        if not original:
            self._log(f'No original records for "{dataset_name}".', 'WARNING')
            return {}

        groups = defaultdict(list)
        for rec in original:
            val = str(rec.get(field, 'unknown')).lower().replace(' ', '_')
            groups[val].append(rec)

        created = {}
        for val, subset in groups.items():
            sub_name = f'{dataset_name}__{val}'
            self._log(f'Splitting by {field}={val}: {len(subset)} records -> "{sub_name}"')
            self.vectorize(subset, sub_name)
            created[val] = sub_name

        self._log(
            f'Field split on "{field}" complete: {len(created)} sub-datasets '
            f'from "{dataset_name}".'
        )
        return created

    # ─────────────────────────────────────────────────────────────
    #  Saving
    # ─────────────────────────────────────────────────────────────

    def save_all(self, dataset_name, prefix=None):
        """
        Save all four dataset variants to disk.

        Files written:
          <prefix>.jsonl              – original  (no embedding)
          <prefix>.vec.jsonl          – vectorized (with embedding)
          <prefix>.pattern.jsonl      – pattern-annotated (with embedding)
          <prefix>.sample.jsonl       – sample (no embedding)

        Returns dict of {variant: Path}.
        """
        entry = self.store.get(dataset_name)
        if not entry:
            self._log(f'Dataset "{dataset_name}" not found.', 'WARNING')
            return {}

        prefix = prefix or dataset_name
        paths  = {}

        variants = [
            ('original',   prefix + '.jsonl',         False),
            ('vectorized', prefix + '.vec.jsonl',      True),
            ('pattern',    prefix + '.pattern.jsonl',  True),
            ('sample',     prefix + '.sample.jsonl',   False),
        ]
        for variant, fname, include_emb in variants:
            records = entry.get(variant, [])
            if not records:
                self._log(f'  Skipping empty variant "{variant}".', 'DEBUG')
                continue
            path = self.data_dir / fname
            self._write_jsonl(records, path, include_embedding=include_emb)
            paths[variant] = path
            self._log(f'  Saved {len(records)} records -> {path}')

        return paths

    def _write_jsonl(self, records, path, include_embedding=True):
        with open(path, 'w', encoding='utf-8') as fh:
            for rec in records:
                if include_embedding:
                    fh.write(json.dumps(rec, ensure_ascii=False) + '\n')
                else:
                    slim = {k: v for k, v in rec.items() if k != 'embedding'}
                    fh.write(json.dumps(slim, ensure_ascii=False) + '\n')

    # ─────────────────────────────────────────────────────────────
    #  Loading
    # ─────────────────────────────────────────────────────────────

    def load_vectorized(self, path, dataset_name=None):
        """
        Load a .vec.jsonl file back into memory, reconstructing the matrix.

        Returns list of records (with embedding field).
        """
        path = Path(path)
        if dataset_name is None:
            stem = path.stem
            for suffix in ('.vec', '.pattern', '.sample'):
                stem = stem.replace(suffix, '')
            dataset_name = stem

        records = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except FileNotFoundError:
            self._log(f'File not found: {path}', 'ERROR')
            return []

        # rebuild matrix from embedding fields
        embeddings = [r.get('embedding') for r in records if r.get('embedding')]
        if NP_AVAILABLE and embeddings:
            matrix = np.array(embeddings, dtype=float)
        else:
            matrix = embeddings

        # merge into store (don't overwrite other variants)
        if dataset_name not in self.store:
            self.store[dataset_name] = {
                'original': [], 'vectorized': [], 'pattern': [], 'sample': [], 'matrix': None
            }

        variant = 'vectorized'
        if '.pattern' in path.name:
            variant = 'pattern'
        elif '.sample' in path.name:
            variant = 'sample'

        self.store[dataset_name][variant] = records
        self.store[dataset_name]['matrix'] = matrix

        self._log(
            f'Loaded {len(records)} records from {path} '
            f'-> store["{dataset_name}"]["{variant}"]'
        )
        return records
