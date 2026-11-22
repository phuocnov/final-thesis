"""
Two-view heterogeneous GAT on data captured from YOUR OWN Online Boutique + Istio
cluster: an L3/4 view (captured hosts, Argus flow features) + an L7 view (the observed
microservice dependency graph). No external dataset -- both views come from a session
produced by the ai-model pipeline (05_run_attacks.sh -> build_dataset.py +
04_pcap_to_flows.sh).

Task: binary flow classification (attack vs normal; --task multiclass for per-attack).

Graph schema
  node types : flow, host, service
  L3/4 view  : flow -> host (src & dst role)  ->  host -> flow
  L7 view    : flow -> service (by dst port) -> service<->service (observed deps) -> service -> flow
  Each view yields a flow embedding; a semantic-attention layer (HAN-style) fuses them.

Inputs (from a session directory built by the pipeline)
  --netflows dataset/netflows.csv            # L3/4: Argus flow features + label (04_pcap_to_flows.sh)
  --graphml  dataset/observed_services.graphml  # L7: observed service-call graph (build_dataset.py)

Usage
  pip install -r requirements-model.txt        # into a venv (see README); torch needs a supported Python
  python two_view_hetero_gat.py --demo         # smoke test on random data, no files needed
  python two_view_hetero_gat.py --netflows dataset/netflows.csv --graphml dataset/observed_services.graphml
  python two_view_hetero_gat.py ... --views none|l34|l7|both    # none = flow-features-only MLP baseline
  python two_view_hetero_gat.py ... --mapping port|shuffled|random   # how flows link to service nodes
  python two_view_hetero_gat.py ... --sweep --seeds 0,1,2,3,4   # full comparison table
  python two_view_hetero_gat.py ... --drop_strong              # drop sttl/dttl (harder task)
  python two_view_hetero_gat.py ... --task multiclass          # per-attack-class, macro-F1 + accuracy
"""
import argparse, glob, os
import numpy as np
import pandas as pd
import networkx as nx
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv
from sklearn.metrics import f1_score, roc_auc_score


# ----------------------------------------------------------------------------- data
def load_service_graph(graphml):
    g = nx.read_graphml(graphml)
    nodes = list(g.nodes())
    idx = {n: i for i, n in enumerate(nodes)}
    e = np.array([(idx[u], idx[v]) for u, v in g.edges()], dtype=np.int64).T
    if e.size == 0:
        e = np.zeros((2, 0), dtype=np.int64)
    return len(nodes), e


MAPPINGS = ('port', 'shuffled', 'random')


def l7_keys(dsport, top_ports):
    """L7 category per captured flow: 'p<port>' if the dst port is in `top_ports`, else 'other'.
    Captured flows carry no service label, so the destination port is the L7 proxy. `top_ports`
    is fixed on the training session so val/test categorise ports the same way."""
    dsport = pd.Series(dsport).astype(str)
    return np.where(dsport.isin(set(top_ports)), 'p' + dsport, 'other')


def fs_edges(keys, src_h, dst_h, n_hosts, svc_edges, n_svc, mapping, seed, cat_order):
    """flow -> service edges (numpy, [2, E]). `cat_order` is the TRAIN-session ranking of L7
    categories, so a category maps to the same service node in every split.
    port     : category rank -> service ranked by degree in the dependency graph (hubs get busy ports).
    shuffled : category rank -> a seeded random permutation of service nodes (control: breaks topology
               alignment but keeps 'which flows share a service').
    random   : every host gets a random service; a flow links to its src and dst host's service.
    """
    assert mapping in MAPPINGS, mapping
    n = len(keys)
    fid = np.arange(n)
    rng = np.random.default_rng(seed)
    if mapping == 'random':
        host2svc = rng.integers(0, n_svc, n_hosts)
        return np.stack([np.concatenate([fid, fid]), np.concatenate([host2svc[src_h], host2svc[dst_h]])])
    rankmap = {k: i for i, k in enumerate(cat_order)}
    other = rankmap.get('other', len(cat_order))                     # categories unseen in train -> 'other'
    rank = np.array([rankmap.get(k, other) for k in keys], dtype=np.int64)
    if mapping == 'port':
        deg = np.bincount(svc_edges.ravel(), minlength=n_svc) if svc_edges.size else np.zeros(n_svc, int)
        svc_order = np.argsort(-deg, kind='stable')
    else:
        svc_order = rng.permutation(n_svc)
    return np.stack([fid, svc_order[rank % n_svc]])                  # >n_svc categories share nodes (modulo)


def build_tensors(fl, svc, mapping, seed, cat_order):
    """Assemble all edge sets for ONE split's flows. fl: flow dict, svc: (n_svc, svc_edges).
    Each split is its own graph (inductive) so test flows never message-pass during training."""
    n_svc, svc_edges = svc
    n = len(fl['y'])
    fid = np.arange(n)
    ei_fh = np.stack([np.concatenate([fid, fid]), np.concatenate([fl['src_h'], fl['dst_h']])])
    ei_fs = fs_edges(fl['keys'], fl['src_h'], fl['dst_h'], fl['n_hosts'], svc_edges, n_svc, mapping, seed, cat_order)
    ei_ss = np.concatenate([svc_edges, svc_edges[::-1]], axis=1)   # make dependency edges bidirectional
    t = lambda a: torch.as_tensor(np.array(a, dtype=np.int64))
    return dict(
        x=torch.as_tensor(np.array(fl['x'], dtype=np.float32)), y=torch.as_tensor(np.array(fl['y'], dtype=np.int64)),
        ei_fh=t(ei_fh), ei_hf=t(ei_fh[::-1]), ei_fs=t(ei_fs), ei_sf=t(ei_fs[::-1]),
        ei_ss=t(ei_ss), n_hosts=fl['n_hosts'], n_svc=n_svc)


# Argus flow columns (from 04_pcap_to_flows.sh) used as L3/4 numeric features -- the
# captured, UNSW-comparable counters. Columns Argus didn't emit are tolerated (filled 0).
CAP_NUM = ['dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'swin', 'dwin', 'spkts', 'dpkts',
           'sload', 'dload', 'sloss', 'dloss', 'smeansz', 'dmeansz', 'sjit', 'djit',
           'tcprtt', 'synack', 'ackdat']
CAP_CAT = ['proto', 'state']
CAP_STRONG = {'sttl', 'dttl'}   # per-flow TTLs are an easy tell; --drop_strong removes them


def _read_capture(netflows, n_flows=0):
    """Read + clean a netflows.csv: fill missing cols, sort by time, coerce numerics/labels."""
    df = pd.read_csv(netflows, low_memory=False)
    assert len(df), f'{netflows} is empty'
    for c in CAP_NUM + CAP_CAT + ['saddr', 'daddr', 'dport', 'stime', 'label']:
        if c not in df.columns:
            df[c] = 0 if c in CAP_NUM else ('-' if c in CAP_CAT + ['saddr', 'daddr'] else
                                            (0 if c in ('dport', 'stime') else 'normal'))
    df['stime'] = pd.to_numeric(df['stime'], errors='coerce').fillna(0)
    df = df.sort_values('stime').reset_index(drop=True)      # temporal order
    if n_flows:
        df = df.head(n_flows).reset_index(drop=True)
    for c in CAP_NUM:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df[CAP_NUM] = df[CAP_NUM].fillna(0).clip(lower=0)
    df['label'] = df['label'].fillna('normal').astype(str).str.strip().replace({'': 'normal'})
    return df


def fit_capture(netflows, drop_strong=False, multiclass=False, n_flows=0, top_ports=8, top_cat=10):
    """Learn the featurisation from the TRAINING session ONLY (so val/test have no leakage):
    numeric log1p mean/std, the kept proto/state levels, the frequent dst ports, the L7 category
    ranking and the class list. The returned dict is reused to transform every split identically."""
    df = _read_capture(netflows, n_flows)
    num = [c for c in CAP_NUM if not (drop_strong and c in CAP_STRONG)]
    xn = np.log1p(df[num].values.astype(np.float64))
    mean, std = xn.mean(0), xn.std(0) + 1e-6
    cat_levels = {c: list(pd.Series(df[c].astype(str)).value_counts().index[:top_cat]) for c in CAP_CAT}
    top = list(pd.Series(df['dport'].astype(str)).value_counts().index[:top_ports])
    cat_order = list(pd.Series(l7_keys(df['dport'], top)).value_counts().index)   # train ranking of L7 categories
    if multiclass:
        classes = sorted(df['label'].unique().tolist())
        if 'other_attack' not in classes:
            classes = classes + ['other_attack']                 # bucket for attack classes unseen in training
    else:
        classes = ['Normal', 'Attack']
    return dict(num=num, mean=mean, std=std, cat_levels=cat_levels, top_ports=top,
                cat_order=cat_order, classes=classes, multiclass=multiclass, drop_strong=drop_strong)


def transform_capture(feat, netflows, n_flows=0, max_normal=0):
    """Apply a fitted featuriser (from fit_capture) to a session -> the flow dict the model consumes.
    The L7 side stays separate: observed_services.graphml is loaded by load_service_graph and fused in-model.
    max_normal>0 downsamples the 'normal' class to at most that many rows (keeping ALL attack flows), which
    caps the graph size for GPU memory and tames the usual ~94%-normal imbalance."""
    df = _read_capture(netflows, n_flows)
    if max_normal:
        is_norm = df['label'].str.lower() == 'normal'
        if int(is_norm.sum()) > max_normal:
            keep_norm = np.random.default_rng(0).choice(df.index[is_norm].to_numpy(),
                                                        size=max_normal, replace=False)
            keep = np.concatenate([df.index[~is_norm].to_numpy(), keep_norm])
            df = df.loc[np.sort(keep)].reset_index(drop=True)   # keep temporal order (index was stime-sorted)
    num = feat['num']
    xn = (np.log1p(df[num].values.astype(np.float64)) - feat['mean']) / feat['std']
    cols = []                                                     # proto/state dummies aligned to train levels (+ 'other')
    for c in CAP_CAT:
        s = df[c].astype(str)
        for lv in feat['cat_levels'][c]:
            cols.append((s == lv).astype(np.float32).values)
        cols.append((~s.isin(feat['cat_levels'][c])).astype(np.float32).values)
    xc = np.stack(cols, axis=1) if cols else np.zeros((len(df), 0), np.float32)
    x = np.concatenate([xn, xc], axis=1)

    lab, classes = df['label'], feat['classes']
    if feat['multiclass']:
        idx = {c: i for i, c in enumerate(classes)}
        unseen = sorted(set(lab.unique()) - set(classes))
        if unseen:
            print(f'  note: labels not in training -> other_attack: {unseen}')
        y = lab.map(lambda v: idx.get(v, idx['other_attack'])).values.astype(np.int64)
    else:
        y = (lab.str.lower() != 'normal').astype(int).values
    n = len(df)
    codes, uniq = pd.factorize(pd.concat([df['saddr'], df['daddr']], ignore_index=True))
    keys = l7_keys(df['dport'], feat['top_ports'])
    meta = df[['stime', 'saddr', 'daddr', 'dport'] + CAP_CAT].copy()
    meta['label'] = lab.values                                   # original label (e.g. syn_flood), for the report/--explain
    return dict(x=x, y=y, src_h=codes[:n], dst_h=codes[n:], n_hosts=len(uniq),
                n_cls=len(classes), classes=classes, n_num=len(num), keys=keys, meta=meta)


def build_from_capture(netflows, n_flows=0, drop_strong=False, multiclass=False):
    """Backward-compatible single-session loader: fit + transform on the same file.
    Returns (featuriser, flow dict)."""
    feat = fit_capture(netflows, drop_strong, multiclass, n_flows)
    return feat, transform_capture(feat, netflows, n_flows)


def demo_flows(n=20000, n_hosts=45, data_seed=0):
    """Random smoke-test data (no files needed), used by --demo."""
    rng = np.random.default_rng(data_seed)
    y = (rng.random(n) < 0.3).astype(int)
    x = rng.normal(size=(n, 20)) + y[:, None] * 0.4
    src_h = np.where(y == 1, rng.integers(0, 5, n), rng.integers(0, n_hosts, n))
    dst_h = rng.integers(0, n_hosts, n)
    keys = np.where(y == 1, rng.integers(0, 3, n), rng.integers(0, 6, n)).astype(str)
    meta = pd.DataFrame(dict(stime=np.arange(n), saddr=[f'h{i}' for i in src_h],
                             daddr=[f'h{i}' for i in dst_h], dport=keys,
                             label=np.where(y == 1, 'Attack', 'Normal')))
    return dict(x=x, y=y, src_h=src_h, dst_h=dst_h, n_hosts=n_hosts, keys=keys, n_cls=2,
                classes=['Normal', 'Attack'], n_num=20, meta=meta)


def demo_service_graph(n_svc=10):
    ring = np.array([[i, (i + 1) % n_svc] for i in range(n_svc)]).T
    return n_svc, ring


# ----------------------------------------------------------------------------- model
class BiGAT(nn.Module):
    """Bipartite GATv2 layer with residual on the destination side."""
    def __init__(self, d, hid, heads, drop):
        super().__init__()
        assert hid * heads == d
        self.conv = GATv2Conv((d, d), hid, heads=heads, dropout=drop, add_self_loops=False)

    def forward(self, xs, xd, ei):
        return F.elu(self.conv((xs, xd), ei)) + xd


class SemanticAttention(nn.Module):
    """Per-flow view attention: each flow gets its own weight per view (softmax over
    views), so every alert can be attributed to the L3/4 or the L7 view. The old HAN-style
    version averaged scores over all flows and learned one global weight per view.
    Returns the fused embedding [N, D] and beta [N, V]."""
    def __init__(self, d, hid=64):
        super().__init__()
        self.score = nn.Sequential(nn.Linear(d, hid), nn.Tanh(), nn.Linear(hid, 1, bias=False))

    def forward(self, zs):
        z = torch.stack(zs, 1)                              # [N, V, D]
        beta = torch.softmax(self.score(z), dim=1)          # [N, V, 1]
        return (beta * z).sum(1), beta.squeeze(-1)


class TwoViewGAT(nn.Module):
    def __init__(self, in_dim, n_svc, hid=32, heads=4, n_cls=2, drop=0.3, views=('l34', 'l7')):
        super().__init__()
        d = hid * heads
        self.views = views
        self.drop = drop
        self.flow_in = nn.Linear(in_dim, d)
        # L3/4 view: flow -> host -> flow
        self.host_token = nn.Parameter(torch.zeros(1, d))
        self.fh = BiGAT(d, hid, heads, drop)
        self.hf = BiGAT(d, hid, heads, drop)
        # L7 view: flow -> service -> (service deps) -> flow
        self.svc_emb = nn.Embedding(n_svc, d)
        self.fs = BiGAT(d, hid, heads, drop)
        self.ss = BiGAT(d, hid, heads, drop)
        self.sf = BiGAT(d, hid, heads, drop)
        self.fuse = SemanticAttention(d)
        self.cls = nn.Sequential(nn.Linear(d, d), nn.ReLU(), nn.Dropout(drop), nn.Linear(d, n_cls))

    def forward(self, g):
        x = F.dropout(F.elu(self.flow_in(g['x'])), self.drop, self.training)
        zs = []
        if 'l34' in self.views:
            h = self.fh(x, self.host_token.expand(g['n_hosts'], -1), g['ei_fh'])
            zs.append(self.hf(h, x, g['ei_hf']))
        if 'l7' in self.views:
            s = self.fs(x, self.svc_emb.weight, g['ei_fs'])
            s = self.ss(s, s, g['ei_ss'])
            zs.append(self.sf(s, x, g['ei_sf']))
        if not zs:                                   # views=() -> flow-features-only MLP baseline
            zs = [x]
        z, beta = self.fuse(zs) if len(zs) > 1 else (zs[0], None)
        return self.cls(z), beta


# ----------------------------------------------------------------------------- train
VIEWS = {'none': (), 'l34': ('l34',), 'l7': ('l7',), 'both': ('l34', 'l7')}
# (name, views, mapping) used by --sweep. mapping is irrelevant for none/l34.
SWEEP = [('mlp-baseline', 'none', 'port'), ('l34-only', 'l34', 'port'),
         ('l7-only (port)', 'l7', 'port'), ('l7-only (shuffled)', 'l7', 'shuffled'),
         ('both (port)', 'both', 'port'), ('both (shuffled)', 'both', 'shuffled'),
         ('both (random-host)', 'both', 'random')]


M2 = 'AUC'   # second metric name; set to 'Acc' in main() for --task multiclass


def run_once(splits, svc, n_cls, classes, views, mapping, seed, a, dev, cat_order,
             verbose=True, explain_dir=None):
    """Train on splits['train'], pick the epoch on splits['val'], report on splits['test'].
    Each role is (flow dict, mask-or-None); roles may share one flow dict (single-session 60/20/20)
    or be separate sessions (mask=None -> use all of it). Each distinct flow dict is its own graph,
    so test flows never message-pass during training (inductive)."""
    torch.manual_seed(seed)
    np.random.seed(seed)
    built = {}
    def graph_for(fl):
        if id(fl) not in built:
            g = build_tensors(fl, svc, mapping, seed, cat_order)
            built[id(fl)] = {k: (v.to(dev) if torch.is_tensor(v) else v) for k, v in g.items()}
        return built[id(fl)]
    def mask_for(g, m):
        return torch.ones(len(g['y']), dtype=torch.bool, device=dev) if m is None else m.to(dev)
    g_tr, m_tr = (lambda fl, m: (graph_for(fl), mask_for(graph_for(fl), m)))(*splits['train'])
    g_va, m_va = (lambda fl, m: (graph_for(fl), mask_for(graph_for(fl), m)))(*splits['val'])
    g_te, m_te = (lambda fl, m: (graph_for(fl), mask_for(graph_for(fl), m)))(*splits['test'])

    model = TwoViewGAT(g_tr['x'].shape[1], g_tr['n_svc'], a.hid, a.heads, n_cls=n_cls, views=VIEWS[views]).to(dev)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=1e-4)
    cnt = torch.bincount(g_tr['y'][m_tr], minlength=n_cls).float()
    w = cnt.sum() / (n_cls * cnt.clamp(min=1))
    if n_cls > 2:                                    # tame the huge weights of very rare classes
        w = w.sqrt().clamp(max=20)
    w = w.to(dev)

    def evaluate(g, mask, details=False):
        model.eval()
        with torch.no_grad():
            logits, beta = model(g)
        t = g['y'][mask].cpu().numpy()
        prob = logits.softmax(-1)[mask].cpu().numpy()
        pred = prob.argmax(-1)
        if n_cls == 2:                                   # binary: F1 of the attack class + AUC
            p = prob[:, 1]
            pred = (p > 0.5).astype(int)
            f1 = f1_score(t, pred, zero_division=0)
            m2 = roc_auc_score(t, p) if len(set(t)) > 1 else float('nan')
        else:                                            # multiclass: macro-F1 + accuracy
            p = prob.max(-1)
            f1 = f1_score(t, pred, average='macro', zero_division=0)
            m2 = float((pred == t).mean())
        b = None if beta is None else beta[mask]          # per-flow view attention [n, V]
        if details:
            return t, p, pred, (None if b is None else b.cpu().numpy())
        return f1, m2, (None if b is None else b.mean(0))  # mean over these flows

    best, best_state = -1, None
    for ep in range(1, a.epochs + 1):
        model.train()
        opt.zero_grad()
        logits, _ = model(g_tr)
        loss = F.cross_entropy(logits[m_tr], g_tr['y'][m_tr], weight=w)
        loss.backward()
        opt.step()
        f1v, aucv, _ = evaluate(g_va, m_va)
        if f1v > best:
            best, best_state = f1v, {k: v.clone() for k, v in model.state_dict().items()}
        if verbose and ep % 10 == 0:
            print(f'ep {ep:3d} loss {loss.item():.4f} val F1 {f1v:.4f} {M2} {aucv:.4f}')

    model.load_state_dict(best_state)
    f1t, auct, beta = evaluate(g_te, m_te)
    if verbose or explain_dir:
        t, p, pred, b = evaluate(g_te, m_te, details=True)
        te_idx = m_te.nonzero().squeeze(-1).cpu().numpy()
        meta_te = splits['test'][0]['meta'].iloc[te_idx].reset_index(drop=True)
        if verbose and n_cls == 2:
            _per_class_report(meta_te['label'].values, pred)
        if explain_dir:
            write_explain(explain_dir, meta_te, te_idx, t, p, pred, b, classes, view=views)
    return f1t, auct, (None if beta is None else beta.cpu().numpy())


def _per_class_report(labels, pred):
    """Binary test detection rate per ORIGINAL attack label (so it's visible which attacks are caught)."""
    df = pd.DataFrame({'label': labels, 'alert': pred == 1})
    print('  per-class test detection (alert rate):')
    for lab, g in df.groupby('label'):
        tag = 'false-alarm' if str(lab).lower() == 'normal' else 'detected'
        print(f'    {lab:<18} {g["alert"].mean():.3f}  ({tag}, n={len(g)})')


def write_explain(out_dir, meta, flow_idx, y_true, p, pred, beta, classes, view='both'):
    """Per-view test-set explanation: one CSV row per test flow + PNG figures.

    Always writes diagnostic plots that make sense for ANY view (per-class detection, score
    separation, score-by-label). When `beta` is given (only `--views both` produces it), also
    writes the L3/4-vs-L7 attention attribution: beta[:, 0] = L3/4 host-view weight,
    beta[:, 1] = L7 service-view weight."""
    os.makedirs(out_dir, exist_ok=True)
    normal = next((i for i, c in enumerate(classes) if str(c).lower() == 'normal'), None)
    pcol = 'p_attack' if len(classes) == 2 else 'p_pred'
    df = meta.copy()
    df.insert(0, 'flow_idx', flow_idx)
    df['y_true'] = [classes[i] for i in y_true]
    df[pcol] = p
    df['pred'] = [classes[i] for i in pred]
    df['is_alert'] = pred != normal
    df['label'] = df['label'].astype(str)          # original attack label, for grouping
    has_beta = beta is not None
    if has_beta:
        df['beta_l34'], df['beta_l7'] = beta[:, 0], beta[:, 1]
        df['dominant_view'] = np.where(df['beta_l7'] > 0.5, 'L7', 'L3/4')
    csv_path = os.path.join(out_dir, 'explanations.csv')
    df.to_csv(csv_path, index=False)

    al = df[df['is_alert']]
    print(f'\nexplain [{view}]: {len(df):,} test flows, {len(al):,} alerts -> {csv_path}')
    if has_beta and len(al):
        share = al['dominant_view'].value_counts(normalize=True)
        print('  alerts dominated by: ' + ', '.join(f'{k} {v:.1%}' for k, v in share.items()))
        print('  mean L7 weight per label (alerts):')
        for lab, v in al.groupby('label')['beta_l7'].agg(['mean', 'count']).sort_values('mean').iterrows():
            print(f'    {lab:<18} L7 {v["mean"]:.3f}  L3/4 {1 - v["mean"]:.3f}  (n={int(v["count"])})')

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print('  matplotlib not installed -> CSV only (.venv/bin/pip install matplotlib)')
        return

    C34, C7 = '#2a9d8f', '#8250df'
    C_ATK, C_NORM = '#e76f51', '#999999'
    written = []

    def _lab_ticks(labs):
        return [f'{l} (n={int((df["label"] == l).sum())})' for l in labs]

    # ---- diagnostic plots: produced for EVERY view -----------------------------------
    # D1) per-class alert rate (detection for attacks, false-alarm for normal)
    rate = df.groupby('label')['is_alert'].mean().sort_values()
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(rate) + 1.6))
    colors = [C_NORM if str(l).lower() == 'normal' else C_ATK for l in rate.index]
    ax.barh(range(len(rate)), rate.values, color=colors)
    ax.set_yticks(range(len(rate)), _lab_ticks(rate.index))
    for i, r in enumerate(rate.values):
        ax.text(min(r + .01, .98), i, f'{r:.2f}', va='center', fontsize=7)
    ax.set_xlim(0, 1)
    ax.set_xlabel('alert rate  (detection for attacks / false-alarm for normal)')
    ax.set_title(f'[{view}] per-class alert rate (test)')
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'detection_by_class.png'), dpi=150); plt.close(fig)
    written.append('detection_by_class.png')

    # D2) score separation: true-normal vs true-attack
    is_norm_true = df['label'].str.lower() == 'normal'
    fig, ax = plt.subplots(figsize=(7, 4))
    bins = np.linspace(0, 1, 41)
    ax.hist(df.loc[is_norm_true, pcol], bins=bins, alpha=.6, label=f'true normal (n={int(is_norm_true.sum())})', color=C_NORM)
    ax.hist(df.loc[~is_norm_true, pcol], bins=bins, alpha=.6, label=f'true attack (n={int((~is_norm_true).sum())})', color=C_ATK)
    ax.set_xlabel(pcol); ax.set_ylabel('flows'); ax.legend()
    ax.set_title(f'[{view}] score separation (test)')
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'score_hist.png'), dpi=150); plt.close(fig)
    written.append('score_hist.png')

    # D3) score distribution per original label
    labs = df.groupby('label')[pcol].median().sort_values().index.tolist()
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(labs) + 1.6))
    ax.boxplot([df.loc[df['label'] == l, pcol] for l in labs], orientation='horizontal', showfliers=False)
    ax.set_yticks(range(1, len(labs) + 1), _lab_ticks(labs))
    ax.set_xlim(0, 1); ax.set_xlabel(pcol)
    ax.set_title(f'[{view}] score distribution per label (test)')
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'score_by_class.png'), dpi=150); plt.close(fig)
    written.append('score_by_class.png')

    # ---- attention attribution: only when both views ran (beta is not None) ----------
    if has_beta:
        # 1) per attack label: which view drives the alerts
        if len(al):
            albs = al.groupby('label')['beta_l7'].median().sort_values().index.tolist()
            fig, ax = plt.subplots(figsize=(8, 0.45 * len(albs) + 1.6))
            ax.boxplot([al.loc[al['label'] == l, 'beta_l7'] for l in albs], orientation='horizontal', showfliers=False)
            ax.set_yticks(range(1, len(albs) + 1), [f'{l} (n={int((al["label"] == l).sum())})' for l in albs])
            ax.axvline(0.5, color='grey', ls='--', lw=1)
            ax.set_xlim(0, 1)
            ax.set_xlabel('L7 view weight  (0 = all L3/4, 1 = all L7)')
            ax.set_title('Which view drives the alerts, per true label')
            fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'view_by_class.png'), dpi=150); plt.close(fig)
            written.append('view_by_class.png')

        # 2) distribution: alerts vs non-alerts
        fig, ax = plt.subplots(figsize=(7, 4))
        bins = np.linspace(0, 1, 41)
        ax.hist(df.loc[~df['is_alert'], 'beta_l7'], bins=bins, alpha=.6, label='not alerted', color='#999999')
        if len(al):
            ax.hist(al['beta_l7'], bins=bins, alpha=.7, label='alerts', color=C7)
        ax.axvline(0.5, color='black', ls='--', lw=1)
        ax.set_xlabel('L7 view weight'); ax.set_ylabel('flows'); ax.legend()
        ax.set_title('Per-flow view attention (test set)')
        fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'view_hist.png'), dpi=150); plt.close(fig)
        written.append('view_hist.png')

        # 3) top alerts as stacked bars
        if len(al):
            top = al.sort_values(pcol, ascending=False).head(30).iloc[::-1]
            names = [f'#{r.flow_idx} {r.label} · {r.saddr}→{r.daddr}:{r.dport}' for r in top.itertuples()]
            ypos = np.arange(len(top))                   # numeric rows: duplicate names must not merge
            fig, ax = plt.subplots(figsize=(9, 0.3 * len(top) + 1.4))
            ax.barh(ypos, top['beta_l34'], color=C34, label='L3/4 host view')
            ax.barh(ypos, top['beta_l7'], left=top['beta_l34'], color=C7, label='L7 service view')
            ax.set_yticks(ypos, names)
            ax.set_xlim(0, 1); ax.axvline(0.5, color='white', lw=1)
            ax.set_xlabel('share of attention'); ax.tick_params(axis='y', labelsize=7)
            ax.legend(loc='lower right', fontsize=8)
            ax.set_title(f'Top {len(top)} alerts by {pcol}')
            fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'top_alerts.png'), dpi=150); plt.close(fig)
            written.append('top_alerts.png')

        # 4) confidence vs view
        fig, ax = plt.subplots(figsize=(7, 5))
        for lab, sub in df.groupby('label'):
            ax.scatter(sub['beta_l7'], sub[pcol], s=6, alpha=.5, label=f'{lab} (n={len(sub)})')
        ax.axvline(0.5, color='grey', ls='--', lw=1)
        ax.set_xlim(0, 1); ax.set_xlabel('L7 view weight'); ax.set_ylabel(pcol)
        ax.legend(fontsize=7, markerscale=2, loc='best')
        ax.set_title('Model confidence vs view attention (test set)')
        fig.tight_layout(); fig.savefig(os.path.join(out_dir, 'p_vs_view.png'), dpi=150); plt.close(fig)
        written.append('p_vs_view.png')

    print('  figures: ' + ', '.join(f'{out_dir}/{f}' for f in written))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--demo', action='store_true', help='smoke test on random data (no files needed)')
    ap.add_argument('--netflows', default='dataset/netflows.csv',
                    help='captured L3/4 flow table from 04_pcap_to_flows.sh')
    ap.add_argument('--graphml', default='dataset/observed_services.graphml',
                    help='observed service-call graph from build_dataset.py (TRAIN session; used for every split)')
    ap.add_argument('--val_netflows', metavar='FILE',
                    help='separate validation session netflows.csv (for choosing the best epoch). '
                         'Omit to use the last 20%% of --netflows by time.')
    ap.add_argument('--test_netflows', metavar='FILE',
                    help='separate test session netflows.csv. Omit for the single-session 60/20/20 split.')
    ap.add_argument('--n_flows', type=int, default=0, help='cap number of flows (0 = all)')
    ap.add_argument('--max_normal', type=int, default=0,
                    help='downsample the normal class to at most N rows per split (keeps ALL attack flows); '
                         '0 = off. Caps graph size for GPU memory and eases the ~94%% normal imbalance.')
    ap.add_argument('--device', default='auto', choices=['auto', 'cpu', 'cuda'],
                    help='auto = cuda if available else cpu; cpu avoids GPU OOM on large graphs')
    ap.add_argument('--views', default='both', choices=list(VIEWS),
                    help="none = flow-features-only MLP baseline; l34 / l7 / both = graph views")
    ap.add_argument('--mapping', default='port', choices=list(MAPPINGS),
                    help='how flows are linked to service nodes (see fs_edges)')
    ap.add_argument('--seeds', default='0', help='comma-separated, e.g. 0,1,2,3,4 (mean +- std is reported)')
    ap.add_argument('--sweep', action='store_true', help='run the full comparison table over --seeds')
    ap.add_argument('--task', default='binary', choices=['binary', 'multiclass'],
                    help='binary = attack vs normal (F1, AUC); multiclass = per attack class (macro-F1, accuracy)')
    ap.add_argument('--drop_strong', action='store_true', help='drop sttl/dttl features (harder task)')
    ap.add_argument('--hid', type=int, default=32)
    ap.add_argument('--heads', type=int, default=4)
    ap.add_argument('--epochs', type=int, default=100)
    ap.add_argument('--lr', type=float, default=5e-3)
    ap.add_argument('--explain', metavar='DIR',
                    help='write explanations.csv + PNGs for the test set of the first seed. Works for any '
                         '--views: single views (l34/l7/none) get diagnostic plots (per-class detection, '
                         'score separation); --views both also gets the L3/4-vs-L7 attention attribution. '
                         'Not with --sweep')
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(',') if s.strip()]
    assert not (a.explain and a.sweep), '--explain cannot be combined with --sweep'
    if a.device == 'cuda':
        assert torch.cuda.is_available(), '--device cuda but no CUDA device is available'
        dev = torch.device('cuda')
    elif a.device == 'cpu':
        dev = torch.device('cpu')
    else:
        dev = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f'device: {dev}')
    global M2
    M2 = 'AUC' if a.task == 'binary' or a.demo else 'Acc'

    if a.demo:
        fl = demo_flows(); svc = demo_service_graph()
        cat_order = list(pd.Series(fl['keys']).value_counts().index)
        n = len(fl['y']); tr, va = int(.6 * n), int(.8 * n); idx = np.arange(n)
        splits = {'train': (fl, torch.as_tensor(idx < tr)),
                  'val':   (fl, torch.as_tensor((idx >= tr) & (idx < va))),
                  'test':  (fl, torch.as_tensor(idx >= va))}
        n_cls, classes, fl_tr = fl['n_cls'], fl['classes'], fl
    else:
        assert os.path.exists(a.netflows), (
            f'no netflows file: {a.netflows}\n'
            'Build a session first: ./05_run_attacks.sh  then  ./04_pcap_to_flows.sh ... netflows.csv')
        assert os.path.exists(a.graphml), (
            f'no graphml file: {a.graphml}\n'
            'Build it first: python build_dataset.py --logs <logs> --labels <labels.csv> --out_dir <dataset>')
        mc = a.task == 'multiclass'
        feat = fit_capture(a.netflows, drop_strong=a.drop_strong, multiclass=mc, n_flows=a.n_flows)
        svc = load_service_graph(a.graphml)
        cat_order, classes, n_cls = feat['cat_order'], feat['classes'], len(feat['classes'])
        fl_tr = transform_capture(feat, a.netflows, a.n_flows, max_normal=a.max_normal)
        if a.max_normal:
            print(f'note: normal class downsampled to <= {a.max_normal:,} per split '
                  '(all attack flows kept); test rates are at the capped base rate')
        if a.test_netflows:                                   # separate test session (inductive)
            fl_te = transform_capture(feat, a.test_netflows, max_normal=a.max_normal)
            if a.val_netflows:                                # separate val session too
                fl_va = transform_capture(feat, a.val_netflows, max_normal=a.max_normal)
                splits = {'train': (fl_tr, None), 'val': (fl_va, None), 'test': (fl_te, None)}
            else:                                             # val = last 20% of train by time
                n = len(fl_tr['y']); cut = int(.8 * n); idx = np.arange(n)
                splits = {'train': (fl_tr, torch.as_tensor(idx < cut)),
                          'val':   (fl_tr, torch.as_tensor(idx >= cut)), 'test': (fl_te, None)}
                print('note: no --val_netflows; validation = last 20% of the training session by time')
        else:                                                 # single-session 60/20/20 (backward compatible)
            n = len(fl_tr['y']); tr, va = int(.6 * n), int(.8 * n); idx = np.arange(n)
            splits = {'train': (fl_tr, torch.as_tensor(idx < tr)),
                      'val':   (fl_tr, torch.as_tensor((idx >= tr) & (idx < va))),
                      'test':  (fl_tr, torch.as_tensor(idx >= va))}
            print('WARNING: one session split 60/20/20 by time -- the test tail may miss attack '
                  'classes. Capture separate sessions and pass --val_netflows/--test_netflows.')

    print(f'{len(fl_tr["y"]):,} train flows | {fl_tr["n_hosts"]} hosts | {svc[0]} services, '
          f'{svc[1].shape[1]} dependency edges | {fl_tr["n_num"]} numeric features | task: {a.task}')
    for role in ('train', 'val', 'test'):                     # per-split class makeup (so missing classes are visible)
        fl_r, m = splits[role]
        y = fl_r['y'] if m is None else fl_r['y'][m.numpy()]
        lab = fl_r['meta']['label'].values if m is None else fl_r['meta']['label'].values[m.numpy()]
        print(f'  {role:<5} {len(y):>7,} flows | attack rate {np.mean(np.asarray(y) != 0):.3f} | '
              f'labels: {dict(pd.Series(lab).value_counts())}')

    if not a.sweep:
        rows = []
        for i, s in enumerate(seeds):
            f1t, auct, beta = run_once(splits, svc, n_cls, classes, a.views, a.mapping, s, a, dev, cat_order,
                                       verbose=len(seeds) == 1, explain_dir=a.explain if i == 0 else None)
            rows.append((f1t, auct))
            msg = f'[{a.views}/{a.mapping}] seed {s}: test F1 {f1t:.4f} | {M2} {auct:.4f}'
            if beta is not None and len(beta) == 2:
                msg += f' | attention L3/4 {beta[0]:.3f}  L7 {beta[1]:.3f}'
            print(msg)
        r = np.array(rows)
        if len(seeds) > 1:
            print(f'mean over {len(seeds)} seeds: F1 {r[:, 0].mean():.4f} +- {r[:, 0].std():.4f} | '
                  f'{M2} {r[:, 1].mean():.4f} +- {r[:, 1].std():.4f}')
        return

    print(f'\nsweep over seeds {seeds} (this trains {len(SWEEP) * len(seeds)} models)')
    table = []
    for name, views, mapping in SWEEP:
        r, b7 = [], []
        for s in seeds:
            f1t, auct, beta = run_once(splits, svc, n_cls, classes, views, mapping, s, a, dev, cat_order,
                                       verbose=False)
            r.append((f1t, auct))
            if beta is not None and len(beta) == 2:
                b7.append(beta[1])
            print(f'  {name:<20} seed {s}: F1 {f1t:.4f} {M2} {auct:.4f}', flush=True)
        r = np.array(r)
        table.append((name, r[:, 0].mean(), r[:, 0].std(), r[:, 1].mean(), r[:, 1].std(),
                      np.mean(b7) if b7 else float('nan')))
    print(f'\n{"config":<22}{"test F1":>18}{"test " + M2:>18}{"L7 attn":>10}')
    for name, f, fs, au, aus, b in table:
        print(f'{name:<22}{f"{f:.4f} +- {fs:.4f}":>18}{f"{au:.4f} +- {aus:.4f}":>18}'
              f'{("-" if b != b else f"{b:.3f}"):>10}')


if __name__ == '__main__':
    main()
