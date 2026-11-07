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


def l7_keys(service, dsport, top_ports=8):
    """L7 category per flow: a `service` label when present; otherwise a frequent dst port, else 'other'.
    With captured data there is no service label, so this falls back to the dst port."""
    service, dsport = pd.Series(service).astype(str), pd.Series(dsport).astype(str)
    top = set(dsport.value_counts().index[:top_ports])
    fb = np.where(dsport.isin(top), 'p' + dsport, 'other')
    return np.where(service.values == '-', fb, service.values)


def fs_edges(keys, src_h, dst_h, n_hosts, svc_edges, n_svc, mapping, seed):
    """flow -> service edges (numpy, [2, E]).
    port     : flow category (dst port) -> service node. Categories ranked by frequency and assigned to
               services ranked by degree in the dependency graph (hubs get the busiest ports).
    shuffled : same grouping of flows, but categories assigned to RANDOM service nodes (control experiment:
               keeps the 'which flows share a service' structure, breaks alignment with graph topology).
    random   : every host gets a random service; a flow links to the service of its src and dst host.
    """
    assert mapping in MAPPINGS, mapping
    n = len(keys)
    fid = np.arange(n)
    rng = np.random.default_rng(seed)
    if mapping == 'random':
        host2svc = rng.integers(0, n_svc, n_hosts)
        return np.stack([np.concatenate([fid, fid]), np.concatenate([host2svc[src_h], host2svc[dst_h]])])
    order = pd.Series(keys).value_counts().index                     # most frequent first
    rank = pd.Series(keys).map({k: i for i, k in enumerate(order)}).values
    if mapping == 'port':
        deg = np.bincount(svc_edges.ravel(), minlength=n_svc) if svc_edges.size else np.zeros(n_svc, int)
        svc_order = np.argsort(-deg, kind='stable')
    else:
        svc_order = rng.permutation(n_svc)
    return np.stack([fid, svc_order[rank % n_svc]])                  # >n_svc categories share nodes (modulo)


def build_tensors(fl, svc, mapping, seed):
    """Assemble all edge sets. fl: flow dict, svc: (n_svc, svc_edges)."""
    n_svc, svc_edges = svc
    n = len(fl['y'])
    fid = np.arange(n)
    ei_fh = np.stack([np.concatenate([fid, fid]), np.concatenate([fl['src_h'], fl['dst_h']])])
    ei_fs = fs_edges(fl['keys'], fl['src_h'], fl['dst_h'], fl['n_hosts'], svc_edges, n_svc, mapping, seed)
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


def build_from_capture(netflows, n_flows=0, drop_strong=False, multiclass=False):
    """Featurise the captured L3/4 flow table (dataset/netflows.csv from Argus) into the
    flow dict the model consumes. The L7 side stays separate: observed_services.graphml
    is loaded by load_service_graph and fused in-model. Missing Argus columns are
    tolerated rather than assumed present."""
    df = pd.read_csv(netflows, low_memory=False)
    assert len(df), f'{netflows} is empty'
    for c in CAP_NUM + CAP_CAT + ['saddr', 'daddr', 'dport', 'stime', 'label']:
        if c not in df.columns:
            df[c] = 0 if c in CAP_NUM else ('-' if c in CAP_CAT + ['saddr', 'daddr'] else
                                            (0 if c in ('dport', 'stime') else 'normal'))
    df['stime'] = pd.to_numeric(df['stime'], errors='coerce').fillna(0)
    df = df.sort_values('stime').reset_index(drop=True)      # temporal order for the split
    if n_flows:
        df = df.head(n_flows).reset_index(drop=True)
    num = [c for c in CAP_NUM if not (drop_strong and c in CAP_STRONG)]
    for c in CAP_NUM:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df[CAP_NUM] = df[CAP_NUM].fillna(0).clip(lower=0)

    lab = df['label'].fillna('normal').astype(str).str.strip().replace({'': 'normal'})
    if multiclass:
        y, uniq = pd.factorize(lab, sort=True)
        classes = list(uniq)
    else:                                                    # binary: normal vs attack
        y = (lab.str.lower() != 'normal').astype(int).values
        classes = ['Normal', 'Attack']

    xn = np.log1p(df[num].values.astype(np.float64))
    xn = (xn - xn.mean(0)) / (xn.std(0) + 1e-6)
    cat = df[CAP_CAT].astype(str).apply(lambda s: s.where(s.isin(s.value_counts().index[:10]), 'other'))
    xc = pd.get_dummies(cat, dtype=np.float32).values
    x = np.concatenate([xn, xc], axis=1)

    n = len(df)
    codes, uniq = pd.factorize(pd.concat([df['saddr'], df['daddr']], ignore_index=True))
    # L7 key per flow: destination port (no 'service' label in captured flows), so pass
    # service='-' and let l7_keys fall back to frequent dst ports.
    keys = l7_keys(pd.Series(['-'] * n), df['dport'])
    return dict(x=x, y=y, src_h=codes[:n], dst_h=codes[n:], n_hosts=len(uniq),
                n_cls=len(classes), classes=classes, n_num=len(num), keys=keys)


def demo_flows(n=20000, n_hosts=45, data_seed=0):
    """Random smoke-test data (no files needed), used by --demo."""
    rng = np.random.default_rng(data_seed)
    y = (rng.random(n) < 0.3).astype(int)
    x = rng.normal(size=(n, 20)) + y[:, None] * 0.4
    src_h = np.where(y == 1, rng.integers(0, 5, n), rng.integers(0, n_hosts, n))
    dst_h = rng.integers(0, n_hosts, n)
    keys = np.where(y == 1, rng.integers(0, 3, n), rng.integers(0, 6, n)).astype(str)
    return dict(x=x, y=y, src_h=src_h, dst_h=dst_h, n_hosts=n_hosts, keys=keys, n_cls=2,
                classes=['Normal', 'Attack'], n_num=20)


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
    """Learns one weight per view (HAN-style) and returns the weighted sum."""
    def __init__(self, d, hid=64):
        super().__init__()
        self.score = nn.Sequential(nn.Linear(d, hid), nn.Tanh(), nn.Linear(hid, 1, bias=False))

    def forward(self, zs):
        z = torch.stack(zs, 1)                              # [N, V, D]
        beta = torch.softmax(self.score(z).mean(0), dim=0)  # [V, 1]
        return (beta.unsqueeze(0) * z).sum(1), beta.squeeze(-1)


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


def run_once(fl, svc, views, mapping, seed, a, dev, verbose=True):
    torch.manual_seed(seed)
    np.random.seed(seed)
    g = build_tensors(fl, svc, mapping, seed)
    g = {k: (v.to(dev) if torch.is_tensor(v) else v) for k, v in g.items()}
    n = len(g['y'])
    # temporal split (flows are sorted by capture time)
    tr, va = int(.6 * n), int(.8 * n)
    idx = torch.arange(n, device=dev)
    m_tr, m_va, m_te = idx < tr, (idx >= tr) & (idx < va), idx >= va

    n_cls = fl['n_cls']
    model = TwoViewGAT(g['x'].shape[1], g['n_svc'], a.hid, a.heads, n_cls=n_cls, views=VIEWS[views]).to(dev)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=1e-4)
    cnt = torch.bincount(g['y'][m_tr], minlength=n_cls).float()
    w = cnt.sum() / (n_cls * cnt.clamp(min=1))
    if n_cls > 2:                                    # tame the huge weights of very rare classes
        w = w.sqrt().clamp(max=20)
    w = w.to(dev)

    def evaluate(mask):
        model.eval()
        with torch.no_grad():
            logits, beta = model(g)
        t = g['y'][mask].cpu().numpy()
        if n_cls == 2:                                   # binary: F1 of the attack class + AUC
            p = logits.softmax(-1)[:, 1][mask].cpu().numpy()
            f1 = f1_score(t, p > 0.5, zero_division=0)
            m2 = roc_auc_score(t, p) if len(set(t)) > 1 else float('nan')
        else:                                            # multiclass: macro-F1 + accuracy
            pred = logits.argmax(-1)[mask].cpu().numpy()
            f1 = f1_score(t, pred, average='macro', zero_division=0)
            m2 = float((pred == t).mean())
        return f1, m2, beta

    best, best_state = -1, None
    for ep in range(1, a.epochs + 1):
        model.train()
        opt.zero_grad()
        logits, _ = model(g)
        loss = F.cross_entropy(logits[m_tr], g['y'][m_tr], weight=w)
        loss.backward()
        opt.step()
        f1v, aucv, _ = evaluate(m_va)
        if f1v > best:
            best, best_state = f1v, {k: v.clone() for k, v in model.state_dict().items()}
        if verbose and ep % 10 == 0:
            print(f'ep {ep:3d} loss {loss.item():.4f} val F1 {f1v:.4f} {M2} {aucv:.4f}')

    model.load_state_dict(best_state)
    f1t, auct, beta = evaluate(m_te)
    return f1t, auct, (None if beta is None else beta.cpu().numpy())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--demo', action='store_true', help='smoke test on random data (no files needed)')
    ap.add_argument('--netflows', default='dataset/netflows.csv',
                    help='captured L3/4 flow table from 04_pcap_to_flows.sh')
    ap.add_argument('--graphml', default='dataset/observed_services.graphml',
                    help='observed service-call graph from build_dataset.py')
    ap.add_argument('--n_flows', type=int, default=0, help='cap number of flows (0 = all)')
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
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(',') if s.strip()]
    dev = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    global M2
    M2 = 'AUC' if a.task == 'binary' or a.demo else 'Acc'

    if a.demo:
        fl, svc = demo_flows(), demo_service_graph()
    else:
        assert os.path.exists(a.netflows), (
            f'no netflows file: {a.netflows}\n'
            'Build a session first: ./05_run_attacks.sh  then  ./04_pcap_to_flows.sh ... netflows.csv')
        assert os.path.exists(a.graphml), (
            f'no graphml file: {a.graphml}\n'
            'Build it first: python build_dataset.py --logs <logs> --labels <labels.csv> --out_dir <dataset>')
        fl = build_from_capture(a.netflows, a.n_flows, drop_strong=a.drop_strong,
                                multiclass=a.task == 'multiclass')
        svc = load_service_graph(a.graphml)
    print(f'{len(fl["y"]):,} flows | {fl["n_hosts"]} hosts | {svc[0]} services, {svc[1].shape[1]} dependency edges '
          f'| {fl["n_num"]} numeric features | task: {a.task}')
    if fl['n_cls'] > 2:
        print('class counts:', dict(zip(fl['classes'], np.bincount(fl['y']).tolist())))
    else:
        print(f'attack rate {fl["y"].mean():.3f}')

    if not a.sweep:
        rows = []
        for s in seeds:
            f1t, auct, beta = run_once(fl, svc, a.views, a.mapping, s, a, dev, verbose=len(seeds) == 1)
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
            f1t, auct, beta = run_once(fl, svc, views, mapping, s, a, dev, verbose=False)
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
