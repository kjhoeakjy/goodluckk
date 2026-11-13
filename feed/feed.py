"""GOODLUCK 구독자 화면 자료 작업.

원본 시스템이 발행한 암호화 자료(추천 순위·성능)를 받아 화면에 필요한 항목만 골라
일반·프리미엄 비밀번호로 각각 암호화해 live 브랜치에 기록한다. 장중에는 30초 간격으로 시세를 덧붙인다.

  python feed/feed.py run    # 장중 반복(예약 실행)
  python feed/feed.py once   # 1회 발행(수동 점검)

환경변수: SRC_PASSWORD, PW_BASIC, PW_PREMIUM, SRC_REPO(기본 kjhoeakjy/stock_high_low), SRC_TOKEN(선택)
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import math
import os
import random
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

OUT = Path(os.environ.get("FEED_OUT", "out"))
SRC_REPO = os.environ.get("SRC_REPO") or "kjhoeakjy/stock_high_low"
N_PREMIUM = 40
N_BASIC = 20
POOL = 100
TICK = 30
SLOTS_KEEP = 12
MAX_RUN = 5 * 3600  # GitHub 작업 6시간 한도 전 종료. 종료 코드 HANDOVER를 받은 작업 단계가 다음 실행을 호출
HANDOVER = 75
OPEN_SHIFT = {"20261119": 60}  # 개장 지연일(분)
KST = dt.timezone(dt.timedelta(hours=9))
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
      "Referer": "https://m.stock.naver.com/", "Accept": "*/*"}
REALTIME = "https://polling.finance.naver.com/api/realtime/domestic/stock/"
INDEX = "https://m.stock.naver.com/api/index/{}/basic"

# ---------------------------------------------------------------- 암호화
SRC_SALT, SRC_ITER = b"stock_high_low/v1", 1_000_000
OUT_SALT, OUT_ITER = "goodluckk/v1", 600_000
_KEYS: dict[tuple, bytes] = {}


def _key(pw: str, salt: bytes, it: int) -> bytes:
    k = (pw, salt, it)
    if k not in _KEYS:
        _KEYS[k] = PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())
    return _KEYS[k]


def dec(doc: dict, pw: str) -> bytes:
    k = _key(pw, doc["salt"].encode(), int(doc["iter"]))
    return AESGCM(k).decrypt(base64.b64decode(doc["iv"]), base64.b64decode(doc["ct"]), None)


def enc(obj, pw: str) -> str:
    data = json.dumps(_finite(obj), ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    iv = secrets.token_bytes(12)
    ct = AESGCM(_key(pw, OUT_SALT.encode(), OUT_ITER)).encrypt(iv, data, None)
    return json.dumps({"v": 1, "iter": OUT_ITER, "salt": OUT_SALT,
                       "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()})


def _finite(o):
    if isinstance(o, float):
        return o if math.isfinite(o) else None
    if isinstance(o, dict):
        return {k: _finite(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_finite(v) for v in o]
    return o


def read_enc(path: Path, pw: str):
    try:
        return json.loads(dec(json.loads(path.read_text()), pw))
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- 시각
def now() -> dt.datetime:
    return dt.datetime.now(KST)


def ymd(t: dt.datetime) -> str:
    return t.strftime("%Y%m%d")


def session(t: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    sh = OPEN_SHIFT.get(ymd(t), 0)
    base = t.replace(hour=9, minute=0, second=0, microsecond=0) + dt.timedelta(minutes=sh)
    return base, base + dt.timedelta(hours=6, minutes=30)


# ---------------------------------------------------------------- 조회
def http(url: str, headers: dict | None = None, timeout: int = 20, tries: int = 3) -> bytes | None:
    h = dict(UA)
    h.update(headers or {})
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404):
                print(f"[http] {e.code}")
                return None
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1.5 * (i + 1))
    return None


def src_file(name: str):
    """원본 저장소 docs/<name>(암호문 JSON)을 받아 복호화."""
    tok = os.environ.get("SRC_TOKEN")
    if tok:
        raw = http(f"https://api.github.com/repos/{SRC_REPO}/contents/docs/{name}?ref=main",
                   {"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github.raw"}, timeout=60)
    else:
        raw = http(f"https://raw.githubusercontent.com/{SRC_REPO}/main/docs/{name}?t={int(time.time())}", {"Cache-Control": "no-cache"}, timeout=60)
    if raw is None:
        return None
    try:
        return json.loads(dec(json.loads(raw), os.environ["SRC_PASSWORD"]))
    except Exception as e:  # noqa: BLE001
        print(f"[src] {name} 복호화 실패: {type(e).__name__}")
        return None


def _num(s):
    if s is None:
        return None
    if isinstance(s, (int, float)):
        return float(s)
    s = re.sub(r"[^0-9.\-]", "", str(s).replace("−", "-"))
    try:
        return float(s) if s not in ("", "-", ".") else None
    except ValueError:
        return None


def _kval(s):
    if s is None:
        return None
    if isinstance(s, (int, float)):
        return float(s)
    m = re.match(r"^(-?[\d.]+)\s*([조억만])?", str(s).replace(",", "").strip())
    return float(m.group(1)) * {"조": 1e12, "억": 1e8, "만": 1e4}.get(m.group(2), 1.0) if m else None


def quotes(codes: list[str], day: str) -> dict[str, dict]:
    """현재가 조회. 거래 시각이 day(YYYYMMDD)인 시세만 사용(장 시작 전 전일 값 혼입 방지)."""
    out = {}
    for i in range(0, len(codes), 100):
        raw = http(REALTIME + ",".join(codes[i:i + 100]))
        try:
            ds = json.loads(raw or b"{}").get("datas") or []
        except Exception:  # noqa: BLE001
            ds = []
        for s in ds:
            code = s.get("itemCode") or s.get("stockCode")
            price = _num(s.get("closePriceRaw") or s.get("closePrice"))
            chg = _num(s.get("compareToPreviousClosePriceRaw") or s.get("compareToPreviousClosePrice"))
            traded = re.sub(r"[^0-9]", "", str(s.get("localTradedAt") or ""))[:8]
            if not code or not price or chg is None or (traded and traded != day):
                continue
            sign = (s.get("compareToPreviousPrice") or {}).get("code")
            if sign in ("4", "5"):
                chg = -abs(chg)
            prev = price - chg
            if prev <= 0:
                continue
            op = _num(s.get("openPriceRaw") or s.get("openPrice"))
            out[code] = {"price": price, "ret": price / prev - 1, "o_ret": (price / op - 1) if op else None,
                         "hi_ret": (_num(s.get("highPriceRaw") or s.get("highPrice")) or price) / prev - 1,
                         "val": _kval(s.get("accumulatedTradingValue")),
                         "lim": sign == "1", "halt": (s.get("tradeStopType") or {}).get("code") not in (None, "1")}
    return out


def index_quotes() -> dict:
    out = {}
    for k in ("KOSPI", "KOSDAQ"):
        try:
            j = json.loads(http(INDEX.format(k)) or b"{}")
            r = _num(j.get("fluctuationsRatio"))
            if r is not None:
                out[k] = r / 100
        except Exception:  # noqa: BLE001
            pass
    return out


# ---------------------------------------------------------------- 자료 정리
def _pick(d: dict | None, keys) -> dict | None:
    return None if not isinstance(d, dict) else {k: d[k] for k in keys if k in d}


SU_KEYS = ("days", "up@5", "p@5", "oc10@5", "oc_win@5", "unbuyable@5")
MON_KEYS = ("ym", "days", "pos", "p@5", "up@5", "gap@5", "oc@5", "net@5")
EX_KEYS = ("final", "cum", "fixed_pnl", "fixed_cum", "day_avg", "win", "worst", "mdd", "skipped", "unfilled", "carried",
           "approx_share", "from", "to")


def _su(s: dict) -> dict:
    o = _pick(s, SU_KEYS) or {}
    o["net"] = _pick(s.get("net"), ("trade_day", "trade_loss_days", "trade_worst"))
    sim = s.get("sim")
    if isinstance(sim, dict):
        o["sim"] = {**(_pick(sim, ("final", "cum", "mdd")) or {}),
                    "daily": [_pick(r, ("d", "bal")) for r in (sim.get("daily") or []) if isinstance(r, dict)]}
    o["monthly"] = [_pick(m, MON_KEYS) for m in (s.get("monthly") or []) if isinstance(m, dict)]
    o["buckets"] = [_pick(b, ("lo", "hi", "n", "rate")) for b in (s.get("buckets") or []) if isinstance(b, dict)]
    return o


def perf_doc(src: dict) -> dict:
    """성능 화면용 자료만 추림(모형 변수·계좌·규칙 값 제외)."""
    base = ((src.get("stats") or {}).get("y_oc10")) or {}
    stats = _su(base)
    stats["horizons"] = {str(h): _su(v) for h, v in (base.get("horizons") or {}).items() if isinstance(v, dict)}
    ex = src.get("exec") or {}
    exec_ = {**(_pick(ex, ("k", "coverage", "bars_full", "gap_days", "gap_approx", "delta_day")) or {}),
             "horizons": {str(h): _pick(v, EX_KEYS) for h, v in (ex.get("horizons") or {}).items() if isinstance(v, dict)},
             "daily": [_pick(r, ("d", "ret")) for r in (ex.get("daily") or []) if isinstance(r, dict)]}
    hist = []
    for h in src.get("history") or []:
        if not h.get("graded"):
            continue
        x = _pick(h, ("target_date", "actual_up_count", "up_hits", "up_10", "up_touch", "up_mean_ret", "up_mean_oc",
                      "trade_net_day", "trade_flag")) or {}
        x["up"] = [_pick(u, ("name", "ret", "hit")) for u in (h.get("up") or [])[:5]]
        hist.append(x)
    perf = [_pick(p, ("as_of", "train_rows", "n_features", "p@5", "ap", "auc", "oc@5", "live_rate")) for p in (src.get("perf") or [])]
    return {"as_of": src.get("as_of"), "generated_at": src.get("generated_at"), "stats": stats, "exec": exec_,
            "history": hist, "perf": perf}


def _txt(v, n: int = 300):
    return str(v)[:n] if v is not None else None


def detail_doc(src: dict, codes: list[str]) -> dict:
    """프리미엄 종목 상세(추천 근거·차트·공시·뉴스). 원본 추천 목록에 상세가 있는 종목으로 한정. 모형 점수·변수 표는 제외."""
    want = set(codes)
    items = {}
    for u in src.get("up") or []:
        code = u.get("code")
        if code not in want:
            continue
        ch = u.get("chart") or {}
        ev = u.get("evidence") or {}
        llm = u.get("llm") if isinstance(u.get("llm"), dict) else None
        g = u.get("groups") or {}
        items[code] = {
            "chart": {k: ch[k] for k in ("d", "o", "h", "l", "c", "v", "fd", "frgn", "inst", "indiv") if isinstance(ch.get(k), list)},
            "up_limit": u.get("up_limit"),
            "reasons": [{"text": _txt(r.get("text"), 80), "dir": "-" if r.get("dir") == "-" else "+"}
                        for r in (u.get("reasons") or []) if isinstance(r, dict) and r.get("text")][:6],
            "groups": {"industry": [_txt(x, 40) for x in (g.get("industry") or [])][:1], "themes": [_txt(x, 40) for x in (g.get("themes") or [])][:6]},
            "news": [{"t": _txt(n.get("t"), 16), "title": _txt(n.get("title")), "url": _txt(n.get("url"), 500)}
                     for n in (ev.get("news") or []) if isinstance(n, dict) and n.get("title")][:4],
            "disc": [{"t": _txt(x.get("t"), 20), "title": _txt(x.get("title"))}
                     for x in (ev.get("disclosures") or []) if isinstance(x, dict) and x.get("title")][:6],
            "llm": ({"verdict": _txt(llm.get("verdict"), 10), "event": _txt(llm.get("event"), 60), "note": _txt(llm.get("note"), 300)} if llm else None),
        }
    return {"target_date": src.get("target_date"), "gen": src.get("generated_at"), "items": items}


def ranking(src: dict, scores: dict | None) -> list[dict]:
    """점수 순위 상위 POOL: [{code,name,close,ret1}]. 전 종목 점수표(정렬됨)가 같은 기준일이면 사용, 아니면 추천 목록."""
    rows = []
    if scores and scores.get("as_of") == src.get("as_of"):
        for r in scores.get("rows") or []:
            rows.append({"code": r[0], "name": r[1], "close": r[2], "ret1": r[3]})
            if len(rows) >= POOL:
                break
    if len(rows) < N_PREMIUM:
        rows = [{"code": u["code"], "name": u["name"], "close": u.get("close"), "ret1": u.get("ret1")} for u in src.get("up") or []]
    return rows


def is_final(src: dict) -> bool:
    g = re.sub(r"[^0-9]", "", src.get("generated_at") or "")
    return g[:8] == src.get("target_date") and g[8:12] >= "0600"


def build_lists(src: dict, scores: dict | None, prev_b: dict | None) -> tuple[dict, dict] | None:
    rank = ranking(src, scores)
    if len(rank) < N_BASIC:
        print("[build] 순위 자료 부족")
        return None
    meta = {"target_date": src["target_date"], "as_of": src["as_of"], "gen": src.get("generated_at"),
            "final": is_final(src), "n_scored": src.get("n_scored")}
    prem = [{**r, "rank": i + 1} for i, r in enumerate(rank[:N_PREMIUM])]
    # 일반: 상위 POOL 중 무작위 N_BASIC(같은 날 다시 발행해도 아직 후보 안에 있는 종목은 유지)
    pool = {r["code"]: r for r in rank[:POOL]}
    keep = []
    if prev_b and prev_b.get("target_date") == src["target_date"]:
        keep = [it["code"] for it in prev_b.get("items") or [] if it.get("code") in pool][:N_BASIC]
    rest = [c for c in pool if c not in keep]
    random.SystemRandom().shuffle(rest)
    chosen = keep + rest[:N_BASIC - len(keep)]
    basic = sorted((pool[c] for c in chosen), key=lambda r: r["name"])
    return {**meta, "tier": "basic", "items": basic}, {**meta, "tier": "premium", "items": prem}


# ---------------------------------------------------------------- 기록
def write(name: str, text: str) -> None:
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def push(msg: str) -> None:
    def g(*a, check=True):
        return subprocess.run(["git", "-C", str(OUT), *a], check=check, capture_output=True, text=True, timeout=60)
    g("add", "-A")
    if not g("diff", "--cached", "--quiet", check=False).returncode:
        return
    has = g("rev-parse", "-q", "--verify", "HEAD", check=False).returncode == 0
    g("commit", "-q", *(["--amend"] if has else []), "-m", msg)  # 커밋 1개만 유지(이력 누적 없음)
    for i in range(4):
        if g("push", "-q", "-f", "origin", "HEAD:live", check=False).returncode == 0:
            return
        time.sleep(2 * (i + 1))
    print("[push] 실패")


def prune_slots() -> None:
    d = OUT / "t"
    if not d.exists():
        return
    ks = sorted({int(p.name.split(".")[0]) for p in d.glob("*.enc") if p.name.split(".")[0].isdigit()})
    for k in ks[:-SLOTS_KEEP]:
        for p in d.glob(f"{k}.*"):
            p.unlink()


class Feed:
    def __init__(self):
        self.pw = {"b": os.environ["PW_BASIC"], "p": os.environ["PW_PREMIUM"]}
        if self.pw["b"] == self.pw["p"]:
            raise SystemExit("PW_BASIC과 PW_PREMIUM이 같음")
        self.lists = {"b": read_enc(OUT / "cur" / "b.json.enc", self.pw["b"]),
                      "p": read_enc(OUT / "cur" / "p.json.enc", self.pw["p"])}
        lb = self.lists["b"] or {}
        self.gen = lb.get("gen")
        self.quotes: dict = {}
        self.index: dict = lb.get("index") or {}
        self.qat = None  # 이번 실행에서 받은 시세 시각(없으면 이전 실행이 남긴 값을 그대로 둠)
        self.closed = bool(lb.get("closed"))
        self.static_ok = False

    def refresh_source(self) -> bool:
        src = src_file("latest.json.enc")
        if not src or not src.get("target_date"):
            print("[src] 자료 없음")
            return False
        t = now()
        today = ymd(t)
        if src.get("generated_at") == self.gen and self.lists["b"] and self.lists["p"]:
            if not self.static_ok:
                self.write_static(src)  # 실행마다 1회 재기록(이전 실행이 남기지 못한 경우 대비)
            return False
        if src["target_date"] < today:
            print("[src] 지난 기준일 자료 · 유지")
            return False
        if src["target_date"] > today and self.lists["b"] and self.lists["b"].get("target_date", "") >= today:
            print("[src] 다음 거래일 잠정안 · 오늘 목록 유지")
            return False
        if not is_final(src) and src["target_date"] == today and t.strftime("%H%M") < "0840" and self.lists["b"]:
            print("[src] 최종안 대기")
            return False
        scores = src_file("scores.json.enc")
        built = build_lists(src, scores, self.lists["b"] if (self.lists["b"] or {}).get("target_date") == src["target_date"] else None)
        if not built:
            return False
        self.lists["b"], self.lists["p"] = built
        self.gen = src.get("generated_at")
        self.quotes, self.qat, self.closed = {}, None, False
        self.write_static(src)
        print(f"[src] 목록 발행 · 기준일 {src['target_date']} · {'최종' if built[0]['final'] else '잠정'}")
        return True

    def write_static(self, src: dict) -> None:
        """목록과 함께 바뀌는 자료: 성능(두 요금제), 종목 상세(프리미엄)."""
        pf = perf_doc(src)
        for k in ("b", "p"):
            write(f"cur/perf.{k}.json.enc", enc(pf, self.pw[k]))
        write("cur/detail.p.json.enc", enc(detail_doc(src, [it["code"] for it in self.lists["p"]["items"]]), self.pw["p"]))
        self.static_ok = True
        self._sig = None  # 다음 기록 때 함께 올라가도록

    def refresh_quotes(self) -> bool:
        b, p = self.lists["b"], self.lists["p"]
        if not b or not p:
            return False
        day = b["target_date"]
        codes = sorted({it["code"] for it in b["items"]} | {it["code"] for it in p["items"]})
        q = quotes(codes, day)
        if not q:
            return False
        self.quotes = q
        self.index = index_quotes() or self.index
        self.qat = now().strftime("%Y-%m-%d %H:%M:%S")
        return True

    def doc(self, k: str) -> dict:
        d = dict(self.lists[k])
        if self.qat:
            d["items"] = [{**it, **self.quotes.get(it["code"], {})} for it in d["items"]]
            d["q_at"], d["index"] = self.qat, self.index
        d["closed"] = self.closed
        return d

    def emit(self, slot: bool) -> None:
        if not self.lists["b"]:
            return
        docs = {t: self.doc(t) for t in ("b", "p")}
        sig = json.dumps(docs, sort_keys=True, default=str)
        if sig == getattr(self, "_sig", None):
            return  # 바뀐 내용 없음 → 기록 생략
        self._sig = sig
        k = int(time.time() // 10)
        for t in ("b", "p"):
            text = enc(docs[t], self.pw[t])
            write(f"cur/{t}.json.enc", text)
            if slot:
                write(f"t/{k}.{t}.json.enc", text)
        prune_slots()
        push(f"feed {now().strftime('%m%d %H%M%S')}")


def run(loop: bool) -> int:
    f = Feed()
    t0 = time.time()
    f.refresh_source()
    last_src = time.time()
    while True:
        t = now()
        op, cl = session(t)
        wk = t.weekday() < 5
        today_list = (f.lists["b"] or {}).get("target_date") == ymd(t)
        in_sess = wk and op <= t <= cl + dt.timedelta(minutes=2)
        try:
            if (in_sess and today_list) or not loop:
                f.refresh_quotes()
            if t > cl + dt.timedelta(minutes=2) and f.qat and f.qat[:10] == t.strftime("%Y-%m-%d"):
                f.closed = True  # 장 마감 후 받은 시세 = 종가
            f.emit(slot=in_sess)
        except Exception as e:  # noqa: BLE001  한 주기 실패가 전체 종료로 이어지지 않도록
            print(f"[run] 주기 오류: {type(e).__name__}")
            f._sig = None
            if not loop:
                return 1
        if not loop:
            return 0
        if not wk or t > cl + dt.timedelta(minutes=5):
            print("[run] 종료")
            return 0
        if time.time() - t0 > MAX_RUN:
            print("[run] 작업 시간 한도 · 다음 실행에 인계")
            return HANDOVER
        if t > op + dt.timedelta(minutes=30) and not today_list:
            print("[run] 오늘 목록 없음(휴장일 등) · 종료")
            return 0
        # 원본 자료 확인: 장 시작 전 3분, 장중 20분 간격
        if time.time() - last_src > (180 if t < op else 1200):
            try:
                f.refresh_source()
            except Exception as e:  # noqa: BLE001
                print(f"[run] 원본 확인 오류: {type(e).__name__}")
            last_src = time.time()
        time.sleep(max(1.0, TICK - (time.time() % TICK)))


if __name__ == "__main__":
    for v in ("SRC_PASSWORD", "PW_BASIC", "PW_PREMIUM"):
        if not os.environ.get(v):
            print(f"Secret {v} 없음")
            sys.exit(1)
    sys.exit(run(loop=(sys.argv[1:] or ["run"])[0] == "run"))
