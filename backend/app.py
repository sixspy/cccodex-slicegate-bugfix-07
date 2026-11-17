
import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

# 测试钩子：在持锁事务内调用，默认空操作，并发测试用它制造持锁窗口
TXN_HOOK = None

POLICY_JIA = "甲"
POLICY_YI = "乙"
POLICY_CODES = {POLICY_JIA: "jia", POLICY_YI: "yi"}
VALID_POLICIES = (POLICY_JIA, POLICY_YI)

# 当日放行策略锁定说明——钉死策略时原样写入 release_policy.lock_note，并在策略页/侧栏/审计中对读
LOCK_NOTE = (
    "当日放行策略锁定说明：甲乙正确性口径与互斥账本择一执行，两边不得混口径；"
    "甲锁定——当日已有任一放行尝试（成功/拒绝/冻结）后再改口一律拒绝并返回『策略已锁定』；"
    "乙锁定——改口前必须先作废当日未完成草稿与半截流水并写改口审计，同一放行单禁止混用甲乙两套写入；"
    "禁止无审计改口，偏离本说明的写入一律拒绝并记『策略口径偏了』；改口侧与放行侧同时动手须排队加锁，后手记『策略争用』。"
)

# 账本终态：成功 / 拒绝（甲口径同步闸）/ 冻结（乙口径待补齐冻结区）/ 作废（改口清理）
LEDGER_TERMINAL = ("成功",)


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def lock_path() -> Path:
    # 跟随被 monkeypatch 的 DB_PATH，保证单机文件库与锁文件同目录
    return Path(DB_PATH).with_suffix(".lock")


def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def now_text() -> str:
    return datetime.now().isoformat(timespec="seconds")


def today_text() -> str:
    return datetime.now().date().isoformat()


class PolicyLock:
    """单机文件锁：改口侧与放行侧共用同一把锁，阻塞排队；发现有人持锁则给后手打争用标记。"""

    def __init__(self):
        self.fd = None
        self.contended = False

    def __enter__(self):
        self.fd = os.open(str(lock_path()), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # 前手正在动手：排队等锁，同时留下争用证据，不可静默过
            self.contended = True
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None


def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))


def _column_names(conn, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_column_if_missing(conn, table: str, column: str, ddl: str):
    if column not in _column_names(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def migrate(conn):
    """老库补列并回填口径戳，保证旧流水与新策略读数不打架。"""
    cols = _column_names(conn, "releases")
    if cols:
        _add_column_if_missing(conn, "releases", "release_no", "release_no TEXT")
        _add_column_if_missing(conn, "releases", "caliber", "caliber TEXT")
        _add_column_if_missing(conn, "releases", "policy_version", "policy_version INTEGER")
        _add_column_if_missing(conn, "releases", "attempt_date", "attempt_date TEXT")
        _add_column_if_missing(conn, "releases", "voided", "voided INTEGER NOT NULL DEFAULT 0")
        _add_column_if_missing(conn, "releases", "audit_id", "audit_id INTEGER")
        # 历史流水按甲口径（同步闸）回填，单号唯一，杜绝后续混写
        conn.execute(
            "UPDATE releases SET release_no='RO-LEGACY-'||id, caliber=?, policy_version=1, "
            "attempt_date=substr(created_at,1,10), voided=0 WHERE release_no IS NULL",
            (POLICY_JIA,),
        )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_releases_release_no ON releases(release_no)"
    )


def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS slices(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_no TEXT UNIQUE NOT NULL,
          biz_date TEXT NOT NULL,
          partition_key TEXT NOT NULL,
          row_count INTEGER NOT NULL,
          expected_count INTEGER NOT NULL,
          completeness TEXT NOT NULL,
          release_status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS releases(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_id INTEGER NOT NULL,
          consumer TEXT NOT NULL,
          status TEXT NOT NULL,
          note TEXT NOT NULL,
          created_at TEXT NOT NULL,
          release_no TEXT,
          caliber TEXT,
          policy_version INTEGER,
          attempt_date TEXT,
          voided INTEGER NOT NULL DEFAULT 0,
          audit_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS watermarks(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          consumer TEXT NOT NULL,
          biz_date TEXT NOT NULL,
          watermark TEXT NOT NULL,
          source_slice TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS release_policy(
          biz_date TEXT PRIMARY KEY,
          policy TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1,
          locked INTEGER NOT NULL DEFAULT 0,
          attempts INTEGER NOT NULL DEFAULT 0,
          lock_note TEXT NOT NULL,
          pinned_at TEXT NOT NULL,
          pinned_by TEXT NOT NULL,
          last_audit_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS policy_audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          kind TEXT NOT NULL,
          biz_date TEXT NOT NULL,
          from_policy TEXT,
          to_policy TEXT,
          operator TEXT NOT NULL,
          detail TEXT NOT NULL,
          related_ids TEXT NOT NULL DEFAULT '[]',
          lock_note TEXT
        );
        CREATE TABLE IF NOT EXISTS release_drafts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          release_no TEXT UNIQUE NOT NULL,
          slice_id INTEGER NOT NULL,
          consumer TEXT NOT NULL,
          caliber TEXT NOT NULL,
          policy_version INTEGER NOT NULL,
          biz_date TEXT NOT NULL,
          status TEXT NOT NULL,
          voided INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          void_audit_id INTEGER
        );
        """)
        migrate(conn)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_releases_release_no ON releases(release_no)"
        )
        if conn.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"] == 0:
            rows = [
                ("SL-2026-11-01-east", "2026-11-01", "east", 980, 1000, "部分完整", "未放行"),
                ("SL-2026-11-01-west", "2026-11-01", "west", 1000, 1000, "完整", "已放行"),
                ("SL-2026-11-02-east", "2026-11-02", "east", 0, 1000, "待检", "未放行"),
            ]
            for r in rows:
                conn.execute("INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status) VALUES (?,?,?,?,?,?,?)", r)
            conn.execute(
                "INSERT INTO releases(slice_id,consumer,status,note,created_at,release_no,caliber,policy_version,attempt_date,voided) "
                "VALUES (2,'ads_order','成功','完整切片放行','2026-11-01T18:00:00','RO-LEGACY-SEED',?,1,'2026-11-01',0)",
                (POLICY_JIA,),
            )
            conn.execute("INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES ('ads_order','2026-11-01','2026-11-01T18:00:00','SL-2026-11-01-west')")


PRODUCT = "日切放行"
SKELETON = "业务日分区切片登记后裁决完整度，完整才放行下游，并与消费水位对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def _start():
    init_db()


# ---------- 账本/策略服务层（所有写操作走同一把文件锁 + 单事务） ----------

def _begin(conn):
    conn.execute("BEGIN IMMEDIATE")


def _insert_audit(conn, kind: str, day: str, operator: str, detail: str,
                  from_policy: str | None = None, to_policy: str | None = None,
                  related_ids: list | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO policy_audit(ts,kind,biz_date,from_policy,to_policy,operator,detail,related_ids,lock_note) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (now_text(), kind, day, from_policy, to_policy, operator, detail,
         json.dumps(related_ids or [], ensure_ascii=False), LOCK_NOTE),
    )
    return cur.lastrowid


def _get_pin(conn, day: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM release_policy WHERE biz_date=?", (day,)).fetchone()


def _get_or_create_pin(conn, day: str, operator: str) -> sqlite3.Row:
    row = _get_pin(conn, day)
    if row:
        return row
    # 当日首条策略：默认甲口径同步闸，随钉死写入锁定说明
    conn.execute(
        "INSERT INTO release_policy(biz_date,policy,version,locked,attempts,lock_note,pinned_at,pinned_by,last_audit_id) "
        "VALUES (?,?,1,0,0,?,?,?,NULL)",
        (day, POLICY_JIA, LOCK_NOTE, now_text(), operator),
    )
    return conn.execute("SELECT * FROM release_policy WHERE biz_date=?", (day,)).fetchone()


def _pin_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "biz_date": row["biz_date"],
        "policy": row["policy"],
        "policy_code": POLICY_CODES.get(row["policy"], ""),
        "caliber": row["policy"],
        "version": row["version"],
        "locked": bool(row["locked"]),
        "attempts": row["attempts"],
        "lock_note": row["lock_note"],
        "pinned_at": row["pinned_at"],
        "pinned_by": row["pinned_by"],
        "last_audit_id": row["last_audit_id"],
    }


def _count_attempts(conn, day: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) c FROM releases WHERE attempt_date=? AND voided=0", (day,)
    ).fetchone()["c"]


def _refresh_pin_lock_state(conn, day: str):
    attempts = _count_attempts(conn, day)
    # 甲锁定条件：当日已有任一未作废放行尝试
    conn.execute(
        "UPDATE release_policy SET attempts=?, locked=? WHERE biz_date=?",
        (attempts, 1 if attempts > 0 else 0, day),
    )


def _new_release_no(day: str) -> str:
    return f"RO-{day}-{uuid.uuid4().hex[:10].upper()}"


def switch_policy(operator: str, target: str) -> dict[str, Any]:
    if target not in VALID_POLICIES:
        raise HTTPException(400, "策略口径非法，只允许 甲 或 乙")
    day = today_text()
    with PolicyLock() as lock:
        conn = connect()
        try:
            _begin(conn)
            pin = _get_or_create_pin(conn, day, operator)
            current = pin["policy"]
            if target == current:
                conn.commit()
                return {"changed": False, **_pin_payload(_get_pin(conn, day))}

            if TXN_HOOK is not None:
                TXN_HOOK()
            attempts = _count_attempts(conn, day)
            # 甲锁定（钉死甲口径时生效）：当日已有任一未作废放行尝试，拒绝改口
            if current == POLICY_JIA and attempts > 0:
                detail = f"策略已锁定：当日已有 {attempts} 条放行尝试（成功/拒绝/冻结），禁止由甲/乙改口；策略口径偏了"
                audit_id = _insert_audit(conn, "策略口径偏了", day, operator, detail,
                                         from_policy=current, to_policy=target)
                conn.execute("UPDATE release_policy SET last_audit_id=? WHERE biz_date=?",
                             (audit_id, day))
                conn.commit()
                raise HTTPException(409, "策略已锁定：当日已有放行尝试，禁止改口")

            # 乙锁定流程：先作废当日未完成草稿与半截流水（成功行属已完结账本，保留），
            # 再写改口审计；新旧口径不得混入同一放行单
            related: list[int] = []
            drafts = conn.execute(
                "SELECT * FROM release_drafts WHERE biz_date=? AND voided=0", (day,)
            ).fetchall()
            for d in drafts:
                aid = _insert_audit(conn, "作废", day, operator,
                                    f"改口前置作废：草稿 {d['release_no']}（{d['caliber']}口径）",
                                    from_policy=current, to_policy=target,
                                    related_ids=[d["id"]])
                conn.execute(
                    "UPDATE release_drafts SET voided=1,status='作废',void_audit_id=? WHERE id=?",
                    (aid, d["id"]),
                )
                related.append(d["id"])
            half = conn.execute(
                "SELECT * FROM releases WHERE attempt_date=? AND voided=0 AND status NOT IN ('成功')",
                (day,),
            ).fetchall()
            for h in half:
                aid = _insert_audit(conn, "作废", day, operator,
                                    f"改口前置作废：半截流水 {h['release_no']}（{h['caliber']}口径，{h['status']}）",
                                    from_policy=current, to_policy=target,
                                    related_ids=[h["id"]])
                conn.execute("UPDATE releases SET voided=1,status='作废',audit_id=? WHERE id=?",
                             (aid, h["id"]))
                related.append(h["id"])

            audit_id = _insert_audit(conn, "改口审计", day, operator,
                                     f"放行策略由 {current} 改为 {target}；已作废未完成草稿/半截流水 {len(related)} 笔，新旧口径不混入同一放行单",
                                     from_policy=current, to_policy=target,
                                     related_ids=related)
            conn.execute(
                "UPDATE release_policy SET policy=?, version=version+1, lock_note=?, "
                "pinned_at=?, pinned_by=?, last_audit_id=? WHERE biz_date=?",
                (target, LOCK_NOTE, now_text(), operator, audit_id, day),
            )
            _refresh_pin_lock_state(conn, day)
            if lock.contended:
                _insert_audit(conn, "策略争用", day, operator,
                              "策略争用：改口侧排队加锁后取得锁，后手未静默通过",
                              from_policy=current, to_policy=target)
            conn.commit()
            return {"changed": True, "audit_id": audit_id, "voided_ids": related,
                    **_pin_payload(_get_pin(conn, day))}
        except HTTPException:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def create_draft(operator: str, sid: int, consumer: str) -> dict[str, Any]:
    day = today_text()
    with PolicyLock() as lock:
        conn = connect()
        try:
            _begin(conn)
            pin = _get_or_create_pin(conn, day, operator)
            if not conn.execute("SELECT 1 FROM slices WHERE id=?", (sid,)).fetchone():
                conn.commit()
                raise HTTPException(404, "切片不存在")
            no = _new_release_no(day)
            cur = conn.execute(
                "INSERT INTO release_drafts(release_no,slice_id,consumer,caliber,policy_version,biz_date,status,voided,created_at) "
                "VALUES (?,?,?,?,?,?,'草稿',0,?)",
                (no, sid, consumer, pin["policy"], pin["version"], day, now_text()),
            )
            if lock.contended:
                _insert_audit(conn, "策略争用", day, operator,
                              "策略争用：草稿侧排队加锁后取得锁，后手未静默通过")
            conn.commit()
            return {"id": cur.lastrowid, "release_no": no, "caliber": pin["policy"],
                    "policy_version": pin["version"], "status": "草稿"}
        except HTTPException:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def attempt_release(operator: str, sid: int, consumer: str,
                    release_no: str | None, caliber: str | None) -> dict[str, Any]:
    day = today_text()
    with PolicyLock() as lock:
        conn = connect()
        try:
            _begin(conn)
            pin = _get_or_create_pin(conn, day, operator)
            active_policy = pin["policy"]

            # 请求显式带口径却与当日钉死策略不一致：偏离锁定说明，拒绝并记策略口径偏了
            if caliber is not None and caliber != active_policy:
                detail = (f"策略口径偏了：请求口径 {caliber} 与当日钉死策略 {active_policy} 不一致，"
                          "同一放行单禁止混用甲乙两套写入")
                audit_id = _insert_audit(conn, "策略口径偏了", day, operator, detail,
                                         from_policy=caliber, to_policy=active_policy)
                conn.execute("UPDATE release_policy SET last_audit_id=? WHERE biz_date=?",
                             (audit_id, day))
                conn.commit()
                raise HTTPException(409, "策略口径偏了：请求口径与当日钉死策略不一致")

            row = conn.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
            if not row:
                conn.commit()
                raise HTTPException(404, "切片不存在")

            if TXN_HOOK is not None:
                TXN_HOOK()
            no = release_no or _new_release_no(day)
            existing = conn.execute("SELECT * FROM releases WHERE release_no=?", (no,)).fetchone()
            if existing is not None:
                # 同一放行单只能有一套口径：后写入若换了甲/乙，直接拒绝
                if existing["caliber"] != active_policy:
                    detail = (f"策略口径偏了：放行单 {no} 已按 {existing['caliber']} 口径写入，"
                              f"不得再按 {active_policy} 口径混写")
                    audit_id = _insert_audit(conn, "策略口径偏了", day, operator, detail,
                                             from_policy=existing["caliber"],
                                             to_policy=active_policy, related_ids=[existing["id"]])
                    conn.execute("UPDATE release_policy SET last_audit_id=? WHERE biz_date=?",
                                 (audit_id, day))
                    conn.commit()
                    raise HTTPException(409, "策略口径偏了：同一放行单不得混用甲乙两套口径")
                if existing["voided"]:
                    conn.commit()
                    raise HTTPException(409, f"放行单 {no} 已作废，禁止再写入")

            complete = row["completeness"] == "完整"
            ts = now_text()
            contention_audit = None
            if lock.contended:
                contention_audit = _insert_audit(
                    conn, "策略争用", day, operator,
                    f"策略争用：放行侧（放行单 {no}）排队加锁后取得锁，后手未静默通过",
                    related_ids=[existing["id"]] if existing else [])

            if active_policy == POLICY_JIA:
                # 甲口径：放行与水位同步闸，不完整即拒绝入账，不推进水位
                if not complete:
                    note = "完整度未达标（甲口径同步闸拒绝）"
                    if existing is None:
                        cur = conn.execute(
                            "INSERT INTO releases(slice_id,consumer,status,note,created_at,release_no,"
                            "caliber,policy_version,attempt_date,voided,audit_id) VALUES (?,?,?,?,?,?,?,?,?,0,?)",
                            (sid, consumer, "拒绝", note, ts, no, active_policy, pin["version"], day,
                             contention_audit),
                        )
                        ledger_id = cur.lastrowid
                    else:
                        conn.execute(
                            "UPDATE releases SET status='拒绝',note=?,created_at=?,audit_id=? WHERE id=?",
                            (note, ts, contention_audit, existing["id"]))
                        ledger_id = existing["id"]
                    _refresh_pin_lock_state(conn, day)
                    conn.commit()
                    raise HTTPException(409, "未完整禁止放行")
                status, note = "成功", "完整切片放行（甲口径同步闸）"
                watermark = True
            else:
                # 乙口径：不完整进待补齐冻结区（半截流水可后续同单补齐），完整才放行推进水位
                if not complete:
                    status, note = "冻结", "完整度未达标，进待补齐冻结区（乙口径）"
                    watermark = False
                else:
                    status, note = "成功", "完整切片放行（乙口径异步纠偏后放行）"
                    watermark = True

            if existing is None:
                cur = conn.execute(
                    "INSERT INTO releases(slice_id,consumer,status,note,created_at,release_no,"
                    "caliber,policy_version,attempt_date,voided,audit_id) VALUES (?,?,?,?,?,?,?,?,?,0,?)",
                    (sid, consumer, status, note, ts, no, active_policy, pin["version"], day,
                     contention_audit),
                )
                ledger_id = cur.lastrowid
            else:
                conn.execute(
                    "UPDATE releases SET status=?,note=?,created_at=?,audit_id=? WHERE id=?",
                    (status, note, ts, contention_audit, existing["id"]))
                ledger_id = existing["id"]

            if status == "成功":
                conn.execute("UPDATE slices SET release_status='已放行' WHERE id=?", (sid,))
            if watermark:
                already = conn.execute(
                    "SELECT 1 FROM watermarks WHERE consumer=? AND source_slice=?",
                    (consumer, row["slice_no"]),
                ).fetchone()
                if not already:
                    conn.execute(
                        "INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES (?,?,?,?)",
                        (consumer, row["biz_date"], ts, row["slice_no"]))

            _refresh_pin_lock_state(conn, day)
            conn.commit()
            return {"ok": True, "release_no": no, "ledger_id": ledger_id,
                    "status": status, "caliber": active_policy,
                    "policy_version": pin["version"], "watermark": watermark,
                    "contention_audit_id": contention_audit}
        except HTTPException:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ---------- HTTP 接口 ----------

class LoginIn(BaseModel):
    username: str
    password: str


def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u


@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "slices": n, "db": str(DB_PATH)}


@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username, role FROM users WHERE username=? AND password_sha=?", (body.username, sha(body.password))).fetchone()
    if not row:
        raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16); SESSIONS[tok] = row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}


@app.get("/api/slices")
def list_slices(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM slices ORDER BY id").fetchall()
    return {"items": [dict(r) for r in rows]}


class SliceIn(BaseModel):
    slice_no: str
    biz_date: str
    partition_key: str
    row_count: int
    expected_count: int


@app.post("/api/slices")
def add_slice(body: SliceIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    comp = "完整" if body.row_count >= body.expected_count and body.expected_count > 0 else ("部分完整" if body.row_count > 0 else "待检")
    with connect() as c:
        try:
            cur = c.execute(
                "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status) VALUES (?,?,?,?,?,?,?)",
                (body.slice_no, body.biz_date, body.partition_key, body.row_count, body.expected_count, comp, "未放行"),
            )
            return {"id": cur.lastrowid, "completeness": comp}
        except sqlite3.IntegrityError:
            raise HTTPException(409, "切片号已存在")


@app.post("/api/slices/{sid}/evaluate")
def evaluate(sid: int, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
        if not row:
            raise HTTPException(404, "切片不存在")
        comp = "完整" if row["row_count"] >= row["expected_count"] and row["expected_count"] > 0 else ("部分完整" if row["row_count"] > 0 else "待检")
        c.execute("UPDATE slices SET completeness=? WHERE id=?", (comp, sid))
    return {"id": sid, "completeness": comp}


class SupplementIn(BaseModel):
    add_count: int


@app.post("/api/slices/{sid}/supplement")
def supplement(sid: int, body: SupplementIn, authorization: str | None = Header(default=None)):
    """乙口径冻结区切片补齐实收行数后重裁完整度。"""
    require_user(authorization)
    if body.add_count <= 0:
        raise HTTPException(400, "补齐行数必须为正")
    with PolicyLock():
        conn = connect()
        try:
            _begin(conn)
            row = conn.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
            if not row:
                conn.commit()
                raise HTTPException(404, "切片不存在")
            new_count = row["row_count"] + body.add_count
            comp = "完整" if new_count >= row["expected_count"] and row["expected_count"] > 0 else "部分完整"
            conn.execute("UPDATE slices SET row_count=?, completeness=? WHERE id=?",
                         (new_count, comp, sid))
            conn.commit()
            return {"id": sid, "row_count": new_count, "completeness": comp}
        except HTTPException:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


class DraftIn(BaseModel):
    consumer: str


@app.post("/api/slices/{sid}/draft")
def draft(sid: int, body: DraftIn, authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    return create_draft(user, sid, body.consumer)


@app.get("/api/drafts")
def list_drafts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT d.*, s.slice_no FROM release_drafts d
                            JOIN slices s ON s.id=d.slice_id ORDER BY d.id DESC""").fetchall()
    return {"items": [dict(r) for r in rows]}


class ReleaseIn(BaseModel):
    consumer: str
    release_no: str | None = None
    caliber: str | None = None


@app.post("/api/slices/{sid}/release")
def release(sid: int, body: ReleaseIn, authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    return attempt_release(user, sid, body.consumer, body.release_no, body.caliber)


@app.get("/api/releases")
def list_releases(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT r.*, s.slice_no FROM releases r
                            JOIN slices s ON s.id=r.slice_id ORDER BY r.id DESC""").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/watermarks")
def list_wm(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM watermarks ORDER BY id DESC").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/policy")
def get_policy(authorization: str | None = Header(default=None)):
    require_user(authorization)
    day = today_text()
    with connect() as c:
        row = _get_or_create_pin(c, day, require_user(authorization))
    return _pin_payload(row)


class PolicySwitchIn(BaseModel):
    policy: str


@app.post("/api/policy/switch")
def policy_switch(body: PolicySwitchIn, authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    return switch_policy(user, body.policy)


@app.get("/api/audits")
def list_audits(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM policy_audit ORDER BY id DESC").fetchall()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["related_ids"] = json.loads(d.get("related_ids") or "[]")
        except json.JSONDecodeError:
            d["related_ids"] = []
        items.append(d)
    return {"items": items}


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
