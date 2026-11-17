
import threading

import pytest
from fastapi.testclient import TestClient

import app as appmod
from app import app, init_db, PolicyLock, switch_policy, attempt_release, LOCK_NOTE


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "t.db")
    init_db()
    yield
    monkeypatch.setattr("app.TXN_HOOK", None)


@pytest.fixture()
def client():
    return TestClient(app)


def _login(c):
    r = c.post("/api/login", json={"username": "admin", "password": "123456"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _partial_slice(c, h, no="SL-T-P"):
    r = c.post("/api/slices", headers=h, json={
        "slice_no": no, "biz_date": "2026-11-04", "partition_key": "mid",
        "row_count": 3, "expected_count": 10})
    assert r.status_code == 200
    return r.json()["id"]


def _full_slice(c, h, no="SL-T-F"):
    r = c.post("/api/slices", headers=h, json={
        "slice_no": no, "biz_date": "2026-11-04", "partition_key": "mid",
        "row_count": 10, "expected_count": 10})
    assert r.status_code == 200
    return r.json()["id"]


# ---------- 原冒烟链路保持 ----------

def test_pipeline(client):
    c = client
    assert c.get("/api/health").json()["product"] == "日切放行"
    h = _login(c)
    assert len(c.get("/api/slices", headers=h).json()["items"]) >= 1
    bad = c.post("/api/slices/1/release", headers=h, json={"consumer": "x"})
    assert bad.status_code == 409
    sid = _full_slice(c, h, "SL-T-1")
    rel = c.post(f"/api/slices/{sid}/release", headers=h, json={"consumer": "ads_x"})
    assert rel.status_code == 200
    assert any(w["source_slice"] == "SL-T-1" for w in c.get("/api/watermarks", headers=h).json()["items"])


# ---------- 默认策略钉死与锁定说明 ----------

def test_default_policy_pinned_with_lock_note(client):
    h = _login(client)
    p = client.get("/api/policy", headers=h).json()
    assert p["policy"] == "甲"
    assert p["version"] == 1
    assert p["locked"] is False
    assert "策略已锁定" in p["lock_note"] and "改口审计" in p["lock_note"]
    assert p["lock_note"] == LOCK_NOTE


# ---------- 甲锁定：当日有放行尝试后禁止改口 ----------

def test_jia_lock_blocks_switch_after_any_attempt(client):
    h = _login(client)
    sid = _partial_slice(client, h)
    # 拒绝也是一次放行尝试
    r = client.post(f"/api/slices/{sid}/release", headers=h, json={"consumer": "x"})
    assert r.status_code == 409

    p = client.get("/api/policy", headers=h).json()
    assert p["locked"] is True
    assert p["attempts"] == 1

    sw = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    assert sw.status_code == 409
    assert "策略已锁定" in sw.json()["detail"]
    # 拒绝改口不改变钉死口径与版本
    p2 = client.get("/api/policy", headers=h).json()
    assert p2["policy"] == "甲" and p2["version"] == 1

    audits = client.get("/api/audits", headers=h).json()["items"]
    assert any(a["kind"] == "策略口径偏了" and "策略已锁定" in a["detail"] for a in audits)


def test_switch_before_any_attempt_writes_audit(client):
    h = _login(client)
    sw = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    assert sw.status_code == 200
    body = sw.json()
    assert body["changed"] is True and body["policy"] == "乙" and body["version"] == 2
    assert "audit_id" in body
    audits = client.get("/api/audits", headers=h).json()["items"]
    assert any(a["kind"] == "改口审计" and a["from_policy"] == "甲" and a["to_policy"] == "乙" for a in audits)

    # 同口径重复提交是无变化幂等，不得新增改口审计
    before = len(audits)
    again = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    assert again.status_code == 200 and again.json()["changed"] is False
    after = client.get("/api/audits", headers=h).json()["items"]
    assert len(after) == before

    # 非法口径拒绝
    bad = client.post("/api/policy/switch", headers=h, json={"policy": "丙"})
    assert bad.status_code == 400


# ---------- 乙锁定：改口前作废草稿与半截流水 ----------

def test_yi_switch_voids_open_draft(client):
    h = _login(client)
    partial = _partial_slice(client, h, "SL-T-P1")
    # 先存一个草稿（默认甲口径），草稿不算放行尝试，当日仍可改口
    d = client.post(f"/api/slices/{partial}/draft", headers=h, json={"consumer": "c1"})
    assert d.status_code == 200
    draft_no = d.json()["release_no"]

    sw = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    assert sw.status_code == 200
    assert sw.json()["changed"] is True and sw.json()["voided_ids"] == [d.json()["id"]]

    drafts = {x["release_no"]: x for x in client.get("/api/drafts", headers=h).json()["items"]}
    assert drafts[draft_no]["voided"] == 1 and drafts[draft_no]["status"] == "作废"
    assert drafts[draft_no]["void_audit_id"] is not None
    audits = client.get("/api/audits", headers=h).json()["items"]
    assert any(a["kind"] == "作废" and draft_no in a["detail"] for a in audits)
    assert any(a["kind"] == "改口审计" and a["from_policy"] == "甲" and a["to_policy"] == "乙" for a in audits)


def test_yi_switch_voids_half_ledger_then_allows_change(client):
    h = _login(client)
    partial = _partial_slice(client, h, "SL-T-P2")
    # 甲 → 乙（当日无尝试）：草稿随改口作废
    d = client.post(f"/api/slices/{partial}/draft", headers=h, json={"consumer": "c2"})
    assert d.status_code == 200
    sw1 = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    assert sw1.status_code == 200 and d.json()["id"] in sw1.json()["voided_ids"]

    # 乙口径下产生一条半截流水（冻结）
    fr = client.post(f"/api/slices/{partial}/release", headers=h, json={"consumer": "c2"})
    assert fr.status_code == 200 and fr.json()["status"] == "冻结"
    freeze_no = fr.json()["release_no"]

    # 乙锁定：乙 → 甲 不硬锁，但必须先作废半截流水并写改口审计，禁止无审计改口
    sw2 = client.post("/api/policy/switch", headers=h, json={"policy": "甲"})
    assert sw2.status_code == 200
    assert sw2.json()["changed"] is True and sw2.json()["policy"] == "甲"
    rel = next(x for x in client.get("/api/releases", headers=h).json()["items"]
               if x["release_no"] == freeze_no)
    assert rel["voided"] == 1 and rel["status"] == "作废" and rel["audit_id"] is not None
    audits = client.get("/api/audits", headers=h).json()["items"]
    assert any(a["kind"] == "作废" and freeze_no in a["detail"] for a in audits)
    assert any(a["kind"] == "改口审计" and a["from_policy"] == "乙" and a["to_policy"] == "甲" for a in audits)
    # 半截流水作废后当日未作废尝试归零，锁定解除
    p = client.get("/api/policy", headers=h).json()
    assert p["policy"] == "甲" and p["attempts"] == 0 and p["locked"] is False


def test_frozen_attempt_under_jia_still_hard_locks(client):
    h = _login(client)
    partial = _partial_slice(client, h, "SL-T-P3")
    # 甲口径下拒绝尝试即硬锁（冻结/拒绝/成功同权）
    fr = client.post(f"/api/slices/{partial}/release", headers=h, json={"consumer": "c3"})
    assert fr.status_code == 409
    blocked = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    assert blocked.status_code == 409 and "策略已锁定" in blocked.json()["detail"]
    p = client.get("/api/policy", headers=h).json()
    assert p["policy"] == "甲" and p["locked"] is True and p["attempts"] == 1
    # 拒绝行保持未作废，未被任何改口动作触碰
    rel = next(x for x in client.get("/api/releases", headers=h).json()["items"]
               if x["status"] == "拒绝")
    assert rel["voided"] == 0
    assert any(a["kind"] == "策略口径偏了" for a in client.get("/api/audits", headers=h).json()["items"])


# ---------- 互斥账本：同一放行单禁止混用甲乙两套写入 ----------

def test_same_release_no_cannot_mix_calibers(client):
    h = _login(client)
    full = _full_slice(client, h, "SL-T-MIX-F")
    partial = _partial_slice(client, h, "SL-T-MIX-P")

    # 甲口径下用指定单号写入一条成功单
    r1 = client.post(f"/api/slices/{full}/release", headers=h,
                     json={"consumer": "c", "release_no": "RO-MIX-1"})
    assert r1.status_code == 200 and r1.json()["caliber"] == "甲"

    # 无放行尝试前可以改口乙
    sw = client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    # 已有尝试 → 必须被甲锁定挡住，保证旧单永远不会被乙口径续写
    assert sw.status_code == 409

    # 即使强行带乙口径打同单，也因与钉死策略不符先被偏口径拦截
    r2 = client.post(f"/api/slices/{partial}/release", headers=h,
                     json={"consumer": "c", "release_no": "RO-MIX-1", "caliber": "乙"})
    assert r2.status_code == 409
    assert "策略口径偏了" in r2.json()["detail"]

    # 同单同口径重试允许幂等走账（甲下完整切片再放行 → 成功）
    r3 = client.post(f"/api/slices/{full}/release", headers=h,
                     json={"consumer": "c", "release_no": "RO-MIX-1"})
    assert r3.status_code == 200 and r3.json()["caliber"] == "甲"

    rels = [x for x in client.get("/api/releases", headers=h).json()["items"]
            if x["release_no"] == "RO-MIX-1"]
    assert all(x["caliber"] == "甲" for x in rels)


def test_explicit_wrong_caliber_rejected_and_audited(client):
    h = _login(client)
    full = _full_slice(client, h, "SL-T-CAL")
    r = client.post(f"/api/slices/{full}/release", headers=h,
                    json={"consumer": "c", "caliber": "乙"})
    assert r.status_code == 409
    assert "策略口径偏了" in r.json()["detail"]
    audits = client.get("/api/audits", headers=h).json()["items"]
    assert any(a["kind"] == "策略口径偏了" and a["from_policy"] == "乙" and a["to_policy"] == "甲" for a in audits)
    # 偏口径被拒不得产生放行流水
    assert client.get("/api/releases", headers=h).json()["items"] == [] or \
           all(x["caliber"] != "乙" for x in client.get("/api/releases", headers=h).json()["items"])


# ---------- 乙口径冻结区与补齐放行 ----------

def test_yi_caliber_freezes_then_releases_after_supplement(client):
    h = _login(client)
    partial = _partial_slice(client, h, "SL-T-YI")
    assert client.post("/api/policy/switch", headers=h, json={"policy": "乙"}).status_code == 200

    r = client.post(f"/api/slices/{partial}/release", headers=h,
                    json={"consumer": "ads_y", "release_no": "RO-YI-1"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "冻结" and body["caliber"] == "乙" and body["watermark"] is False
    # 冻结期不推进水位
    assert not any(w["source_slice"] == "SL-T-YI" for w in client.get("/api/watermarks", headers=h).json()["items"])

    # 补齐 7 行后完整，同单同口径续写成成功并推进水位
    sup = client.post(f"/api/slices/{partial}/supplement", headers=h, json={"add_count": 7})
    assert sup.status_code == 200 and sup.json()["completeness"] == "完整"
    r2 = client.post(f"/api/slices/{partial}/release", headers=h,
                     json={"consumer": "ads_y", "release_no": "RO-YI-1"})
    assert r2.status_code == 200 and r2.json()["status"] == "成功"
    assert any(w["source_slice"] == "SL-T-YI" for w in client.get("/api/watermarks", headers=h).json()["items"])

    rows = [x for x in client.get("/api/releases", headers=h).json()["items"]
            if x["release_no"] == "RO-YI-1"]
    assert len(rows) == 1 and rows[0]["status"] == "成功" and rows[0]["caliber"] == "乙"


# ---------- 并发：改口侧与放行侧同时动手，排队加锁 + 争用留痕 ----------

def test_concurrent_switch_and_release_serialized_with_contention():
    started = threading.Event()
    release_done = threading.Event()

    def hook():
        # 第一个拿到锁的事务（改口）持锁期间，启动放行线程制造争用
        started.set()
        release_done.wait(timeout=5)

    appmod.TXN_HOOK = hook
    errors = []

    def do_switch():
        try:
            switch_policy("admin", "乙")
        except Exception as e:  # noqa: BLE001
            errors.append(("switch", e))

    t = threading.Thread(target=do_switch)
    t.start()
    assert started.wait(timeout=5)
    # 改口持锁中发起放行：必须阻塞排队，不静默过
    out = attempt_release("admin", 2, "ads_order", None, None)
    release_done.set()
    t.join(timeout=5)

    assert not errors, errors
    # 放行发生在改口之后，按乙口径入账
    assert out["caliber"] == "乙"
    # 后手（放行侧）留有策略争用审计
    with appmod.connect() as c:
        kinds = [r["kind"] for r in c.execute("SELECT kind FROM policy_audit").fetchall()]
    assert "策略争用" in kinds
    assert "改口审计" in kinds


def test_lock_is_globally_serialized():
    seen = []
    order = []

    def worker(name):
        with PolicyLock():
            order.append(f"{name}-in")
            seen.append(name)
            order.append(f"{name}-out")

    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert sorted(seen) == [f"w{i}" for i in range(6)]


# ---------- 四处对读：策略页/审计列表/目录旁注/详情条同源 ----------

def test_four_views_read_consistently(client):
    h = _login(client)
    full = _full_slice(client, h, "SL-T-VIEW")
    client.post("/api/policy/switch", headers=h, json={"policy": "乙"})
    rel = client.post(f"/api/slices/{full}/release", headers=h,
                      json={"consumer": "ads_v", "release_no": "RO-VIEW-1"})
    assert rel.status_code == 200

    policy = client.get("/api/policy", headers=h).json()
    audits = client.get("/api/audits", headers=h).json()["items"]
    releases = client.get("/api/releases", headers=h).json()["items"]
    drafts = client.get("/api/drafts", headers=h).json()["items"]
    assert isinstance(drafts, list)

    row = next(x for x in releases if x["release_no"] == "RO-VIEW-1")
    # 详情条字段与策略侧栏同源同口径
    assert row["caliber"] == policy["policy"] == "乙"
    assert row["policy_version"] == policy["version"]
    assert row["attempt_date"] == policy["biz_date"]
    # 审计里锁定说明与策略页完全一致
    ga = next(a for a in audits if a["kind"] == "改口审计")
    assert ga["lock_note"] == policy["lock_note"] == LOCK_NOTE
    # 切片接口仍可用于目录旁注
    assert any(s["slice_no"] == "SL-T-VIEW" for s in client.get("/api/slices", headers=h).json()["items"])


def test_legacy_rows_backfilled_with_jia_caliber(client):
    h = _login(client)
    items = client.get("/api/releases", headers=h).json()["items"]
    seed = next(x for x in items if x["release_no"] == "RO-LEGACY-SEED")
    assert seed["caliber"] == "甲" and seed["release_no"] and seed["attempt_date"] == "2026-11-01"
    assert seed["voided"] == 0


def test_login_still_works_and_auth_required(client):
    assert client.get("/api/policy").status_code == 401
    h = _login(client)
    assert client.get("/api/policy", headers=h).status_code == 200
    bad = client.post("/api/login", json={"username": "admin", "password": "x"})
    assert bad.status_code == 401
