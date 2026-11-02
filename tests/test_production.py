"""Settings, auth, limits, headers, metrics, health, money, persistence, key rotation and migrations."""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import text

from cbdcguard import db, ops
from cbdcguard.ledger import CBDCLedger, build_demo_ledger

I32 = base64.b64encode(b"i" * 32).decode()
W32 = base64.b64encode(b"w" * 32).decode()
KEY = "cbdcguard_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "rbi-ops", "role": "admin"}}
KEYS = {"k-iss": {"user": "issue-dept", "role": "issuer"}, "k-pay": {"user": "psp", "role": "payments"},
        "k-aud": {"user": "asha", "role": "auditor"}, "k-mon": {"user": "prom", "role": "monitor"},
        "k-admin": {"user": "root", "role": "admin"}}


def prod_env(**over):
    env = {"CBDCGUARD_ENV": "production", "CBDCGUARD_API_KEYS": json.dumps(HASHED), "CBDCGUARD_ISSUER_KEY": I32,
           "CBDCGUARD_WALLET_KEY": W32, "CBDCGUARD_DATABASE_URL": "sqlite://"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("CBDCGUARD_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"CBDCGUARD_{k}", v)
    import cbdcguard.api as api

    return importlib.reload(api)


def test_production_settings_accepted():
    s = ops.load_settings(prod_env())
    assert s.production and not s.demo and s.secret["ISSUER_KEY"] == b"i" * 32 and not s.ephemeral


@pytest.mark.parametrize("change, message", [
    ({"CBDCGUARD_API_KEYS": None}, "API keys"),
    ({"CBDCGUARD_ISSUER_KEY": None}, "ISSUER_KEY"),
    ({"CBDCGUARD_WALLET_KEY": None}, "WALLET_KEY"),
    ({"CBDCGUARD_DATABASE_URL": None}, "DATABASE_URL"),
    ({"CBDCGUARD_API_KEYS": json.dumps({KEY: {"user": "x", "role": "admin"}})}, "sha256"),
    ({"CBDCGUARD_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"CBDCGUARD_ISSUER_KEY": base64.b64encode(b"short").decode()}, "32 bytes"),
    ({"CBDCGUARD_WALLET_KEY": base64.b64encode(b"w" * 48).decode()}, "32 bytes"),
    ({"CBDCGUARD_ISSUER_KEY_PREVIOUS": base64.b64encode(b"p" * 40).decode()}, "32 bytes"),
    ({"CBDCGUARD_WALLET_KEY": "not base64!"}, "base64"),
    ({"CBDCGUARD_CORS_ORIGINS": "*"}, "CORS"),
    ({"CBDCGUARD_ENV": "prod"}, "development or production"),
    ({"CBDCGUARD_DATABASE_URL": "mysql://x"}, "postgresql"),
])
def test_production_refuses_to_start(change, message):
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings(prod_env(**change))


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"CBDCGUARD_HOST": "0.0.0.0"})
    assert ops.load_settings({"CBDCGUARD_HOST": "0.0.0.0", "CBDCGUARD_API_KEYS": json.dumps(HASHED)}).host == "0.0.0.0"
    dev = ops.load_settings({})
    assert dev.demo and set(dev.ephemeral) == {"ISSUER_KEY", "WALLET_KEY"} and dev.port == 8018


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("CBDCGUARD_")}
    r = subprocess.run([sys.executable, "-m", "cbdcguard", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "configuration error" in r.stderr and "without API keys" in r.stderr


def test_roles_decide_what_a_key_may_do(monkeypatch):
    api = boot(monkeypatch, API_KEYS=json.dumps(KEYS))
    c = TestClient(api.app)
    spend = {"utxo_id": "UTXO-FOOD-102", "merchant_id": "M-FOOD-MUM", "amount": "100.00"}
    assert c.get("/state").status_code == 401
    assert c.get("/state", headers={"x-api-key": "wrong"}).status_code == 401
    assert c.get("/state", headers={"x-api-key": "k-aud"}).status_code == 200
    assert c.post("/cbdc/transfer", json=spend, headers={"x-api-key": "k-aud"}).status_code == 403
    assert c.post("/cbdc/mint", json={"owner_id": "X", "amount": 10}, headers={"x-api-key": "k-pay"}).status_code == 403
    assert c.post("/cbdc/transfer", json=spend, headers={"x-api-key": "k-pay"}).status_code == 200
    assert c.post("/cbdc/mint", json={"owner_id": "X", "amount": 10}, headers={"authorization": "Bearer k-iss"}).status_code == 200
    assert c.post("/offline/sync", headers={"x-api-key": "k-pay"}).status_code == 403
    assert c.post("/offline/sync", headers={"x-api-key": "k-iss"}).status_code == 200
    assert c.post("/reset", headers={"x-api-key": "k-iss"}).status_code == 403
    assert c.get("/bench", headers={"x-api-key": "k-iss"}).status_code == 403
    assert c.get("/metrics", headers={"x-api-key": "k-pay"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'http_requests_total{method="POST",route="/cbdc/transfer",status="200"}' in m.text
    assert 'cbdcguard_decisions_total{decision="approved"}' in m.text and "errors_total" in m.text


def test_money_is_exact_paise(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    uid = f"UTXO-M-{uuid.uuid4().hex[:6]}"
    r = c.post("/cbdc/mint", json={"owner_id": "F", "amount": "6000.10", "utxo_id": uid})
    assert r.status_code == 200 and r.json()["utxo"]["amount_paise"] == 600_010 and r.json()["utxo"]["amount"] == "6000.10"
    t = c.post("/cbdc/transfer", json={"utxo_id": uid, "merchant_id": "M-AGRI-PUNE", "amount": 0.3})
    assert t.json()["amount_paise"] == 30 and t.json()["approved"]
    change = c.get("/state").json()["utxos"]
    assert {"utxo_id": t.json()["change_utxo_id"], "amount_paise": 599_980} in [{k: u[k] for k in ("utxo_id", "amount_paise")} for u in change]
    for bad in ("0.001", "NaN", "Infinity", "-5", "1e12", "abc"):
        assert c.post("/cbdc/mint", json={"owner_id": "F", "amount": bad}).status_code == 422, bad
    assert c.post("/cbdc/mint", json={"owner_id": "F", "amount": 10, "utxo_id": uid}).status_code == 400  # reused ID


def test_rate_limit(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.get("/state").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    assert int(c.get("/state").headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200  # probes are never limited


def test_body_size_cap(monkeypatch):
    c = TestClient(boot(monkeypatch, MAX_BODY_BYTES="1000").app)
    assert c.post("/cbdc/mint", json={"owner_id": "F" * 1200, "amount": 1}).status_code == 413

    def chunks():  # no content-length: the cap still holds
        for _ in range(20):
            yield b"a" * 100

    assert c.post("/cbdc/mint", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    assert c.post("/cbdc/sweep", json={}).status_code == 200


def test_headers_and_request_ids(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    r = c.get("/state", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == ops.API_CSP and r.headers["cache-control"] == "no-store"
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert len(c.get("/healthz", headers={"x-request-id": "bad id\n"}).headers["x-request-id"]) == 32
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_cors_only_for_listed_origins(monkeypatch):
    c = TestClient(boot(monkeypatch, CORS_ORIGINS="https://console.bank.example").app)
    ok = c.get("/healthz", headers={"origin": "https://console.bank.example"})
    assert ok.headers["access-control-allow-origin"] == "https://console.bank.example"
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_errors_do_not_leak(monkeypatch):
    api = boot(monkeypatch)

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: wallet secret 0xdeadbeef")

    c = TestClient(api.app)
    r = c.get("/boom")
    assert r.status_code == 500 and "deadbeef" not in r.text and r.json()["request_id"] == r.headers["x-request-id"]
    bad = c.post("/cbdc/mint", json={"owner_id": "F", "amount": "98765432101234"})
    assert bad.status_code == 422 and "98765432101234" not in bad.text
    assert c.post("/cbdc/mint", content=b"{not json", headers={"content-type": "application/json"}).status_code == 422


def test_health_and_readiness(monkeypatch):
    api = boot(monkeypatch)
    c = TestClient(api.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": True}
    api.store.dispose()
    monkeypatch.setattr(api.store, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["database"] is False and "db down" not in r.text


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello", extra={"fields": {"n": 1}})
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["n"] == 1 and line["level"] == "INFO"


def test_production_warns_and_refuses_reset(monkeypatch, tmp_path, capsys):
    env = {k.removeprefix("CBDCGUARD_"): v for k, v in prod_env(CBDCGUARD_DATABASE_URL=f"sqlite:///{tmp_path / 'p.db'}").items()}
    api = boot(monkeypatch, **env, ACCEPT_UNREVIEWED_CRYPTO="yes")
    warnings = [json.loads(line) for line in capsys.readouterr().out.splitlines() if "UNREVIEWED" in line]
    assert warnings and warnings[0]["level"] == "WARNING" and "cryptographer" in warnings[0]["msg"]
    c = TestClient(api.app)
    assert c.post("/reset", headers={"x-api-key": KEY}).status_code == 403
    assert "reviewed" in c.post("/offline/sync", headers={"x-api-key": KEY}).json()["warning"]


def test_production_refuses_unreviewed_crypto_without_consent(monkeypatch, tmp_path):
    env = {k.removeprefix("CBDCGUARD_"): v for k, v in prod_env(CBDCGUARD_DATABASE_URL=f"sqlite:///{tmp_path / 'c.db'}").items()}
    with pytest.raises(ops.ConfigError, match="CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO=yes"):
        boot(monkeypatch, **env)
    with pytest.raises(ops.ConfigError, match="reviewed by a cryptographer"):
        boot(monkeypatch, **env, ACCEPT_UNREVIEWED_CRYPTO="no")
    # through `serve` too: the error is raised while uvicorn imports the app
    run_env = {k: v for k, v in os.environ.items() if not k.startswith("CBDCGUARD_")}
    run_env.update(prod_env(CBDCGUARD_DATABASE_URL=f"sqlite:///{tmp_path / 'c.db'}"))
    r = subprocess.run([sys.executable, "-m", "cbdcguard", "serve", "--port", "1"], env=run_env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0 and "configuration error" in r.stderr and "ACCEPT_UNREVIEWED_CRYPTO" in r.stderr


def _url(tmp_path):
    return os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'ledger.db'}"


def test_ledger_survives_a_restart(monkeypatch, tmp_path):
    url, run = _url(tmp_path), uuid.uuid4().hex[:6].upper()
    keys = {"DATABASE_URL": url, "ISSUER_KEY": I32, "WALLET_KEY": W32}
    c = TestClient(boot(monkeypatch, **keys).app)
    uid, wid, coin = f"UTXO-R-{run}", f"W-R-{run}", f"COIN-R-{run}"
    assert c.post("/cbdc/mint", json={"owner_id": "F", "amount": "5000", "utxo_id": uid}).status_code == 200
    t = c.post("/cbdc/transfer", json={"utxo_id": uid, "merchant_id": "M-AGRI-PUNE", "amount": "1200.50"}).json()
    api = boot(monkeypatch, **keys)
    api.LEDGER.register_offline_wallet(wid, "Restart Test", collateral_paise=100_000)
    api.LEDGER.mint_offline_coin(wid, 30_000, coin_id=coin)
    before = api.LEDGER.merchant("M-FOOD-MUM").balance_paise
    c = TestClient(api.app)
    assert c.post("/offline/spend", json={"wallet_id": wid, "coin_id": coin, "merchant_id": "M-FOOD-MUM"}).status_code == 200

    api = boot(monkeypatch, **keys)  # restart: same database and keys
    c = TestClient(api.app)
    assert c.get("/state").status_code == 200 and api.LEDGER.utxo(uid).status == "SPENT"
    assert api.LEDGER.utxo(t["change_utxo_id"]).amount_paise == 500_000 - 120_050
    assert c.post("/cbdc/transfer", json={"utxo_id": uid, "merchant_id": "M-AGRI-PUNE"}).status_code == 400  # still spent
    sync = c.post("/offline/sync").json()  # the packet queued before the restart
    assert coin in [p["coin_id"] for p in sync["settled_packets"]]
    # the wallet secrets were sealed in the database, so a double spend after a restart still unmasks the wallet
    assert c.post("/offline/spend", json={"wallet_id": wid, "coin_id": coin, "merchant_id": "M-AGRI-PUNE",
                                          "simulate_double_spend": True}).status_code == 200
    alert = c.post("/offline/sync").json()["double_spend_alerts"][0]
    assert alert["wallet_id"] == wid and alert["verified_against_commitment"] and alert["slashed_paise"] == 60_000
    led = CBDCLedger(engine=db.connect(url), issuer_key=Ed25519PrivateKey.from_private_bytes(b"i" * 32), wallet_key=b"w" * 32)
    assert led.merchant("M-FOOD-MUM").balance_paise == before + 30_000
    assert led.wallet(wid).collateral_paise == 40_000 and led.wallet(wid).slashed


def test_key_rotation(tmp_path):
    url = _url(tmp_path)
    old_i, new_i = Ed25519PrivateKey.from_private_bytes(b"1" * 32), Ed25519PrivateKey.from_private_bytes(b"2" * 32)
    run = uuid.uuid4().hex[:6].upper()
    a = CBDCLedger(engine=db.connect(url), issuer_key=old_i, wallet_key=b"a" * 32)
    if a.merchant("M-ROT") is None:
        from cbdcguard.ledger import MerchantProfile
        a.register_merchant(MerchantProfile("M-ROT", "Rotation", 5411, "Grocery", "IN-MH"))
    a.register_offline_wallet(f"W-ROT-{run}", "Rotation", 10_000)
    a.mint_offline_coin(f"W-ROT-{run}", 1_000, coin_id=f"C-ROT-{run}")
    a.execute_offline_spend(f"W-ROT-{run}", f"C-ROT-{run}", "M-ROT", nonce="n1")
    a.mint_offline_coin(f"W-ROT-{run}", 1_000, coin_id=f"C-ROT2-{run}")

    no_prev = CBDCLedger(engine=db.connect(url), issuer_key=new_i, wallet_key=b"b" * 32)
    with pytest.raises(ValueError, match="unseal"):  # new wallet key alone can't read the old secrets
        no_prev.execute_offline_spend(f"W-ROT-{run}", f"C-ROT2-{run}", "M-ROT", nonce="n2")
    rotated = CBDCLedger(engine=db.connect(url), issuer_key=new_i, wallet_key=b"b" * 32,
                         previous_issuer_keys=(old_i,), previous_wallet_keys=(b"a" * 32,))
    rotated.execute_offline_spend(f"W-ROT-{run}", f"C-ROT2-{run}", "M-ROT", nonce="n2")
    report = rotated.sync_offline_batch()  # coins signed by the old issuer key still settle
    assert {p["coin_id"] for p in report["settled_packets"]} >= {f"C-ROT-{run}", f"C-ROT2-{run}"}


def test_replicas_cannot_double_pay(tmp_path):
    url = _url(tmp_path)
    keys = {"issuer_key": Ed25519PrivateKey.from_private_bytes(b"i" * 32), "wallet_key": b"w" * 32}
    run = uuid.uuid4().hex[:6].upper()
    a = CBDCLedger(engine=db.connect(url), **keys)
    b = CBDCLedger(engine=db.connect(url), **keys)  # a second replica, same database
    a.mint_utxo("F", 10_000, "PBM-GENERAL", utxo_id=f"U-REP-{run}")
    if a.merchant("M-REP") is None:
        from cbdcguard.ledger import MerchantProfile
        a.register_merchant(MerchantProfile("M-REP", "Replica", 5411, "Grocery", "IN-MH"))
    assert a.transfer_utxo(f"U-REP-{run}", "M-REP").approved
    with pytest.raises(ValueError, match="not spendable"):
        b.transfer_utxo(f"U-REP-{run}", "M-REP")
    a.register_offline_wallet(f"W-REP-{run}", "Replica", 10_000)
    a.mint_offline_coin(f"W-REP-{run}", 5_000, coin_id=f"C-REP-{run}")
    pkt = a.execute_offline_spend(f"W-REP-{run}", f"C-REP-{run}", "M-REP", nonce="n1")
    b.queue_packet(pkt)  # the terminal uploads it twice, to different replicas
    before = a.merchant("M-REP").balance_paise
    settled = len(b.sync_offline_batch()["settled_packets"]) + len(a.sync_offline_batch()["settled_packets"])
    assert settled == 1 and a.merchant("M-REP").balance_paise == before + 5_000


def test_demo_ledger_is_in_memory_and_independent():
    a, b = build_demo_ledger(), build_demo_ledger()
    a.transfer_utxo("UTXO-FOOD-102", "M-FOOD-MUM")
    assert a.utxo("UTXO-FOOD-102").status == "SPENT" and b.utxo("UTXO-FOOD-102").status == "UNSPENT"


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"]
    assert db.migrate(eng) == []
    with eng.connect() as c:
        assert [r[0] for r in c.execute(text("SELECT version FROM schema_migrations"))] == [1]
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"utxos", "transfers", "offline_wallets", "offline_coins", "offline_packets", "settled_coins"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("CBDCGUARD_")}, "CBDCGUARD_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "cbdcguard", "migrate"], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "up to date" in out.stdout
