# language: Python 3.11+, file: tests/test_store_perf.py
# *batch apis, junction queries, status funnel — one writer, no N+1*
import time

import pytest

from cf.store import VALID_STATUSES, Store


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "c.db"))
    yield s
    s.close()


def _campaign_with_targets(store: Store, name: str, n: int):
    cid = store.create_campaign(name, base_url="http://h")
    tokens = store.add_targets(
        [{"campaign_id": cid, "email": f"u{i}@corp.tld"} for i in range(n)]
    )
    return cid, tokens


# ─── batch inserts ───


def test_add_targets_batch_one_roundtrip(store):
    cid, tokens = _campaign_with_targets(store, "batch", 50)
    assert len(tokens) == 50
    assert all(len(t) == 16 for t in tokens)
    assert store.count_targets(cid) == 50


def test_log_events_batch_count(store):
    cid, tokens = _campaign_with_targets(store, "evs", 3)
    n = store.log_events(
        [
            {
                "beacon_id": f"b{i}",
                "campaign_id": cid,
                "kind": "test",
                "payload": f"p{i}",
            }
            for i in range(25)
        ]
    )
    assert n == 25
    evs = store.events(cid, limit=100)
    assert len(evs) == 25


def test_record_hits_batch(store):
    cid, tokens = _campaign_with_targets(store, "hits", 4)
    rows = [
        {"token": t, "kind": "lure", "ip": "1.1.1.1", "ua": "ua"} for t in tokens
    ]
    rows.append({"token": tokens[0], "kind": "pixel", "ip": "2.2.2.2"})
    assert store.record_hits(rows) == 5
    assert len(store.campaign_hits(cid)) == 5


# ─── campaign-scoped hit queries (the N+1 kills) ───


def test_campaign_hits_join_scopes_to_campaign(store):
    cid_a, tok_a = _campaign_with_targets(store, "a", 2)
    cid_b, tok_b = _campaign_with_targets(store, "b", 2)
    for t in tok_a:
        store.record_hit(t, "lure", ip="1.2.3.4")
    for t in tok_b:
        store.record_hit(t, "pixel", ip="9.9.9.9")
    hits_a = store.campaign_hits(cid_a)
    assert len(hits_a) == 2
    assert {h["ip"] for h in hits_a} == {"1.2.3.4"}
    hits_b = store.campaign_hits(cid_b)
    assert len(hits_b) == 2
    assert {h["ip"] for h in hits_b} == {"9.9.9.9"}


def test_campaign_hits_since_cutoff_filters_and_sorts(store):
    cid, tokens = _campaign_with_targets(store, "since", 2)
    old = time.time() - 7200
    recent = time.time() - 60
    store.record_hits(
        [
            {"token": tokens[0], "kind": "lure", "created_at": old},
            {"token": tokens[1], "kind": "lure", "created_at": recent},
        ]
    )
    hits = store.campaign_hits_since(cid, time.time() - 3600)
    assert len(hits) == 1
    assert hits[0]["kind"] == "lure"
    assert hits[0]["created_at"] >= time.time() - 3600


def test_empty_campaign_hit_queries(store):
    cid, _ = _campaign_with_targets(store, "empty", 1)
    assert store.campaign_hits(cid) == []
    assert store.campaign_hits_since(cid, time.time()) == []


# ─── counts ───


def test_counts_empty_and_filled(store):
    assert store.count_campaigns() == 0
    cid_a, tok_a = _campaign_with_targets(store, "x", 3)
    cid_b, _ = _campaign_with_targets(store, "y", 2)
    assert store.count_campaigns() == 2
    assert store.count_targets(cid_a) == 3
    assert store.count_targets(cid_b) == 2


# ─── status funnel ───


def test_set_status_many_updates_in_bulk(store):
    cid, tokens = _campaign_with_targets(store, "st", 5)
    assert store.set_status_many(tokens[:3], "clicked") == 3
    rows = store.targets(cid)
    clicked = {r["token"] for r in rows if r["status"] == "clicked"}
    assert clicked == set(tokens[:3])


def test_set_status_many_rejects_unknown_status(store):
    cid, tokens = _campaign_with_targets(store, "st2", 1)
    with pytest.raises(ValueError):
        store.set_status_many(tokens, "smurf")
    with pytest.raises(ValueError):
        store.set_status_many([], "not-a-status")


def test_set_status_many_chunks_over_sqlite_var_ceiling(store):
    # 1200 tokens means three 500-chunks — the variable-limit path must
    # not drop the tail
    cid, tokens = _campaign_with_targets(store, "big", 1200)
    n = store.set_status_many(tokens, "delivered")
    assert n == 1200
    assert all(r["status"] == "delivered" for r in store.targets(cid))


def test_funnel_transitions_respect_report_order(store):
    cid, tokens = _campaign_with_targets(store, "funnel", 1)
    from cf.report import _ORDER

    assert _ORDER[0] == "created"
    # delivered (the stager reply) can only follow a click
    assert _ORDER.index("delivered") > _ORDER.index("clicked")
    assert set(VALID_STATUSES) == set(_ORDER)


def test_status_unknown_campaign_is_an_error_value(store):
    st = store.status("nope")
    assert st.get("error") or st.get("targets") == 0
