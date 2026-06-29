from schema import Finding, Location, Evidence
from pipeline.consensus import cluster


def mk(lane, model, file, s, e, cwe="CWE-89", sink="db.query"):
    return Finding(task_id="t", lane_id=lane, model=model, title="x", cwe=cwe,
                   location=Location(file, s, e, sink=sink))


def test_overlapping_lines_same_key_merge():
    fs = [mk("l1", "claude", "a/x.js", 40, 44), mk("l2", "gpt-5", "a/x.js", 43, 47)]
    cs = cluster(fs, line_tolerance=10)
    assert len(cs) == 1
    assert cs[0].support == 2
    assert cs[0].family_support == 2  # anthropic + openai


def test_distant_lines_do_not_merge():
    fs = [mk("l1", "claude", "a/x.js", 40, 41), mk("l2", "claude", "a/x.js", 400, 401)]
    cs = cluster(fs, line_tolerance=10)
    assert len(cs) == 2


def test_different_cwe_class_does_not_merge():
    fs = [mk("l1", "claude", "a/x.js", 40, 44, cwe="CWE-89"),
          mk("l2", "claude", "a/x.js", 40, 44, cwe="CWE-79")]
    cs = cluster(fs)
    assert len(cs) == 2  # injection vs xss are different classes


def test_same_family_counts_one_family():
    fs = [mk("l1", "claude-opus-4-8", "a/x.js", 40, 44),
          mk("l2", "claude-sonnet-4-6", "a/x.js", 41, 45)]
    cs = cluster(fs)
    assert len(cs) == 1
    assert cs[0].support == 2          # two lanes
    assert cs[0].family_support == 1   # but one family -> not independent corroboration
