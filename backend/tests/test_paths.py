"""Path finding over the relationship graph."""
from app.api.paths import find_paths

GRAPH = {
    "actor:A": ["victim:X", "ioc:1"],
    "victim:X": ["actor:A", "actor:B"],
    "ioc:1": ["actor:A", "actor:B"],
    "actor:B": ["victim:X", "ioc:1", "malware:M"],
    "malware:M": ["actor:B", "actor:C"],
    "actor:C": ["malware:M", "victim:Y"],
    "victim:Y": ["actor:C", "actor:D"],
    "actor:D": ["victim:Y", "victim:Z"],
    "victim:Z": ["actor:D", "actor:E"],
    "actor:E": ["victim:Z"],
    "lonely": [],
}
nb = lambda n: {x: ("finding", f"{n}-{x}") for x in GRAPH.get(n, [])}  # noqa: E731


def test_shortest_paths_including_equally_short_ones():
    paths, _ = find_paths("actor:A", "actor:B", nb)
    assert sorted(paths) == [["actor:A", "ioc:1", "actor:B"], ["actor:A", "victim:X", "actor:B"]]  # both two-hop routes
    paths, _ = find_paths("actor:A", "actor:C", nb)
    # A -(X or 1)- B - M - C: four hops, five nodes, two routes
    assert all(len(p) == 5 and p[0] == "actor:A" and p[-1] == "actor:C" and "malware:M" in p for p in paths) and len(paths) == 2


def test_limits_and_dead_ends():
    assert find_paths("actor:A", "actor:A", nb)[0] == [["actor:A"]]
    assert find_paths("actor:A", "lonely", nb)[0] == []
    # A - X - B - M - C - Y - D is six hops away
    assert find_paths("actor:A", "actor:D", nb, max_hops=5)[0] == []
    assert len(find_paths("actor:A", "actor:D", nb, max_hops=6)[0][0]) == 7
    assert find_paths("actor:A", "actor:D", nb, max_hops=6, budget=1)[0] == []  # the expansion budget is respected
