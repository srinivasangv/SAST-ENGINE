"""The Code Property Graph and the small IR the taint engine walks.

Owner: Member 1 (Prepare / CPG).

Two things live here:

1. `CPG` -- a plain graph of nodes and edges. It is what we show on the
   dashboard ("we built 412 nodes and 690 edges from this repo without
   running a build") and it is how a finding is traced back to source.

2. The IR (`Function`, `Stmt`, `Expr`, `Call`) -- a tiny, language-neutral
   description of a function body. Both the Python parser and the
   JavaScript parser produce this, so the taint engine in stage2_scan.py
   is written once and works for both languages.

Everything is a dataclass, so `print(fn)` in a debugger shows you the whole
structure. There is no magic here on purpose.
"""

from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------
# 1. The graph
# --------------------------------------------------------------------------

# Node kinds we create. Keeping this list short keeps the graph readable.
NODE_KINDS = ("MODULE", "FUNCTION", "PARAM", "ASSIGN", "CALL", "RETURN", "IF", "LOOP", "ROUTE")

# Edge kinds:
#   AST   - structural containment (module -> function -> statement)
#   FLOW  - one statement runs after another
#   CALL  - an HTTP route points at the function that handles it
EDGE_KINDS = ("AST", "FLOW", "CALL")


@dataclass
class Node:
    id: int
    kind: str
    name: str
    file: str
    line: int
    code: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "name": self.name,
            "file": self.file, "line": self.line, "code": self.code,
        }


@dataclass
class Edge:
    src: int
    dst: int
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind}


class CPG:
    """A very small graph. Add nodes, add edges, ask for stats."""

    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []
        self._next_id = 1

    def add_node(self, kind: str, name: str, file: str, line: int, code: str = "") -> Node:
        node = Node(id=self._next_id, kind=kind, name=name, file=file, line=line, code=code)
        self._next_id += 1
        self.nodes.append(node)
        return node

    def add_edge(self, src: int, dst: int, kind: str) -> None:
        self.edges.append(Edge(src=src, dst=dst, kind=kind))

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for node in self.nodes:
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        edges_by_kind: dict[str, int] = {}
        for edge in self.edges:
            edges_by_kind[edge.kind] = edges_by_kind.get(edge.kind, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "nodes_by_kind": by_kind,
            "edges_by_kind": edges_by_kind,
        }

    def to_dict(self, limit: int = 300) -> dict[str, Any]:
        """A trimmed view for the dashboard -- the full graph is too big to render."""
        nodes = self.nodes[:limit]
        keep = {n.id for n in nodes}
        return {
            "stats": self.stats(),
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in self.edges if e.src in keep and e.dst in keep],
        }


# --------------------------------------------------------------------------
# 2. The IR
# --------------------------------------------------------------------------


@dataclass
class Call:
    """A function call found inside an expression.

    `name` is the dotted name as written in the source: "os.system",
    "cursor.execute", "child_process.exec". The rule tables in rules.py
    are matched against this string.
    """
    name: str
    line: int
    code: str
    args: list["Expr"] = field(default_factory=list)
    kwargs: dict[str, "Expr"] = field(default_factory=dict)


@dataclass
class Expr:
    """Everything the taint engine needs to know about a value.

    We deliberately do NOT keep a full expression tree. Flattening it into
    "which variables does this read, which source patterns does it match,
    which calls does it contain" is enough for taint analysis and is far
    easier for a reader to follow.
    """
    code: str = ""
    vars: list[str] = field(default_factory=list)      # variable names read
    sources: list[str] = field(default_factory=list)   # e.g. "request.args"
    calls: list[Call] = field(default_factory=list)    # calls inside this expression
    only_literal: bool = False                         # built purely from constants


@dataclass
class Stmt:
    """One statement in a function body.

    kind is one of: assign | expr | return | if | loop | try
    """
    kind: str
    line: int
    code: str
    targets: list[str] = field(default_factory=list)   # variables assigned
    value: Expr | None = None
    test: Expr | None = None                           # the condition of an if/while
    body: list["Stmt"] = field(default_factory=list)
    orelse: list["Stmt"] = field(default_factory=list)
    always_false: bool = False                         # `if False:` -- dead code


@dataclass
class Function:
    """One function, with everything Stage 2 needs to analyse it."""
    name: str
    file: str
    line: int
    end_line: int
    lang: str                                          # "python" | "javascript"
    params: list[str] = field(default_factory=list)
    body: list[Stmt] = field(default_factory=list)
    route_path: str = ""                               # "/run" if it handles an HTTP route
    route_methods: list[str] = field(default_factory=list)
    node_id: int = 0                                   # its node in the CPG

    @property
    def is_route(self) -> bool:
        """A route handler is directly reachable by an attacker over HTTP."""
        return bool(self.route_path)

    def entry_description(self) -> str:
        if self.is_route:
            methods = "|".join(self.route_methods) or "GET"
            return f"HTTP route {methods} {self.route_path} -> {self.name}()"
        return f"internal function {self.name}()"


@dataclass
class ParsedRepo:
    """The full output of Stage 1 for one repository."""
    name: str
    path: str
    cpg: CPG
    functions: list[Function] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    file_lines: dict[str, list[str]] = field(default_factory=dict)   # file -> source lines
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    duration_ms: int = 0

    def snippet(self, file: str, line: int, context: int = 4) -> str:
        """Return the source around a line, used in reports and LLM prompts."""
        lines = self.file_lines.get(file, [])
        if not lines:
            return ""
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        out = []
        for index in range(start, end):
            marker = ">>" if index == line - 1 else "  "
            out.append(f"{marker} {index + 1:4d} | {lines[index]}")
        return "\n".join(out)

    def stats(self) -> dict[str, Any]:
        data = self.cpg.stats()
        data.update({
            "files": len(self.files),
            "functions": len(self.functions),
            "routes": sum(1 for f in self.functions if f.is_route),
            "languages": self.languages,
            "parse_errors": len(self.parse_errors),
            "duration_ms": self.duration_ms,
        })
        return data
