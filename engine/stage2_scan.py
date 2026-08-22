"""STAGE 2 of 4 -- SCAN.

Owner: Member 2 (Scan / Taint engine).

Walk every function and ask one question over and over:

    "Can a value that an attacker controls reach a dangerous call?"

The algorithm is a forward taint analysis and it fits on one page:

    tainted = {}                         # variable name -> how it got dirty
    for each statement, in order:
        if it assigns:   evaluate the right-hand side.
                         dirty  -> remember the variable
                         clean  -> forget the variable
        for every call:  if the call is a SINK and one of its dangerous
                         arguments is dirty, report a finding.

Three details make it useful rather than a toy:

  1. A sanitizer does NOT clear the taint. It is recorded on the path and the
     finding is still reported. Stage 3 decides whether the sanitizer really
     covers this sink. Suppressing here would destroy the evidence that makes
     the false-positive comparison meaningful.

  2. Parameters of functions that are NOT HTTP route handlers are treated as
     possibly-tainted, but the finding is marked `http_reachable = False`.
     Real SAST tools do this, and it is a large source of their false
     positives -- which is exactly what we want Stage 3 to clean up.

  3. Calls into functions defined in the same repository are followed
     (up to two levels), so a route handler that passes user input to a
     helper still produces a complete path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import rules
from .cpg import Expr, Function, ParsedRepo, Stmt

MAX_CALL_DEPTH = 2          # how far we follow calls into other functions
LOOP_PASSES = 2             # walk a loop body twice so taint set inside it settles


# --------------------------------------------------------------------------
# The taint path -- the evidence attached to every finding.
# --------------------------------------------------------------------------


@dataclass
class Step:
    file: str
    line: int
    code: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line,
                "code": self.code.strip(), "description": self.description}


@dataclass
class TaintPath:
    steps: list[Step] = field(default_factory=list)
    source_label: str = ""
    source_pattern: str = ""
    sanitizers: list[str] = field(default_factory=list)
    guarded: bool = False
    http_reachable: bool = True
    entry: str = ""
    # The route the taint STARTED at. A helper function has no route of its
    # own, so without carrying this along, an inter-procedural finding loses
    # the URL an attacker would actually call and the PoC becomes useless.
    route_path: str = ""
    route_methods: list[str] = field(default_factory=list)

    def copy(self) -> "TaintPath":
        return TaintPath(
            steps=list(self.steps), source_label=self.source_label,
            source_pattern=self.source_pattern, sanitizers=list(self.sanitizers),
            guarded=self.guarded, http_reachable=self.http_reachable, entry=self.entry,
            route_path=self.route_path, route_methods=list(self.route_methods),
        )

    def then(self, step: Step) -> "TaintPath":
        new = self.copy()
        new.steps.append(step)
        return new


def _merge(left: TaintPath | None, right: TaintPath | None) -> TaintPath | None:
    """Combine two ways a value got dirty. The longer path wins; flags are OR-ed."""
    if left is None:
        return right
    if right is None:
        return left
    winner = left if len(left.steps) >= len(right.steps) else right
    merged = winner.copy()
    merged.sanitizers = list(dict.fromkeys(left.sanitizers + right.sanitizers))
    merged.guarded = left.guarded or right.guarded
    merged.http_reachable = left.http_reachable or right.http_reachable
    return merged


# --------------------------------------------------------------------------
# Scan context -- everything shared while walking one repository.
# --------------------------------------------------------------------------


class _Context:
    def __init__(self, repo: ParsedRepo) -> None:
        self.repo = repo
        self.findings: list[dict[str, Any]] = []
        self.seen_keys: set[str] = set()
        self.by_name: dict[str, Function] = {}
        for function in repo.functions:
            self.by_name.setdefault(function.name, function)
            self.by_name.setdefault(function.name.split(".")[-1], function)
        self.unreachable_depth = 0     # > 0 means we are inside `if False:`


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def scan(repo: ParsedRepo) -> list[dict[str, Any]]:
    """Return every raw finding in this repository."""
    context = _Context(repo)

    for function in repo.functions:
        environment: dict[str, TaintPath] = {}

        if function.is_route:
            entry = function.entry_description()
        else:
            entry = function.entry_description()
            # Parameters of an internal function might carry user input, but we
            # cannot prove it. Mark the path so Stage 3 can weigh that.
            for param in function.params:
                environment[param] = TaintPath(
                    steps=[Step(function.file, function.line, f"{function.name}({param})",
                                f"parameter `{param}` of an internal function "
                                f"(no proven attacker-controlled caller)")],
                    source_label="function parameter",
                    source_pattern="parameter",
                    http_reachable=False,
                    entry=entry,
                )

        _walk(function.body, environment, function, context, entry, depth=0)

    return context.findings


# --------------------------------------------------------------------------
# Walking statements
# --------------------------------------------------------------------------


def _walk(statements: list[Stmt], environment: dict[str, TaintPath],
          function: Function, context: _Context, entry: str, depth: int) -> None:
    for statement in statements:

        if statement.kind == "assign":
            _check_sinks(statement.value, environment, function, context, entry, depth)
            taint = _evaluate(statement.value, environment, function, context, entry, depth)
            for target in statement.targets:
                if taint is None:
                    environment.pop(target, None)
                else:
                    environment[target] = taint.then(Step(
                        function.file, statement.line, statement.code,
                        f"value flows into `{target}`"))

        elif statement.kind in ("expr", "return"):
            _check_sinks(statement.value, environment, function, context, entry, depth)

        elif statement.kind == "if":
            _check_sinks(statement.test, environment, function, context, entry, depth)
            _mark_guarded(statement.test, environment)

            if statement.always_false:
                context.unreachable_depth += 1
            _walk(statement.body, environment, function, context, entry, depth)
            if statement.always_false:
                context.unreachable_depth -= 1

            _walk(statement.orelse, environment, function, context, entry, depth)

        elif statement.kind == "loop":
            for _ in range(LOOP_PASSES):
                _walk(statement.body, environment, function, context, entry, depth)


def _mark_guarded(test: Expr | None, environment: dict[str, TaintPath]) -> None:
    """`if user_value not in ALLOWED: abort()` -- remember that a check happened.

    We do not try to prove the check is correct. We record that one exists and
    let Stage 3 judge it. That is a much more honest split of responsibility
    than guessing in a regex.
    """
    if test is None:
        return
    for name in test.vars:
        if name in environment and not environment[name].guarded:
            guarded = environment[name].copy()
            guarded.guarded = True
            environment[name] = guarded


# --------------------------------------------------------------------------
# Evaluating an expression: is this value dirty, and how did it get that way?
# --------------------------------------------------------------------------


def _evaluate(expression: Expr | None, environment: dict[str, TaintPath],
              function: Function, context: _Context, entry: str, depth: int) -> TaintPath | None:
    if expression is None:
        return None

    # A sink consumes the tainted value; we do not assume its RESULT is also
    # attacker-controlled. Without this rule, `data = fs.readFileSync(userPath)`
    # would mark `data` as attacker input and every later use of it becomes a
    # second, noisier finding chained off the first one.
    if len(expression.calls) == 1 and not expression.sources:
        only_call = expression.calls[0]
        if rules.find_sink(only_call.name, function.lang) is not None:
            return None

    path: TaintPath | None = None

    # 1. The expression reads an attacker-controlled source directly.
    for pattern in expression.sources:
        rule = rules.find_source(pattern, function.lang)
        label = rule["label"] if rule else "user input"
        source_path = TaintPath(
            steps=[Step(function.file, _line_of(expression, function),
                        expression.code, f"attacker input enters via {label} (`{pattern}`)")],
            source_label=label, source_pattern=pattern,
            http_reachable=function.is_route, entry=entry,
            route_path=function.route_path, route_methods=list(function.route_methods),
        )
        path = _merge(path, source_path)

    # 2. The expression reads a variable we already know is dirty.
    for name in expression.vars:
        if name in environment:
            path = _merge(path, environment[name])

    # 3. Calls inside the expression: sanitizers get recorded, other calls
    #    simply pass the taint through (str(x), "a" + f(x), and so on).
    for call in expression.calls:
        argument_tainted = any(
            _evaluate(argument, environment, function, context, entry, depth) is not None
            for argument in call.args)
        if not argument_tainted or path is None:
            continue
        sanitizer = rules.find_sanitizer(call.name, function.lang)
        if sanitizer:
            path = path.copy()
            if call.name not in path.sanitizers:
                path.sanitizers.append(call.name)
            path.steps.append(Step(function.file, call.line, call.code,
                                   f"passed through `{call.name}()`"))

    return path


def _line_of(expression: Expr, function: Function) -> int:
    for call in expression.calls:
        if call.line:
            return call.line
    return function.line


# --------------------------------------------------------------------------
# Checking sinks
# --------------------------------------------------------------------------


def _check_sinks(expression: Expr | None, environment: dict[str, TaintPath],
                 function: Function, context: _Context, entry: str, depth: int) -> None:
    if expression is None:
        return

    for call in expression.calls:
        # Nested calls first: sink(inner(x)) must check `inner` too.
        for argument in call.args:
            _check_sinks(argument, environment, function, context, entry, depth)
        for keyword_value in call.kwargs.values():
            _check_sinks(keyword_value, environment, function, context, entry, depth)

        sink = rules.find_sink(call.name, function.lang)
        if sink is not None:
            _check_one_sink(call, sink, environment, function, context, entry)

        # Not a sink -- but is it one of our own functions? Follow the call.
        if sink is None and depth < MAX_CALL_DEPTH:
            _follow_call(call, environment, function, context, entry, depth)


def _check_one_sink(call, sink: dict[str, Any], environment: dict[str, TaintPath],
                    function: Function, context: _Context, entry: str) -> None:
    # Some sinks are only dangerous with a particular keyword argument,
    # e.g. subprocess.run(cmd, shell=True).
    required = sink.get("requires_kwarg")
    if required:
        keyword, expected = required
        supplied = call.kwargs.get(keyword)
        if supplied is None or expected.lower() not in supplied.code.strip().lower():
            return

    positions = sink.get("args") or []
    for index, argument in enumerate(call.args):
        if positions and index not in positions:
            continue
        path = _evaluate(argument, environment, function, context, entry, depth=0)
        if path is None:
            continue
        _emit(call, sink, path, function, context, entry)
        return          # one finding per sink call is enough


def _follow_call(call, environment: dict[str, TaintPath], function: Function,
                 context: _Context, entry: str, depth: int) -> None:
    """A route handler calling a helper: carry the taint into the helper."""
    callee = context.by_name.get(call.name) or context.by_name.get(call.name.split(".")[-1])
    if callee is None or callee is function or not callee.params:
        return

    inner_environment: dict[str, TaintPath] = {}
    for index, argument in enumerate(call.args):
        if index >= len(callee.params):
            break
        path = _evaluate(argument, environment, function, context, entry, depth)
        if path is not None:
            inner_environment[callee.params[index]] = path.then(Step(
                function.file, call.line, call.code,
                f"passed as `{callee.params[index]}` into `{callee.name}()`"))

    if inner_environment:
        _walk(callee.body, inner_environment, callee, context, entry, depth + 1)


# --------------------------------------------------------------------------
# Building the finding
# --------------------------------------------------------------------------


def _emit(call, sink: dict[str, Any], path: TaintPath,
          function: Function, context: _Context, entry: str) -> None:
    category = sink["category"]
    meta = rules.vuln_class(category)

    final_path = path.then(Step(
        function.file, call.line, call.code,
        f"reaches the dangerous call `{call.name}()`"))

    key = f"{function.file}:{call.line}:{call.name}:{category}"
    if key in context.seen_keys:
        return
    context.seen_keys.add(key)

    finding = {
        "id": hashlib.sha256(f"{context.repo.name}:{key}".encode()).hexdigest()[:12],
        "repo": context.repo.name,
        "category": category,
        "title": meta["title"],
        "cwe": meta["cwe"],
        "owasp": meta["owasp"],
        "severity": meta["severity"],
        "why_dangerous": meta["why"],

        "file": function.file,
        "line": call.line,
        "function": function.name,
        "sink": call.name,
        "sink_code": call.code.strip(),
        "language": function.lang,

        "entry": path.entry or entry,
        "http_reachable": path.http_reachable,
        "route_path": path.route_path or function.route_path,
        "route_methods": path.route_methods or function.route_methods,
        "source_label": path.source_label,
        "source_pattern": path.source_pattern,

        "sanitizers": path.sanitizers,
        "sanitizer_covers_sink": any(
            rules.sanitizer_covers(name, category, function.lang) for name in path.sanitizers),
        "guarded": path.guarded,
        "unreachable": context.unreachable_depth > 0,

        "taint_path": [step.to_dict() for step in final_path.steps],
        "snippet": context.repo.snippet(function.file, call.line),

        "stage": "scan",
        "status": "unvalidated",
    }
    context.findings.append(finding)
