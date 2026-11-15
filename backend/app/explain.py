"""Board-level "Why this order" explanation for the patch plan."""


# The ranking rule in plain language; shown first so a board member knows how to read the list
ORDER_RULE = ("Order rule: most actively exploited findings (CISA KEV) first, "
              "then the most total risk removed.")

# What each fix type means, for the 3 types in app/fix_type.py
EFFORT_NOTE = {
    "vendor update": "install the vendor's update",
    "library update": "rebuild and test every app that bundles it",
    "replace": "end-of-life, so replace it",
}

def plural(n, word):
    """1 -> '1 finding'; anything else (including 0) -> '3 findings'."""
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def num(x):
    """Drop a trailing .0 so boards read '95', not '95.0'; keeps '150.5'."""
    return f"{x:g}"


def why_this_order(plan, limit=3):
    """Plain-language reasons for the patch plan order."""
    # Nothing to explain if there's nothing to patch
    if not plan:
        return []

    lines = [ORDER_RULE]
    prev = None  # the package just before this one; None means we're on the first

    for p in plan[:limit]:
        if prev is None:
            # First package: say why it leads
            if p.kev_findings > 0:
                # It has actively exploited findings, so KEV put it first
                lines.append(
                    f"{p.package} first: {plural(p.kev_findings, 'actively exploited finding')} "
                    f"on {plural(len(p.hosts), 'host')}."
                )
            else:
                # No KEV findings anywhere at the top, so total risk put it first
                lines.append(
                    f"{p.package} first: no actively exploited findings, "
                    f"so it leads on total risk ({num(p.risk_removed)})."
                )
        elif p.kev_findings < prev.kev_findings:
            # Fewer exploited findings than the one before, so KEV put it lower
            text = (
                f"{p.package} next: {plural(p.kev_findings, 'actively exploited finding')}, "
                f"fewer than {prev.package} ({prev.kev_findings})."
            )
            if p.risk_removed > prev.risk_removed:
                # The trade-off: more total risk, but exploited findings still win
                text += (
                    f" It removes more total risk ({num(p.risk_removed)} vs {num(prev.risk_removed)}), "
                    f"but exploited findings come first."
                )
            lines.append(text)
        elif p.risk_removed != prev.risk_removed:
            # Same exploited count, so total risk broke the tie
            lines.append(
                f"{p.package} next: tied on actively exploited findings ({p.kev_findings}), "
                f"so total risk decides ({num(p.risk_removed)} vs {num(prev.risk_removed)})."
            )
        else:
            # Same exploited count and same risk, so patch_plan() sorted by name
            lines.append(
                f"{p.package} next: tied on exploited findings and total risk, so listed A to Z."
            )
        # Known fix type: end this package's line with the effort; unknown adds nothing
        if p.fix_type in EFFORT_NOTE:
            lines[-1] += f" Effort: {p.fix_type} ({EFFORT_NOTE[p.fix_type]})."
        prev = p

    return lines