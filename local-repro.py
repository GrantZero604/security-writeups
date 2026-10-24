#!/usr/bin/env python3
"""
A local model of the Halloween Store coupon bug (Intigriti 1026).

I could not read the server's source, so I rebuilt the smallest thing that reproduces
every behaviour I observed on the live target, then checked the model against the real
responses. If the model predicts the live results on all six cases, the reconstruction
is probably right.

    python3 local-repro.py

Author: Bram Brinkmeier (grantzero)
"""

PROMOS = {"NIGHT20": 20, "NEWS30": 30}
SUBTOTAL = 66600          # EUR 666.00, in cents
CREDIT = 6600             # EUR 66.00


class Cart:
    """`broken=True` models the live server. `broken=False` is the one-line fix."""

    def __init__(self, broken=True):
        self.broken = broken
        self.promotions = {}      # code -> count, insertion ordered
        self.last_coupon = None   # the single slot that causes the bug

    def apply(self, submitted):
        code = submitted.strip().upper()          # lookup normalises: trim + casefold
        if code not in PROMOS:
            return "invalid_coupon"

        if self.broken:
            # What the live server does: compare against ONE remembered code.
            already = (self.last_coupon == code)
        else:
            # What it should do: compare against everything on the cart.
            already = (code in self.promotions)

        if already:
            return "coupon_already_applied"

        self.promotions[code] = self.promotions.get(code, 0) + 1
        self.last_coupon = code
        return "ok"

    def remove(self, code):
        code = code.strip().upper()
        if code not in self.promotions:
            return "not_applied"
        del self.promotions[code]
        # Re-arms the guard to whatever is now last, which is why you cannot
        # immediately re-apply that one.
        self.last_coupon = next(reversed(self.promotions), None)
        return "ok"

    @property
    def percent(self):
        return sum(PROMOS[c] * n for c, n in self.promotions.items())

    @property
    def total(self):
        discount = min(SUBTOTAL * self.percent // 100, SUBTOTAL)   # clamped at subtotal
        return SUBTOTAL - discount

    @property
    def can_checkout(self):
        return self.total <= CREDIT


# ---------------------------------------------------------------- the six live cases
# Each row: description, the sequence to run, and what the LIVE server actually returned.
CASES = [
    ("same code twice in a row",
     ["NIGHT20", "NIGHT20"], "coupon_already_applied"),
    ("different case, straight after",
     ["NIGHT20", "night20"], "coupon_already_applied"),
    ("leading space, straight after (my wrong theory)",
     ["NIGHT20", " NIGHT20"], "coupon_already_applied"),
    ("leading space, but after the OTHER code",
     ["NIGHT20", "NEWS30", " NIGHT20"], "ok"),
    ("plain duplicate, after the OTHER code",
     ["NIGHT20", "NEWS30", "NIGHT20"], "ok"),
    ("the full alternation",
     ["NIGHT20", "NEWS30", "NIGHT20", "NEWS30"], "ok"),
]

print("Model vs. the live server\n" + "-" * 58)
agree = 0
for label, seq, live in CASES:
    cart = Cart(broken=True)
    for code in seq:
        got = cart.apply(code)
    ok = got == live
    agree += ok
    print(f"  [{'MATCH' if ok else 'DIFFER'}] {label}")
    print(f"           model={got:<24} live={live}")

print(f"\n  {agree}/{len(CASES)} cases match the live server.\n")

print("The attack, against the model\n" + "-" * 58)
cart = Cart(broken=True)
for code in ["NIGHT20", "NEWS30", "NIGHT20", "NEWS30"]:
    cart.apply(code)
    print(f"  apply {code:<8} sum {cart.percent:>3}%   total EUR {cart.total/100:>7,.2f}"
          f"   checkout={cart.can_checkout}")

print("\nThe same attack, against the one-line fix\n" + "-" * 58)
fixed = Cart(broken=False)
for code in ["NIGHT20", "NEWS30", "NIGHT20", "NEWS30"]:
    result = fixed.apply(code)
    print(f"  apply {code:<8} {result:<24} sum {fixed.percent:>3}%"
          f"   total EUR {fixed.total/100:>7,.2f}")
print(f"\n  Fixed cart stops at {fixed.percent}% and EUR {fixed.total/100:,.2f}, "
      f"well above the EUR {CREDIT/100:,.2f} credit. Checkout stays blocked.")
