import sqlite3,sys
c=sqlite3.connect(sys.argv[1]+"/st/s4.db")
for t in ["operations","notes","attachments"]:
    print(t)
    for r in c.execute(f"select * from {t}"): print(r)
