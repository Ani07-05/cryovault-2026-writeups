import sqlite3,sys
c=sqlite3.connect(sys.argv[1]+"/case.db")
for n,s in c.execute("select name,sql from sqlite_master"): print(s)
for (n,) in c.execute("select name from sqlite_master where type='table'").fetchall():
    print(n,c.execute(f"select count(*) from {n}").fetchone())
