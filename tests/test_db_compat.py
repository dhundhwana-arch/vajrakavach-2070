import unittest
from backend.core.db import CompatRow, translate_sqlite_to_pg_sql


class DatabaseCompatTests(unittest.TestCase):
    def test_compat_row_dual_access(self) -> None:
        row = CompatRow(["id", "email"], [42, "founder@vajrakavach.in"])
        self.assertEqual(row["id"], 42)
        self.assertEqual(row["email"], "founder@vajrakavach.in")
        self.assertEqual(row[0], 42)
        self.assertEqual(row[1], "founder@vajrakavach.in")

    def test_sqlite_to_postgres_translation(self) -> None:
        ddl = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        self.assertIn("SERIAL PRIMARY KEY", translate_sqlite_to_pg_sql(ddl))

        ins = "INSERT INTO users (email, role) VALUES (?, ?)"
        pg_ins = translate_sqlite_to_pg_sql(ins)
        self.assertEqual(pg_ins, "INSERT INTO users (email, role) VALUES (%s, %s) RETURNING id")

        sel = "SELECT COUNT(*) FROM assets WHERE tenant_id = ?"
        self.assertEqual(translate_sqlite_to_pg_sql(sel), "SELECT COUNT(*) FROM assets WHERE tenant_id = %s")


if __name__ == "__main__":
    unittest.main()
