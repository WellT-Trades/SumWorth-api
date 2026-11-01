import tempfile
import unittest
from unittest import mock
from pathlib import Path

import db

# Use a throwaway database, never your real sumworth.db.
# This must happen BEFORE app is imported, because app sets itself up on import.
_tmp = tempfile.TemporaryDirectory()
db.DB_PATH = Path(_tmp.name) / "test.db"

import app as app_module  # noqa: E402


class AuthAndIsolationTests(unittest.TestCase):
    def setUp(self):
        db.DB_PATH.unlink(missing_ok=True)
        db.init_db()
        self.client = app_module.app.test_client()

    # --- helpers -------------------------------------------------------
    def signup(self, email):
        password = "test-password-1"
        self.client.post("/auth/register", json={"email": email, "password": password})
        reply = self.client.post("/auth/login", json={"email": email, "password": password})
        return {"Authorization": "Bearer " + reply.get_json()["token"]}

    def add_account(self, headers, name="Opay", number="1111", kobo=1000):
        return self.client.post(
            "/accounts",
            json={"name": name, "account_number": number, "balance_kobo": kobo},
            headers=headers,
        )

    # --- tests ---------------------------------------------------------
    def test_no_token_is_refused(self):
        self.assertEqual(self.client.get("/accounts").status_code, 401)

    def test_fake_token_is_refused(self):
        reply = self.client.get("/accounts", headers={"Authorization": "Bearer nonsense"})
        self.assertEqual(reply.status_code, 401)

    def test_wrong_password_is_refused(self):
        self.signup("a@example.com")
        reply = self.client.post(
            "/auth/login", json={"email": "a@example.com", "password": "wrong-password"}
        )
        self.assertEqual(reply.status_code, 401)

    def test_user_cannot_see_another_users_accounts(self):
        alice = self.signup("alice@example.com")
        bob = self.signup("bob@example.com")
        self.add_account(alice)
        self.assertEqual(self.client.get("/accounts", headers=bob).get_json(), [])

    def test_user_cannot_edit_or_delete_another_users_account(self):
        alice = self.signup("alice@example.com")
        bob = self.signup("bob@example.com")
        account_id = self.add_account(alice).get_json()["id"]

        edit = self.client.put(
            f"/accounts/{account_id}",
            json={"name": "Hacked", "account_number": "0000", "balance_kobo": 1},
            headers=bob,
        )
        delete = self.client.delete(f"/accounts/{account_id}", headers=bob)
        self.assertEqual(edit.status_code, 404)
        self.assertEqual(delete.status_code, 404)

        # Alice's account is untouched
        mine = self.client.get("/accounts", headers=alice).get_json()
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["name"], "Opay")
        self.assertEqual(mine[0]["balance_kobo"], 1000)

    def test_two_users_can_have_the_same_account_name_and_number(self):
        alice = self.signup("alice@example.com")
        bob = self.signup("bob@example.com")
        self.assertEqual(self.add_account(alice).status_code, 201)
        self.assertEqual(self.add_account(bob).status_code, 201)

    def test_duplicate_within_one_user_is_refused(self):
        alice = self.signup("alice@example.com")
        self.add_account(alice)
        self.assertEqual(self.add_account(alice, name="OPAY").status_code, 409)
    
    def login_with(self, email, password):
        return self.client.post("/auth/login", json={"email": email, "password": password})

    def test_four_wrong_passwords_lock_the_account(self):
        self.signup("a@example.com")
        codes = [self.login_with("a@example.com", "wrong-password").status_code for _ in range(4)]
        self.assertEqual(codes, [401, 401, 401, 429])
        # Even the correct password is refused while locked
        self.assertEqual(self.login_with("a@example.com", "test-password-1").status_code, 429)

    def test_successful_login_resets_the_counter(self):
        self.signup("a@example.com")
        for _ in range(3):
            self.login_with("a@example.com", "wrong-password")
        self.assertEqual(self.login_with("a@example.com", "test-password-1").status_code, 200)
        codes = [self.login_with("a@example.com", "wrong-password").status_code for _ in range(3)]
        self.assertEqual(codes, [401, 401, 401])

    def test_unknown_email_locks_the_same_way(self):
        codes = [self.login_with("nobody@example.com", "whatever-pass").status_code for _ in range(4)]
        self.assertEqual(codes, [401, 401, 401, 429])

    def request_reset_code(self, email):
        with mock.patch.object(app_module, "send_reset_code") as fake:
            self.client.post("/auth/forgot-password", json={"email": email})
        return fake.call_args[0][1] if fake.called else None

    def reset(self, email, code, new_password="new-password-9"):
        return self.client.post(
            "/auth/reset-password",
            json={"email": email, "code": code, "new_password": new_password},
        )

    def test_reset_with_correct_code_changes_password(self):
        self.signup("a@example.com")
        code = self.request_reset_code("a@example.com")
        self.assertEqual(self.reset("a@example.com", code).status_code, 200)
        self.assertEqual(self.login_with("a@example.com", "test-password-1").status_code, 401)
        self.assertEqual(self.login_with("a@example.com", "new-password-9").status_code, 200)

    def test_wrong_code_dies_after_five_tries(self):
        self.signup("a@example.com")
        code = self.request_reset_code("a@example.com")
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(5):
            self.assertEqual(self.reset("a@example.com", wrong).status_code, 400)
        # The right code no longer works either
        self.assertEqual(self.reset("a@example.com", code).status_code, 400)

    def test_code_cannot_be_used_twice(self):
        self.signup("a@example.com")
        code = self.request_reset_code("a@example.com")
        self.assertEqual(self.reset("a@example.com", code).status_code, 200)
        self.assertEqual(self.reset("a@example.com", code, "another-pass-1").status_code, 400)

    def test_expired_code_is_refused(self):
        self.signup("a@example.com")
        code = self.request_reset_code("a@example.com")
        conn = db.get_connection()
        conn.execute("UPDATE password_resets SET expires_at = 1")
        conn.commit()
        conn.close()
        self.assertEqual(self.reset("a@example.com", code).status_code, 400)

    def test_unknown_email_gets_the_same_reply_and_no_code(self):
        self.signup("a@example.com")
        known = self.client.post("/auth/forgot-password", json={"email": "a@example.com"})
        unknown = self.client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
        self.assertEqual(known.get_json(), unknown.get_json())
        self.assertIsNone(self.request_reset_code("nobody@example.com"))

if __name__ == "__main__":
    unittest.main()
    