from app.core.security import hash_password, verify_password


def test_passwords_are_hashed_and_verifiable():
    password_hash = hash_password("correct horse battery staple")
    assert password_hash != "correct horse battery staple"
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)
