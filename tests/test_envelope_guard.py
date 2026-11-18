from security.envelope_guard import (
    derive_nonce,
    aad,
    encrypt_field,
    decrypt_field,
    rotate_key
)


def test_nonce_unique():
    assert derive_nonce('seed', 1) != derive_nonce('seed', 2)

def test_nonce_det():
    assert derive_nonce('seed', 1) == derive_nonce('seed', 1)

def test_aad():
    assert aad('t1', 'email') != aad('t2', 'email')

def test_aad_field():
    assert aad('t1', 'email') != aad('t1', 'phone')

def test_encrypt():
    assert encrypt_field('x', b'k', 'n', aad('t1', 'f'))['cipher'] != 'x'

def test_version():
    assert encrypt_field('x', b'k', 'n', 'a')['version']

def test_decrypt():
    assert decrypt_field(encrypt_field('x', b'k', 'n', 'a'), b'k', 'a') == 'x'

def test_wrong_aad():
    assert decrypt_field(encrypt_field('x', b'k', 'n', 'a'), b'k', 'b') is None

def test_wrong_key():
    assert decrypt_field(encrypt_field('x', b'k', 'n', 'a'), b'j', 'a') is None

def test_tag():
    assert len(encrypt_field('x', b'k', 'n', 'a')['tag']) == 32

def test_empty():
    assert encrypt_field('', b'k', 'n', 'a')['cipher'] != ''

def test_rotate():
    assert rotate_key({'v': 1, 'key': b'k'})['v'] == 2

def test_no_plain():
    assert 'x' not in str(encrypt_field('x', b'k', 'n', 'a'))

def test_nonce_in():
    assert encrypt_field('x', b'k', 'n', 'a')['nonce'] == 'n'

def test_safe():
    assert decrypt_field({'cipher': 'bad', 'tag': 'bad', 'nonce': 'n', 'version': 1}, b'k', 'a') is None
