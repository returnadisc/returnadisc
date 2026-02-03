import secrets
import string

def generate_disc_id():
    prefix = "DISC-"
    alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ23456789"
    code = ''.join(secrets.choice(alphabet) for _ in range(6))
    return prefix + code
