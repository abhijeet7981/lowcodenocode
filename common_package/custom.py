import random
import string


def generate_otp():
    digits = string.digits
    return ''.join(random.choice(digits) for i in range(6))


def generate_password():
    characters = string.ascii_letters + string.punctuation + string.digits
    return ''.join(random.choice(characters) for i in range(8, 16))
