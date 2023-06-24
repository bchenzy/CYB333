import re
import random
from datetime import datetime, timedelta

# Constants for password expiration
PASSWORD_EXPIRATION_DAYS = 90

def check_password_strength(password):
    """Check the strength of a password."""
    if len(password) < 8:
        return "Weak: Password should be at least 8 characters long."

    if re.search(r'\d', password) is None:
        return "Weak: Password should contain at least one digit."

    if re.search(r'[A-Z]', password) is None or re.search(r'[a-z]', password) is None:
        return "Weak: Password should contain at least one uppercase and one lowercase letter."

    if re.search(r'[@#$%^&+=]', password) is None:
        return "Weak: Password should contain at least one special character."

    return "Strong: Password meets the required strength criteria."


def generate_otp():
    """Generate a randomized 3-digit OTP."""
    return str(random.randint(100, 999))


def is_password_expired(password_date):
    """Check if the password has expired based on the provided date."""
    expiration_date = password_date + timedelta(days=PASSWORD_EXPIRATION_DAYS)
    return datetime.now() > expiration_date


def main():
    password = input("Enter a password: ")
    strength = check_password_strength(password)
    print(strength)

    generated_otp = generate_otp()
    print("Generated OTP:", generated_otp)

    otp = input("Enter the one-time password (OTP): ")
    if otp == generated_otp:
        print("OTP verified. Access granted.")

        password_date_str = input("Enter the date the password was last changed (YYYY-MM-DD): ")
        password_date = datetime.strptime(password_date_str, "%Y-%m-%d")
        if is_password_expired(password_date):
            print("Password has expired. Access denied.")
        else:
            print("Password is valid. Access granted.")
    else:
        print("Invalid OTP. Access denied.")


if __name__ == "__main__":
    main()
