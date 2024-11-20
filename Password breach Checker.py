import requests
import hashlib

# Function to check if a password has been breached
def check_breach(password):
    # Step 1: Hash the password with SHA-1
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Step 2: Query the Have I Been Pwned API with the first 5 characters of the SHA-1 hash
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    response = requests.get(url)
    if response.status_code == 200:
        # Step 3: Check if the suffix of our hash appears in the response
        hashes = response.text.splitlines()
        for hash_suffix in hashes:
            stored_hash, count = hash_suffix.split(":")
            if stored_hash == suffix:
                return True, count  # Password is breached
    return False, 0  # Password is safe

# Modified password strength checker function
def check_password_strength(password):
    min_length = 8
    common_patterns = ["password", "123456", "qwerty", "admin", "letmein"]
    score = 0
    max_score = 10

    length_check = len(password) >= min_length
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False
    has_common_pattern = False

    if length_check:
        score += 2
        if len(password) >= 12:
            score += 1

    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        else:
            has_special = True

    if has_upper:
        score += 2
    if has_lower:
        score += 2
    if has_digit:
        score += 2
    if has_special:
        score += 2

    for pattern in common_patterns:
        if pattern in password.lower():
            has_common_pattern = True
            score -= 3
            break

    # Breach Check
    is_breached, breach_count = check_breach(password)
    if is_breached:
        score -= 2  # Deduct points for breach
        print(f"Warning: This password has been exposed {breach_count} times in data breaches!")

    if score >= 9:
        rating = "Very Strong"
    elif score >= 7:
        rating = "Strong"
    elif score >= 5:
        rating = "Moderate"
    else:
        rating = "Weak"

    print(f"Password Score: {score}/{max_score}")
    print(f"Password Strength: {rating}")
    
    strength_bar = "=" * score
    print(f"Strength Bar: [{strength_bar.ljust(max_score, '-')}]\n")

    if rating == "Weak":
        print("\nTips to improve your password:")
        if not length_check:
            print("- Increase length (at least 8 characters).")
        if not has_upper:
            print("- Add uppercase letters.")
        if not has_lower:
            print("- Add lowercase letters.")
        if not has_digit:
            print("- Include numbers.")
        if not has_special:
            print("- Use special characters.")
        if has_common_pattern:
            print("- Avoid common patterns like 'password' or '123456'.")
