# ----------------------------------------------------------
# "Each of you should use whatever gift you have received to 
# serve others, as faithful stewards of God's grace in its 
# various forms." - 1st Peter 4:10
# ----------------------------------------------------------
#Password Strength Checker

def check_password_strength(password):
    min_length = 8
    common_patterns = ['password','12345678','admin@2024','#98765432#']

    #Scoring Variables 
    score = 0
    max_score  = 10

    #checkpoint variables 

    length_check = len(password) >= min_length
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False
    has_common_pattern = False

    if length_check:
        score += 2
        if len(password) >= 12:
            score +=1


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
        score += 2  # Points for uppercase characters
    if has_lower:
        score += 2  # Points for lowercase characters
    if has_digit:
        score += 2  # Points for numeric characters
    if has_special:
        score += 2  # Points for special characters

    # Check for common patterns
    for pattern in common_patterns:
        if pattern in password.lower():
            has_common_pattern = True
            score -= 3  # Deduct points for common patterns
            break

    # Determine password rating
    if score >= 9:
        rating = "Very Strong"
    elif score >= 7:
        rating = "Strong"
    elif score >= 5:
        rating = "Moderate"
    else:
        rating = "Weak"

    # Display password score and rating
    print(f"Password Score: {score}/{max_score}")
    print(f"Password Strength: {rating}")
    
    # Graphical Representation (Text-based)
    strength_bar = "=" * score  # Create a bar based on the score
    print(f"Strength Bar: [{strength_bar.ljust(max_score, '-')}]")

    # Tips for improvement
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

# Test Run:
password = input("Enter a password to check its strength: ")
check_password_strength(password)

