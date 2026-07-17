import secrets
import string

class PasswordGenerator:
    """Professional Password Generator - xAI/Grok Build Standards."""
    
    def __init__(self, length=16, use_digits=True, use_special=True, use_uppercase=True):
        if length < 8:
            raise ValueError("Password length must be at least 8 characters for security.")
            
        self.length = length
        self.use_digits = use_digits
        self.use_special = use_special
        self.use_uppercase = use_uppercase

    def generate(self):
        """Generates a cryptographically secure random password."""
        chars = string.ascii_lowercase
        if self.use_uppercase:
            chars += string.ascii_uppercase
        if self.use_digits:
            chars += string.digits
        if self.use_special:
            chars += string.punctuation
        
        if not chars:
            raise ValueError("No character sets selected.")

        # Cryptographically secure selection
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(self.length))
            
            # Validation: Ensure at least one of each requested type
            if (self.use_digits and not any(c.isdigit() for c in password)):
                continue
            if (self.use_special and not any(c in string.punctuation for c in password)):
                continue
            if (self.use_uppercase and not any(c.isupper() for c in password)):
                continue
            
            return password

if __name__ == "__main__":
    try:
        gen = PasswordGenerator(length=20)
        print(f"Generated Secure Password: {gen.generate()}")
    except Exception as e:
        print(f"Error: {e}")
