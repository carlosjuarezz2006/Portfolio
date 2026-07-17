import secrets
import string

class PasswordGenerator:
    """Professional Password Generator - xAI/Grok Build Standards."""
    
    def __init__(self, length=16, use_digits=True, use_special=True):
        self.length = length
        self.use_digits = use_digits
        self.use_special = use_special

    def generate(self):
        characters = string.ascii_letters
        if self.use_digits:
            characters += string.digits
        if self.use_special:
            characters += string.punctuation
        
        # Cryptographically secure selection
        return ''.join(secrets.choice(characters) for _ in range(self.length))

if __name__ == "__main__":
    gen = PasswordGenerator(length=24)
    print(f"Secure Password: {gen.generate()}")
