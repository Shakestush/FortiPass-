import re
from typing import Dict, Any, Optional
import hashlib
import requests
from datetime import datetime

class PasswordStrengthChecker:
    def __init__(self):
        # Common passwords and patterns to check against
        self.common_passwords = self._load_common_passwords()
        self.leak_api_url = "https://api.pwnedpasswords.com/range/"
        
        # Password requirements configuration
        self.config = {
            'min_length': 12,  # Increased from 8 to 12 for better security
            'max_length': 64,
            'require_upper': True,
            'require_lower': True,
            'require_digit': True,
            'require_special': True,
            'special_chars': r'[!@#$%^&*(),.?":{}|<>]',
            'max_consecutive_repeats': 2,
            'max_sequential_chars': 3
        }
    
    def _load_common_passwords(self) -> set:
        """Load a set of common passwords"""
        try:
            with open('common_passwords.txt', 'r') as f:
                return {line.strip() for line in f}
        except FileNotFoundError:
            # Fallback to a small built-in list
            return {
                'password', '123456', 'qwerty', 'letmein', 
                'admin', 'welcome', 'monkey', 'sunshine',
                'password1', '12345678', '123456789', '123123'
            }
    
    def check_strength(self, password: str) -> Dict[str, any]:
        """Comprehensive password strength evaluation"""
        if not password:
            return {"valid": False, "score": 0, "issues": ["Password is empty"]}
        
        results = {
            "valid": True,
            "score": 0,
            "issues": [],
            "suggestions": [],
            "details": {}
        }
        
        # Basic checks
        self._check_length(password, results)
        self._check_composition(password, results)
        self._check_patterns(password, results)
        self._check_common(password, results)
        
        # Advanced checks
        self._check_entropy(password, results)
        self._check_pwned(password, results)
        
        # Calculate overall score (0-100)
        results["score"] = self._calculate_score(results)
        
        # Determine if password meets minimum requirements
        if results["score"] < 70:
            results["valid"] = False
            if "Choose a stronger password" not in results["suggestions"]:
                results["suggestions"].append("Choose a stronger password")
        
        return results
    
    def _check_length(self, password: str, results: Dict[str, any]):
        """Check password length requirements"""
        length = len(password)
        results["details"]["length"] = length
        
        if length < self.config['min_length']:
            results["valid"] = False
            results["issues"].append(
                f"Too short (minimum {self.config['min_length']} characters)"
            )
        elif length > self.config['max_length']:
            results["valid"] = False
            results["issues"].append(
                f"Too long (maximum {self.config['max_length']} characters)"
            )
        else:
            # Length contributes to score
            length_score = min(30, length * 2)  # Up to 15 chars gets full points
            results["details"]["length_score"] = length_score
    
    def _check_composition(self, password: str, results: Dict[str, any]):
        """Check character composition requirements"""
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = bool(re.search(self.config['special_chars'], password))
        
        results["details"]["composition"] = {
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special
        }
        
        if self.config['require_upper'] and not has_upper:
            results["valid"] = False
            results["issues"].append("Missing uppercase letter")
            results["suggestions"].append("Add at least one uppercase letter")
        
        if self.config['require_lower'] and not has_lower:
            results["valid"] = False
            results["issues"].append("Missing lowercase letter")
            results["suggestions"].append("Add at least one lowercase letter")
        
        if self.config['require_digit'] and not has_digit:
            results["valid"] = False
            results["issues"].append("Missing digit")
            results["suggestions"].append("Add at least one number")
        
        if self.config['require_special'] and not has_special:
            results["valid"] = False
            results["issues"].append("Missing special character")
            results["suggestions"].append(f"Add a special character: {self.config['special_chars']}")
    
    def _check_patterns(self, password: str, results: Dict[str, any]):
        """Check for weak patterns"""
        # Check for repeated characters with default value 1 if no repeats
        repeat_matches = list(re.finditer(r'(.)\1+', password))
        repeats = max((len(match.group()) for match in repeat_matches), default=1)
        
        if repeats > self.config['max_consecutive_repeats']:
            results["valid"] = False
            results["issues"].append(
                f"Too many consecutive repeats (max {self.config['max_consecutive_repeats']})"
            )
            results["suggestions"].append("Avoid repeating the same character multiple times")
        
        # Check for sequential characters (abc, 123, etc.)
        sequential = 0
        max_sequential = 0
        for i in range(len(password) - 1):
            if ord(password[i+1]) - ord(password[i]) == 1:
                sequential += 1
                max_sequential = max(max_sequential, sequential)
                if sequential >= self.config['max_sequential_chars']:
                    results["valid"] = False
                    results["issues"].append("Contains obvious sequences")
                    results["suggestions"].append("Avoid simple sequences like '123' or 'abc'")
                    break
            else:
                sequential = 0
        
        # Check for keyboard patterns (qwerty, etc.)
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456',
            '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn'
        ]
        lower_pwd = password.lower()
        for pattern in keyboard_patterns:
            if pattern in lower_pwd:
                results["valid"] = False
                results["issues"].append("Contains keyboard pattern")
                results["suggestions"].append("Avoid common keyboard walks")
                break
    
    def _check_common(self, password: str, results: Dict[str, any]):
        """Check against common passwords"""
        lower_pwd = password.lower()
        if lower_pwd in self.common_passwords:
            results["valid"] = False
            results["score"] = 0
            results["issues"].append("Password is too common")
            results["suggestions"].append("Avoid dictionary words and common passwords")
    
    def _check_entropy(self, password: str, results: Dict[str, any]):
        """Calculate password entropy"""
        char_set = 0
        if any(c.islower() for c in password):
            char_set += 26
        if any(c.isupper() for c in password):
            char_set += 26
        if any(c.isdigit() for c in password):
            char_set += 10
        if bool(re.search(self.config['special_chars'], password)):
            char_set += len(self.config['special_chars'])
        
        entropy = len(password) * (char_set ** 0.5)
        results["details"]["entropy"] = entropy
        
        if entropy < 30:
            results["issues"].append("Low entropy (too predictable)")
            results["suggestions"].append("Use more random characters")
    
    def _check_pwned(self, password: str, results: Dict[str, any]):
        """Check password against Have I Been Pwned database (k-anonymity)"""
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            response = requests.get(f"{self.leak_api_url}{prefix}")
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = int(line.split(':')[1])
                        results["details"]["pwned_count"] = count
                        if count > 0:
                            results["valid"] = False
                            results["issues"].append(
                                f"Password found in {count} known breaches"
                            )
                            results["suggestions"].append(
                                "This password has been compromised - choose a different one"
                            )
                        break
        except requests.RequestException:
            # API call failed - skip this check
            pass
    
    def _calculate_score(self, results: Dict[str, any]) -> int:
        """Calculate overall password score (0-100)"""
        score = 0
        
        # Length contributes up to 30 points
        length = results["details"].get("length", 0)
        score += min(30, length * 2)  # More weight to length
        
        # Composition contributes up to 30 points
        comp = results["details"].get("composition", {})
        if comp.get("has_upper", False):
            score += 7
        if comp.get("has_lower", False):
            score += 7
        if comp.get("has_digit", False):
            score += 8
        if comp.get("has_special", False):
            score += 8
        
        # Entropy contributes up to 40 points
        entropy = results["details"].get("entropy", 0)
        score += min(40, entropy)
        
        # Deductions for issues (5 points per issue, max 30 points deduction)
        score -= min(30, len(results["issues"]) * 5)
        
        return max(0, min(100, int(score)))
    
    def generate_password(self, length: int = 16) -> str:
        """Generate a strong password"""
        import secrets
        import string
        
        if length < self.config['min_length']:
            length = self.config['min_length']
        if length > self.config['max_length']:
            length = self.config['max_length']
        
        chars = string.ascii_letters + string.digits
        if self.config['require_special']:
            chars += ''.join(set(self.config['special_chars']))
        
        # Generate multiple passwords if first attempt fails
        for _ in range(10):  # Try up to 10 times
            password = ''.join(secrets.choice(chars) for _ in range(length))
            if self.check_strength(password)["valid"]:
                return password
        
        # Fallback if we couldn't generate a valid password
        return ''.join(secrets.choice(chars) for _ in range(length))

if __name__ == "__main__":
    checker = PasswordStrengthChecker()
    
    print("\nPassword Strength Checker")
    print("========================")
    print(f"Minimum requirements:")
    print(f"- Length: {checker.config['min_length']}+ characters")
    print(f"- Contains uppercase: {checker.config['require_upper']}")
    print(f"- Contains lowercase: {checker.config['require_lower']}")
    print(f"- Contains digit: {checker.config['require_digit']}")
    print(f"- Contains special: {checker.config['require_special']}")
    print("Special characters:", checker.config['special_chars'])
    print("\nEnter 'q' to quit\n")
    
    while True:
        password = input("Enter password to check: ").strip()
        
        if password.lower() == 'q':
            break
        
        result = checker.check_strength(password)
        
        print(f"\nPassword Strength: {result['score']}/100")
        print(f"Valid: {'Yes' if result['valid'] else 'No'}")
        
        if result["issues"]:
            print("\nIssues found:")
            for issue in result["issues"]:
                print(f"- {issue}")
        
        if result["suggestions"]:
            print("\nSuggestions:")
            for suggestion in result["suggestions"]:
                print(f"- {suggestion}")
        
        print("\nDetails:")
        print(f"- Length: {result['details'].get('length', 0)} characters")
        print(f"- Composition: {result['details'].get('composition', {})}")
        if 'entropy' in result['details']:
            print(f"- Entropy: {result['details']['entropy']:.1f}")
        if 'pwned_count' in result['details']:
            print(f"- Breach appearances: {result['details']['pwned_count']}")
        
        print("\nGenerate a strong password example:")
        print(f"Example: {checker.generate_password()}\n")
