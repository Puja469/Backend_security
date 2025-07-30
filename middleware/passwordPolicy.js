const bcrypt = require('bcryptjs');


const passwordPolicy = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfo: true
};


const commonPasswords = [
  'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
  'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'hello',
  'freedom', 'whatever', 'qazwsx', 'trustno1', 'jordan', 'harley',
  'ranger', 'iwantu', 'jennifer', 'hunter', 'buster', 'soccer',
  'baseball', 'tiger', 'charlie', 'andrew', 'michelle', 'love',
  'sunshine', 'jessica', 'asshole', '696969', 'amanda', 'access',
  'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor',
  'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana',
  'moon', 'moscow'
];

// Validate password strength
const validatePassword = (password, userInfo = {}) => {
  const errors = [];

 
  if (password.length < passwordPolicy.minLength) {
    errors.push(`Password must be at least ${passwordPolicy.minLength} characters long`);
  }

  
  if (password.length > passwordPolicy.maxLength) {
    errors.push(`Password must not exceed ${passwordPolicy.maxLength} characters`);
  }

  
  if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  
  if (passwordPolicy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

 
  if (passwordPolicy.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  
  if (passwordPolicy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  
  if (passwordPolicy.preventCommonPasswords && commonPasswords.includes(password.toLowerCase())) {
    errors.push('Password is too common. Please choose a more unique password');
  }

  
  if (passwordPolicy.preventUserInfo && userInfo) {
    const userInfoLower = Object.values(userInfo).join(' ').toLowerCase();
    const passwordLower = password.toLowerCase();

    if (userInfoLower && passwordLower.includes(userInfoLower)) {
      errors.push('Password should not contain your personal information');
    }
  }

  
  if (/(.)\1{2,}/.test(password)) {
    errors.push('Password should not contain repeated characters');
  }

  
  const keyboardPatterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', '654321'];
  const passwordLower = password.toLowerCase();
  for (const pattern of keyboardPatterns) {
    if (passwordLower.includes(pattern)) {
      errors.push('Password should not contain keyboard patterns');
      break;
    }
  }

  return {
    isValid: errors.length === 0,
    errors: errors
  };
};

// Check password history (prevent reuse)
const checkPasswordHistory = async (newPassword, passwordHistory) => {
  if (!passwordHistory || passwordHistory.length === 0) {
    return { canReuse: true };
  }

  for (const oldPasswordHash of passwordHistory) {
    const isMatch = await bcrypt.compare(newPassword, oldPasswordHash);
    if (isMatch) {
      return {
        canReuse: false,
        error: 'Password has been used recently. Please choose a different password'
      };
    }
  }

  return { canReuse: true };
};

// Generate password strength score
const getPasswordStrength = (password) => {
  let score = 0;

  // Length contribution
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;

  // Character variety contribution
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1;

  // Bonus for mixed case and numbers
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) && /[a-zA-Z]/.test(password)) score += 1;

  // Penalty for common patterns
  if (commonPasswords.includes(password.toLowerCase())) score -= 2;
  if (/(.)\1{2,}/.test(password)) score -= 1;

  // Determine strength level
  if (score <= 2) return { score, level: 'weak' };
  if (score <= 4) return { score, level: 'fair' };
  if (score <= 6) return { score, level: 'good' };
  return { score, level: 'strong' };
};

// Middleware for password validation
const validatePasswordMiddleware = (req, res, next) => {
  const { password, ...userInfo } = req.body;

  if (!password) {
    return res.status(400).json({
      status: 'error',
      message: 'Password is required'
    });
  }

  const validation = validatePassword(password, userInfo);

  if (!validation.isValid) {
    return res.status(400).json({
      status: 'error',
      message: 'Password validation failed',
      errors: validation.errors
    });
  }

  // Add password strength to request
  req.passwordStrength = getPasswordStrength(password);

  next();
};

// Middleware for password history check
const checkPasswordHistoryMiddleware = async (req, res, next) => {
  try {
    const { password } = req.body;
    const { passwordHistory } = req.user || {};

    if (passwordHistory) {
      const historyCheck = await checkPasswordHistory(password, passwordHistory);

      if (!historyCheck.canReuse) {
        return res.status(400).json({
          status: 'error',
          message: historyCheck.error
        });
      }
    }

    next();
  } catch (error) {
    console.error('Password history check error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error checking password history'
    });
  }
};

module.exports = {
  validatePassword,
  checkPasswordHistory,
  getPasswordStrength,
  validatePasswordMiddleware,
  checkPasswordHistoryMiddleware,
  passwordPolicy
};
