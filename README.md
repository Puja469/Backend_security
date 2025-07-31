# ThriftStore - Security Features

A comprehensive overview of all security features implemented in the ThriftStore e-commerce application.

## 🛡️ Security Features Implemented

### Authentication & Authorization Security

- **JWT Token Security**
  - Secure JWT tokens with httpOnly cookies
  - Role-based access control (User/Admin)
  - Session versioning for enhanced security
  - Automatic token expiration handling
  - Secure token transmission

- **Two-Factor Authentication (2FA)**
  - Email OTP verification system
  - 5-minute OTP expiration
  - Secure OTP generation and validation
  - Account lockout after failed attempts
  - Multi-step authentication process

- **Account Security Measures**
  - Account lockout after 5 failed login attempts
  - Session invalidation across all devices
  - Comprehensive login attempt tracking
  - IP-based security monitoring
  - Suspicious activity detection

- **Password Security**
  - bcrypt password hashing with 12 salt rounds
  - Password history tracking to prevent reuse
  - Enhanced password policy validation
  - Password strength scoring system
  - Common password prevention
  - Password expiration policies

### CSRF Protection

- **Cross-Site Request Forgery Prevention**
  - CSRF token generation and validation
  - Token-based request verification
  - Secure token storage and transmission
  - Automatic token refresh mechanism
  - Session-based token management

### Rate Limiting & DDoS Protection

- **Strategic Rate Limiting**
  - Authentication routes: 5 requests per 15 minutes
  - File uploads: 10 uploads per hour
  - Product creation: 50 creations per 15 minutes
  - Password operations: Strict rate limiting
  - API endpoint protection

### Input Validation & Sanitization

- **Comprehensive Input Security**
  - XSS protection with xss-clean middleware
  - MongoDB injection prevention with mongo-sanitize
  - Input validation with Joi schemas
  - Enhanced input sanitization
  - Suspicious activity detection
  - HTTP Parameter Pollution (HPP) prevention
  - Request size validation
  - URL length validation

### File Upload Security

- **Secure File Handling**
  - File type validation (images only: JPG, PNG, GIF, WebP)
  - File size limits (5MB maximum)
  - Secure filename generation with crypto
  - MIME type validation for content verification
  - Virus scanning simulation
  - Upload rate limiting
  - Path traversal protection

### Security Headers & CORS

- **Web Security Headers**
  - Helmet.js implementation for security headers
  - Content Security Policy (CSP)
  - Secure CORS configuration
  - HTTP Strict Transport Security (HSTS)
  - X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
  - Referrer Policy and Permissions Policy

### Activity Logging & Monitoring

- **Comprehensive Security Monitoring**
  - Detailed activity logging system
  - Security event tracking and analysis
  - IP address logging and monitoring
  - User agent tracking
  - Real-time security metrics
  - Request/response logging
  - Security dashboard with export capabilities

### CAPTCHA Integration

- **Bot Prevention**
  - Character-based CAPTCHA system
  - Session-based CAPTCHA storage
  - Rate limiting for CAPTCHA generation
  - Configurable CAPTCHA complexity
  - Attempt limiting and expiration

### Email Security

- **Secure Email Communication**
  - Professional email templates with branding
  - OTP email verification system
  - Password reset email security
  - Login verification emails
  - Email template security

### Database Security

- **Data Protection**
  - MongoDB injection prevention
  - Secure database connections
  - Data encryption at rest
  - Query sanitization
  - Database access controls

### Error Handling & Security

- **Secure Error Management**
  - Secure error messages without sensitive data exposure
  - Custom error handlers
  - Security-focused error logging
  - Graceful failure handling
  - Error sanitization

### Network Security

- **HTTPS Implementation**
  - SSL/TLS encryption
  - Secure certificate management
  - HTTPS-only communication
  - Secure cookie transmission

### Security Monitoring Dashboard

- **Real-Time Security Analytics**
  - Live security metrics display
  - Security event trend analysis
  - Suspicious IP tracking and blocking
  - System health monitoring
  - Security report generation and export
  - Performance monitoring

### Additional Security Measures

- **Advanced Security Features**
  - Request validation middleware
  - Suspicious user agent detection
  - Query parameter validation
  - Circular reference detection
  - Security audit logging
  - Environment-based security configuration
  - Data sanitization
  - Secure query construction
  - Connection security

- **Session Management**
  - Secure session handling
  - Session invalidation
  - Cross-device logout
  - Session versioning

## 🛡️ Security Summary

The ThriftStore application implements a comprehensive security framework with multiple layers of protection:

- **Authentication & Authorization**: JWT tokens, 2FA, role-based access control
- **Data Protection**: Input sanitization, XSS prevention, CSRF protection
- **File Security**: Upload validation, MIME type checking, virus scanning
- **Network Security**: HTTPS, security headers, CORS protection
- **Monitoring**: Activity logging, security dashboard, real-time analytics
- **Bot Prevention**: CAPTCHA integration, rate limiting, suspicious activity detection

All security features are production-ready and follow industry best practices for web application security.
- Production environment hardening
- Security compliance certifications

## 🏗️ Security Architecture

### Multi-Layer Security Approach

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND LAYER                          │
│  • CSRF Token Management                                   │
│  • Secure Cookie Handling                                  │
│  • Input Validation                                        │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   GATEWAY LAYER                            │
│  • Rate Limiting (Strategic)                               │
│  • Security Headers (Helmet)                               │
│  • CORS Configuration                                      │
│  • Request Validation                                      │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                  AUTHENTICATION LAYER                      │
│  • JWT Token Validation                                    │
│  • 2FA OTP Verification                                    │
│  • Session Management                                      │
│  • Role-Based Access Control                               │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   BUSINESS LAYER                           │
│  • Input Sanitization                                      │
│  • File Upload Security                                    │
│  • Database Query Security                                 │
│  • Activity Logging                                        │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   DATA LAYER                               │
│  • MongoDB Injection Prevention                            │
│  • Data Encryption                                         │
│  • Secure Connections                                      │
│  • Backup Security                                         │
└─────────────────────────────────────────────────────────────┘
```

### Security Flow

1. **Request Arrival**: Rate limiting and security headers applied
2. **Authentication**: JWT validation, 2FA if required, role checking
3. **Input Processing**: Validation, sanitization, suspicious activity detection
4. **Business Logic**: Secure operations with activity logging
5. **Data Access**: Sanitized queries with injection prevention
6. **Response**: Secure headers, error handling, logging

## 📚 Documentation

- [Security Implementation Summary](./SECURITY_IMPLEMENTATION_SUMMARY.md)
- [Security Configuration](./config/security.js)
- [Security Audit Script](./scripts/securityAudit.js)
- [Security Middleware](./middleware/security.js)
- [Password Policy](./middleware/passwordPolicy.js)
- [CAPTCHA Implementation](./middleware/captcha.js)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run security audit: `node scripts/securityAudit.js`
5. Submit a pull request

## 📄 License

This project is licensed under the ISC License.

## 👨‍💻 Author

- Puja Purbey

---

**This project demonstrates secure web development practices with comprehensive security monitoring and protection mechanisms.** # Backend_security

## 🔒 HTTPS Implementation

### SSL Certificate Setup

The application now supports HTTPS with SSL certificates for enhanced security.

#### Development Setup

1. **Generate SSL Certificates:**
   ```bash
   node scripts/setup-ssl.js generate
   ```

2. **Check Certificate Status:**
   ```bash
   node scripts/setup-ssl.js check
   ```

3. **View Certificate Information:**
   ```bash
   node scripts/setup-ssl.js info
   ```

#### Production Setup

For production, use certificates from a trusted Certificate Authority (CA):

1. **Set Environment Variables:**
   ```env
   SSL_CERT_PATH=/path/to/your/certificate.pem
   SSL_KEY_PATH=/path/to/your/private-key.pem
   ```

2. **Ensure NODE_ENV=production**

#### SSL Configuration Features

- **Automatic HTTPS/HTTP Fallback**: Uses HTTPS when certificates are available, falls back to HTTP for development
- **Environment-Aware**: Different behavior for development vs production
- **Certificate Validation**: Validates certificate existence and format
- **Secure Headers**: Enhanced security headers when using HTTPS

#### Testing HTTPS

```bash
# Test HTTPS connection
node test/test-https.js
```

### Security Features
