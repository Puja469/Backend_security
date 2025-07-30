#!/usr/bin/env node

/**
 * Security Audit Script for ThriftStore Backend
 * This script performs a comprehensive security audit of the application
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    reset: '\x1b[0m'
};

const log = {
    info: (msg) => console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
    warning: (msg) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
    section: (msg) => console.log(`\n${colors.cyan}=== ${msg} ===${colors.reset}`)
};

class SecurityAudit {
    constructor() {
        this.auditResults = {
            passed: [],
            warnings: [],
            errors: [],
            recommendations: []
        };
    }

    // Check if file exists
    checkFileExists(filePath, description) {
        try {
            if (fs.existsSync(filePath)) {
                this.auditResults.passed.push(`✓ ${description} exists`);
                return true;
            } else {
                this.auditResults.errors.push(`✗ ${description} missing`);
                return false;
            }
        } catch (error) {
            this.auditResults.errors.push(`✗ Error checking ${description}: ${error.message}`);
            return false;
        }
    }

    // Check environment variables
    checkEnvironmentVariables() {
        log.section('Environment Variables Check');

        const requiredEnvVars = [
            'JWT_SECRET',
            'JWT_EXPIRES_IN',
            'MONGODB_URI',
            'NODE_ENV'
        ];

        const optionalEnvVars = [
            'FRONTEND_URL',
            'RATE_LIMIT_WINDOW_MS',
            'RATE_LIMIT_MAX_REQUESTS',
            'AUTH_RATE_LIMIT_MAX',
            'MAX_FILE_SIZE',
            'ALLOWED_FILE_TYPES'
        ];

        // Check if environment file exists (either .env or config/config.env)
        const envFileExists = fs.existsSync('.env') || fs.existsSync('config/config.env');
        if (envFileExists) {
            this.auditResults.passed.push(`✓ Environment file exists`);
        } else {
            this.auditResults.errors.push(`✗ Environment file (.env or config/config.env) missing`);
        }

        // Check required environment variables
        requiredEnvVars.forEach(envVar => {
            if (process.env[envVar]) {
                this.auditResults.passed.push(`✓ Required environment variable ${envVar} is set`);
            } else {
                this.auditResults.errors.push(`✗ Required environment variable ${envVar} is missing`);
            }
        });

        // Check optional environment variables
        optionalEnvVars.forEach(envVar => {
            if (process.env[envVar]) {
                this.auditResults.passed.push(`✓ Optional environment variable ${envVar} is set`);
            } else {
                this.auditResults.warnings.push(`⚠ Optional environment variable ${envVar} is not set`);
            }
        });

        // Check JWT secret security
        if (process.env.JWT_SECRET) {
            if (process.env.JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
                this.auditResults.errors.push('✗ JWT_SECRET is using default value - change in production');
            } else if (process.env.JWT_SECRET.length < 32) {
                this.auditResults.warnings.push('⚠ JWT_SECRET should be at least 32 characters long');
            } else {
                this.auditResults.passed.push('✓ JWT_SECRET is properly configured');
            }
        }
    }

    // Check dependencies
    checkDependencies() {
        log.section('Dependencies Security Check');

        try {
            // Check for security vulnerabilities
            const auditOutput = execSync('npm audit --json', { encoding: 'utf8' });
            const auditData = JSON.parse(auditOutput);

            if (auditData.metadata.vulnerabilities.total === 0) {
                this.auditResults.passed.push('✓ No security vulnerabilities found in dependencies');
            } else {
                this.auditResults.errors.push(`✗ Found ${auditData.metadata.vulnerabilities.total} security vulnerabilities in dependencies`);
                this.auditResults.recommendations.push('Run "npm audit fix" to fix vulnerabilities');
            }

            // Check required security packages
            const requiredPackages = [
                'helmet',
                'express-rate-limit',
                'express-slow-down',
                'express-mongo-sanitize',
                'xss-clean',
                'hpp',
                'bcryptjs',
                'jsonwebtoken',
                'cookie-parser'
            ];

            const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
            const installedPackages = Object.keys(packageJson.dependencies || {});

            requiredPackages.forEach(pkg => {
                if (installedPackages.includes(pkg)) {
                    this.auditResults.passed.push(`✓ Security package ${pkg} is installed`);
                } else {
                    this.auditResults.errors.push(`✗ Security package ${pkg} is missing`);
                }
            });

        } catch (error) {
            this.auditResults.errors.push(`✗ Error checking dependencies: ${error.message}`);
        }
    }

    // Check security middleware implementation
    checkSecurityMiddleware() {
        log.section('Security Middleware Check');

        const securityFiles = [
            { path: 'middleware/security.js', description: 'Security middleware' },
            { path: 'middleware/auth.js', description: 'Authentication middleware' },
            { path: 'middleware/upload.js', description: 'File upload security' },
            { path: 'middleware/passwordValidator.js', description: 'Password validation' },
            { path: 'middleware/passwordPolicy.js', description: 'Password policy' },
            { path: 'middleware/activityLogger.js', description: 'Activity logging' },
            { path: 'validation/securityValidation.js', description: 'Security validation schemas' },
            { path: 'config/security.js', description: 'Security configuration' }
        ];

        securityFiles.forEach(file => {
            this.checkFileExists(file.path, file.description);
        });
    }

    // Check route security implementation
    checkRouteSecurity() {
        log.section('Route Security Check');

        const routeFiles = [
            'routes/AuthRoute.js',
            'routes/UserRoute.js',
            'routes/ItemRoute.js',
            'routes/CategoryRoute.js',
            'routes/SubCategoryRoute.js',
            'routes/CommentRoute.js',
            'routes/OrderRoute.js',
            'routes/NotificationRoute.js'
        ];

        routeFiles.forEach(routeFile => {
            if (this.checkFileExists(routeFile, `Route file ${routeFile}`)) {
                try {
                    const content = fs.readFileSync(routeFile, 'utf8');

                    // Check for security middleware usage
                    const securityChecks = [
                        { pattern: /sanitizeData/, name: 'Data sanitization' },
                        { pattern: /preventXSS/, name: 'XSS prevention' },
                        { pattern: /preventHPP/, name: 'HTTP Parameter Pollution prevention' },
                        { pattern: /detectSuspiciousActivity/, name: 'Suspicious activity detection' },
                        { pattern: /securityHeaders/, name: 'Security headers' },
                        { pattern: /apiLimiter|authLimiter/, name: 'Rate limiting' },
                        { pattern: /protect/, name: 'Authentication protection' },
                        { pattern: /authorize/, name: 'Authorization' },
                        { pattern: /activityLogger/, name: 'Activity logging' }
                    ];

                    securityChecks.forEach(check => {
                        if (check.pattern.test(content)) {
                            this.auditResults.passed.push(`✓ ${check.name} implemented in ${routeFile}`);
                        } else {
                            this.auditResults.warnings.push(`⚠ ${check.name} not found in ${routeFile}`);
                        }
                    });

                } catch (error) {
                    this.auditResults.errors.push(`✗ Error reading ${routeFile}: ${error.message}`);
                }
            }
        });
    }

    // Check main application security
    checkApplicationSecurity() {
        log.section('Application Security Check');

        const appFile = 'app.js';
        if (this.checkFileExists(appFile, 'Main application file')) {
            try {
                const content = fs.readFileSync(appFile, 'utf8');

                const securityChecks = [
                    { pattern: /helmet/, name: 'Helmet.js security headers' },
                    { pattern: /cors/, name: 'CORS configuration' },
                    { pattern: /cookieParser/, name: 'Cookie parser' },
                    { pattern: /morgan/, name: 'Request logging' },
                    { pattern: /express\.json.*limit/, name: 'Request size limiting' },
                    { pattern: /express\.urlencoded.*limit/, name: 'URL encoded size limiting' }
                ];

                securityChecks.forEach(check => {
                    if (check.pattern.test(content)) {
                        this.auditResults.passed.push(`✓ ${check.name} implemented in app.js`);
                    } else {
                        this.auditResults.warnings.push(`⚠ ${check.name} not found in app.js`);
                    }
                });

            } catch (error) {
                this.auditResults.errors.push(`✗ Error reading app.js: ${error.message}`);
            }
        }
    }

    // Check file structure and permissions
    checkFileStructure() {
        log.section('File Structure Security Check');

        // Check for sensitive files that shouldn't be exposed
        const sensitiveFiles = [
            '.env',
            'config/config.env',
            'package-lock.json',
            'node_modules'
        ];

        sensitiveFiles.forEach(file => {
            if (fs.existsSync(file)) {
                if (file === 'node_modules') {
                    this.auditResults.passed.push('✓ node_modules directory exists (expected)');
                } else {
                    this.auditResults.passed.push(`✓ ${file} exists`);
                }
            } else {
                if (file === 'node_modules') {
                    this.auditResults.warnings.push('⚠ node_modules directory missing - run npm install');
                } else {
                    this.auditResults.warnings.push(`⚠ ${file} not found`);
                }
            }
        });

        // Check for .gitignore
        if (this.checkFileExists('.gitignore', '.gitignore file')) {
            try {
                const gitignoreContent = fs.readFileSync('.gitignore', 'utf8');
                const requiredIgnores = [
                    'node_modules',
                    '.env',
                    'config/config.env'
                ];

                requiredIgnores.forEach(ignore => {
                    if (gitignoreContent.includes(ignore)) {
                        this.auditResults.passed.push(`✓ ${ignore} is properly ignored in .gitignore`);
                    } else {
                        this.auditResults.warnings.push(`⚠ ${ignore} should be added to .gitignore`);
                    }
                });

            } catch (error) {
                this.auditResults.errors.push(`✗ Error reading .gitignore: ${error.message}`);
            }
        }
    }

    // Check SSL/HTTPS configuration
    checkSSLConfiguration() {
        log.section('SSL/HTTPS Configuration Check');

        const sslDir = path.join(__dirname, '..', 'ssl');
        const certPath = path.join(sslDir, 'cert.pem');
        const keyPath = path.join(sslDir, 'key.pem');

        // Check SSL directory
        if (fs.existsSync(sslDir)) {
            this.auditResults.passed.push('✓ SSL directory exists');
        } else {
            this.auditResults.warnings.push('⚠ SSL directory not found (HTTPS not configured)');
        }

        // Check certificate files
        if (fs.existsSync(certPath)) {
            this.auditResults.passed.push('✓ SSL certificate file exists');
        } else {
            this.auditResults.warnings.push('⚠ SSL certificate file not found');
        }

        if (fs.existsSync(keyPath)) {
            this.auditResults.passed.push('✓ SSL private key file exists');
        } else {
            this.auditResults.warnings.push('⚠ SSL private key file not found');
        }

        // Check SSL configuration file
        const sslConfigPath = path.join(__dirname, '..', 'config', 'ssl.js');
        if (fs.existsSync(sslConfigPath)) {
            this.auditResults.passed.push('✓ SSL configuration file exists');
        } else {
            this.auditResults.errors.push('✗ SSL configuration file missing');
        }

        // Check SSL setup script
        const sslSetupPath = path.join(__dirname, 'setup-ssl.js');
        if (fs.existsSync(sslSetupPath)) {
            this.auditResults.passed.push('✓ SSL setup script exists');
        } else {
            this.auditResults.warnings.push('⚠ SSL setup script not found');
        }
    }

    // Generate security recommendations
    generateRecommendations() {
        log.section('Security Recommendations');

        const recommendations = [
            'Ensure JWT_SECRET is a strong, unique value in production',
            'Use CA-signed SSL certificates for production deployment',
            'Regularly update dependencies with npm audit',
            'Monitor application logs for suspicious activity',
            'Implement rate limiting for all endpoints',
            'Use environment-specific configurations',
            'Regularly backup and secure database',
            'Implement proper error handling without exposing sensitive information',
            'Consider implementing API versioning',
            'Set up monitoring and alerting for security events',
            'Regularly renew SSL certificates before expiration',
            'Monitor SSL certificate expiration dates'
        ];

        recommendations.forEach(rec => {
            this.auditResults.recommendations.push(`💡 ${rec}`);
        });
    }

    // Run complete audit
    async runAudit() {
        log.info('Starting comprehensive security audit...\n');

        this.checkEnvironmentVariables();
        this.checkDependencies();
        this.checkSecurityMiddleware();
        this.checkRouteSecurity();
        this.checkApplicationSecurity();
        this.checkFileStructure();
        this.checkSSLConfiguration(); // Added SSL/HTTPS check
        this.generateRecommendations();

        // Print results
        this.printResults();
    }

    // Print audit results
    printResults() {
        log.section('Security Audit Results');

        console.log(`\n${colors.green}Passed Checks: ${this.auditResults.passed.length}${colors.reset}`);
        this.auditResults.passed.forEach(check => {
            console.log(`  ${check}`);
        });

        console.log(`\n${colors.yellow}Warnings: ${this.auditResults.warnings.length}${colors.reset}`);
        this.auditResults.warnings.forEach(warning => {
            console.log(`  ${warning}`);
        });

        console.log(`\n${colors.red}Errors: ${this.auditResults.errors.length}${colors.reset}`);
        this.auditResults.errors.forEach(error => {
            console.log(`  ${error}`);
        });

        console.log(`\n${colors.cyan}Recommendations:${colors.reset}`);
        this.auditResults.recommendations.forEach(rec => {
            console.log(`  ${rec}`);
        });

        // Summary
        const totalChecks = this.auditResults.passed.length + this.auditResults.warnings.length + this.auditResults.errors.length;
        const successRate = ((this.auditResults.passed.length / totalChecks) * 100).toFixed(1);

        console.log(`\n${colors.magenta}Summary:${colors.reset}`);
        console.log(`  Total Checks: ${totalChecks}`);
        console.log(`  Passed: ${this.auditResults.passed.length}`);
        console.log(`  Warnings: ${this.auditResults.warnings.length}`);
        console.log(`  Errors: ${this.auditResults.errors.length}`);
        console.log(`  Success Rate: ${successRate}%`);

        if (this.auditResults.errors.length === 0) {
            console.log(`\n${colors.green}🎉 Security audit completed successfully!${colors.reset}`);
        } else {
            console.log(`\n${colors.red}⚠️  Please address the errors above before deployment.${colors.reset}`);
        }
    }
}

// Run the audit
if (require.main === module) {
    const audit = new SecurityAudit();
    audit.runAudit().catch(error => {
        log.error(`Audit failed: ${error.message}`);
        process.exit(1);
    });
}

module.exports = SecurityAudit; 