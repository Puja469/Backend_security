#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * SSL Certificate Setup Script
 * Helps generate and manage SSL certificates for development and production
 */

class SSLSetup {
    constructor() {
        this.sslDir = path.join(__dirname, '..', 'ssl');
        this.certPath = path.join(this.sslDir, 'cert.pem');
        this.keyPath = path.join(this.sslDir, 'key.pem');
    }

    /**
     * Create SSL directory if it doesn't exist
     */
    createSSLDirectory() {
        if (!fs.existsSync(this.sslDir)) {
            fs.mkdirSync(this.sslDir, { recursive: true });
            console.log('✅ SSL directory created');
        }
    }

    /**
     * Generate self-signed certificates for development
     */
    generateDevelopmentCertificates() {
        try {
            this.createSSLDirectory();

            console.log('🔐 Generating self-signed SSL certificates for development...');

            const command = `openssl req -x509 -newkey rsa:4096 -keyout "${this.keyPath}" -out "${this.certPath}" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=ThriftStore/CN=localhost"`;

            execSync(command, { stdio: 'inherit' });

            console.log('✅ Development SSL certificates generated successfully!');
            console.log(`📁 Certificate: ${this.certPath}`);
            console.log(`🔑 Private Key: ${this.keyPath}`);
            console.log('⚠️  Note: These are self-signed certificates for development only');

        } catch (error) {
            console.error('❌ Error generating SSL certificates:', error.message);
            console.log('💡 Make sure OpenSSL is installed on your system');
            process.exit(1);
        }
    }

    /**
     * Check if certificates exist
     */
    checkCertificates() {
        const certExists = fs.existsSync(this.certPath);
        const keyExists = fs.existsSync(this.keyPath);

        console.log('🔍 Checking SSL certificates...');
        console.log(`📄 Certificate: ${certExists ? '✅ Found' : '❌ Missing'}`);
        console.log(`🔑 Private Key: ${keyExists ? '✅ Found' : '❌ Missing'}`);

        return certExists && keyExists;
    }

    /**
     * Validate certificate format
     */
    validateCertificates() {
        try {
            if (!this.checkCertificates()) {
                return false;
            }

            // Try to read certificates
            const cert = fs.readFileSync(this.certPath);
            const key = fs.readFileSync(this.keyPath);

            console.log('✅ SSL certificates are valid and readable');
            return true;

        } catch (error) {
            console.error('❌ Error validating certificates:', error.message);
            return false;
        }
    }

    /**
     * Show certificate information
     */
    showCertificateInfo() {
        try {
            if (!fs.existsSync(this.certPath)) {
                console.log('❌ Certificate not found');
                return;
            }

            console.log('📋 Certificate Information:');
            const command = `openssl x509 -in "${this.certPath}" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:)"`;
            execSync(command, { stdio: 'inherit' });

        } catch (error) {
            console.error('❌ Error reading certificate info:', error.message);
        }
    }

    /**
     * Clean up certificates
     */
    cleanup() {
        try {
            if (fs.existsSync(this.certPath)) {
                fs.unlinkSync(this.certPath);
                console.log('🗑️  Certificate removed');
            }

            if (fs.existsSync(this.keyPath)) {
                fs.unlinkSync(this.keyPath);
                console.log('🗑️  Private key removed');
            }

            if (fs.existsSync(this.sslDir) && fs.readdirSync(this.sslDir).length === 0) {
                fs.rmdirSync(this.sslDir);
                console.log('🗑️  SSL directory removed');
            }

        } catch (error) {
            console.error('❌ Error cleaning up:', error.message);
        }
    }

    /**
     * Show help information
     */
    showHelp() {
        console.log(`
🔐 SSL Certificate Setup Script

Usage: node scripts/setup-ssl.js [command]

Commands:
  generate    Generate new self-signed certificates for development
  check       Check if certificates exist and are valid
  info        Show certificate information
  cleanup     Remove existing certificates
  help        Show this help message

Examples:
  node scripts/setup-ssl.js generate
  node scripts/setup-ssl.js check
  node scripts/setup-ssl.js info
  node scripts/setup-ssl.js cleanup

Note: For production, use certificates from a trusted Certificate Authority (CA)
    `);
    }
}

// Main execution
if (require.main === module) {
    const sslSetup = new SSLSetup();
    const command = process.argv[2] || 'help';

    switch (command) {
        case 'generate':
            sslSetup.generateDevelopmentCertificates();
            break;
        case 'check':
            sslSetup.checkCertificates();
            break;
        case 'info':
            sslSetup.showCertificateInfo();
            break;
        case 'cleanup':
            sslSetup.cleanup();
            break;
        case 'help':
        default:
            sslSetup.showHelp();
            break;
    }
}

module.exports = SSLSetup;