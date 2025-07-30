const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

/**
 * SSL Configuration for HTTPS
 * Handles both development (self-signed) and production (CA-signed) certificates
 */

class SSLConfig {
    constructor() {
        this.isDevelopment = process.env.NODE_ENV !== 'production';
        this.sslOptions = null;
    }

    /**
     * Load SSL certificates
     */
    loadCertificates() {
        try {
            if (this.isDevelopment) {
                // Development: Use self-signed certificates
                const certPath = path.join(__dirname, '..', 'ssl', 'cert.pem');
                const keyPath = path.join(__dirname, '..', 'ssl', 'key.pem');

                if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
                    this.sslOptions = {
                        key: fs.readFileSync(keyPath),
                        cert: fs.readFileSync(certPath)
                    };
                    console.log('🔒 SSL certificates loaded for development');
                    return true;
                } else {
                    console.warn('⚠️  SSL certificates not found. Running in HTTP mode.');
                    return false;
                }
            } else {
                // Production: Use CA-signed certificates
                const certPath = process.env.SSL_CERT_PATH || path.join(__dirname, '..', 'ssl', 'cert.pem');
                const keyPath = process.env.SSL_KEY_PATH || path.join(__dirname, '..', 'ssl', 'key.pem');

                if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
                    this.sslOptions = {
                        key: fs.readFileSync(keyPath),
                        cert: fs.readFileSync(certPath)
                    };
                    console.log('🔒 SSL certificates loaded for production');
                    return true;
                } else {
                    console.error('❌ SSL certificates required for production but not found');
                    return false;
                }
            }
        } catch (error) {
            console.error('❌ Error loading SSL certificates:', error.message);
            return false;
        }
    }

    /**
     * Create server (HTTPS or HTTP)
     */
    createServer(app) {
        if (this.sslOptions) {
            // Create HTTPS server
            const server = https.createServer(this.sslOptions, app);
            return { server, isHttps: true };
        } else {
            // Fallback to HTTP server
            const server = http.createServer(app);
            return { server, isHttps: false };
        }
    }

    /**
     * Get server startup message
     */
    getStartupMessage(port) {
        if (this.sslOptions) {
            return {
                message: `🚀 Server running on https://localhost:${port}`,
                details: [
                    `🔒 HTTPS enabled with SSL certificates`,
                    `⚠️  Note: You may see a security warning for self-signed certificates in development`
                ]
            };
        } else {
            return {
                message: `🚀 Server running on http://localhost:${port}`,
                details: [
                    `⚠️  Running in HTTP mode (no SSL certificates found)`,
                    `💡 For production, ensure SSL certificates are properly configured`
                ]
            };
        }
    }

    /**
     * Validate SSL configuration
     */
    validate() {
        if (!this.isDevelopment && !this.sslOptions) {
            throw new Error('SSL certificates are required for production environment');
        }
        return true;
    }
}

module.exports = SSLConfig;