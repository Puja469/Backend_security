const https = require('https');
const fs = require('fs');

/**
 * Test HTTPS functionality
 */

// Test configuration
const testConfig = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/auth/login',
    method: 'GET',
    rejectUnauthorized: false // Allow self-signed certificates
};

console.log('🔍 Testing HTTPS connection...');

// Make HTTPS request
const req = https.request(testConfig, (res) => {
    console.log(`✅ HTTPS Response Status: ${res.statusCode}`);
    console.log(`🔒 HTTPS Headers:`);
    console.log(`   - Content-Type: ${res.headers['content-type']}`);
    console.log(`   - Server: ${res.headers['server']}`);

    // Check for security headers
    const securityHeaders = [
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'strict-transport-security'
    ];

    console.log(`🛡️  Security Headers:`);
    securityHeaders.forEach(header => {
        if (res.headers[header]) {
            console.log(`   ✅ ${header}: ${res.headers[header]}`);
        } else {
            console.log(`   ⚠️  ${header}: Not found`);
        }
    });

    let data = '';
    res.on('data', (chunk) => {
        data += chunk;
    });

    res.on('end', () => {
        console.log(`📄 Response Body: ${data.substring(0, 100)}...`);
        console.log('🎉 HTTPS test completed successfully!');
    });
});

req.on('error', (error) => {
    console.error('❌ HTTPS Test Failed:', error.message);
    console.log('💡 Make sure the server is running with HTTPS enabled');
});

req.end();