const nodemailer = require("nodemailer");

// Use environment variables for email configuration
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER || "poojapurbey469@gmail.com", // Use env var or fallback
        pass: process.env.EMAIL_PASS || "cozyaamsjrepckwo" // Use env var or fallback
    }
});

const sendEmail = async (to, subject, text, html = null) => {
    try {
        // Check if email configuration is properly set
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
            console.warn("⚠️ Email credentials not configured in environment variables. Using fallback credentials.");
        }

        const mailOptions = {
            from: process.env.EMAIL_USER || "poojapurbey469@gmail.com",
            to,
            subject,
            text,
            ...(html && { html })
        };

        const result = await transporter.sendMail(mailOptions);
        console.log("✅ Email sent successfully to:", to);
        console.log("📧 Email subject:", subject);
        return result;
    } catch (error) {
        console.error("❌ Error sending email:", error.message);
        console.error("📧 Email details - To:", to, "Subject:", subject);

        // Log specific error details for debugging
        if (error.code === 'EAUTH') {
            console.error("🔐 Authentication failed. Check email credentials.");
        } else if (error.code === 'ECONNECTION') {
            console.error("🌐 Connection failed. Check network or SMTP settings.");
        } else if (error.code === 'ETIMEDOUT') {
            console.error("⏰ Connection timeout. Check network connection.");
        }

        throw error; // Re-throw to handle in calling function
    }
};

// Email templates
const createEmailVerificationTemplate = (userName, otp) => {
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification - ThriftStore</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f8f9fa;
            }
            .container {
                background-color: #ffffff;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #e9ecef;
            }
            .logo {
                font-size: 28px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
            .tagline {
                color: #7f8c8d;
                font-size: 16px;
                margin-bottom: 0;
            }
            .otp-container {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                margin: 25px 0;
            }
            .otp-code {
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 4px;
                margin: 10px 0;
                font-family: 'Courier New', monospace;
            }
            .message {
                margin: 25px 0;
                font-size: 16px;
            }
            .warning {
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
                padding: 15px;
                margin: 20px 0;
                color: #856404;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e9ecef;
                color: #6c757d;
                font-size: 14px;
            }
            .social-links {
                margin-top: 15px;
            }
            .social-links a {
                color: #667eea;
                text-decoration: none;
                margin: 0 10px;
            }
            .social-links a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛍️ ThriftStore</div>
                <p class="tagline">Your Sustainable Shopping Destination</p>
            </div>
            
            <div class="message">
                <h2>Hello ${userName}! 👋</h2>
                <p>Thank you for joining <strong>ThriftStore</strong> - your premier destination for sustainable and affordable shopping!</p>
                <p>To complete your registration and start exploring our amazing collection of pre-loved treasures, please verify your email address using the OTP below:</p>
            </div>
            
            <div class="otp-container">
                <h3>Your Email Verification Code</h3>
                <div class="otp-code">${otp}</div>
                <p>Enter this code on the verification page to activate your account</p>
            </div>
            
            <div class="warning">
                <strong>⚠️ Important:</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>This code will expire in <strong>10 minutes</strong></li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't request this code, please ignore this email</li>
                </ul>
            </div>
            
            <div class="message">
                <p>Once verified, you'll be able to:</p>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>🛒 Browse and purchase from our curated collection</li>
                    <li>💬 Connect with other thrift enthusiasts</li>
                    <li>📱 Access exclusive deals and promotions</li>
                    <li>🌱 Contribute to sustainable shopping practices</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>Welcome to the ThriftStore community! 🌟</p>
                <p>If you have any questions, feel free to reach out to our support team.</p>
                <div class="social-links">
                    <a href="#">Website</a> | 
                    <a href="#">Support</a> | 
                    <a href="#">Privacy Policy</a>
                </div>
                <p style="margin-top: 15px; font-size: 12px;">
                    © 2024 ThriftStore. All rights reserved.<br>
                    Making sustainable shopping accessible to everyone.
                </p>
            </div>
        </div>
    </body>
    </html>
    `;

    const text = `
🛍️ ThriftStore - Your Sustainable Shopping Destination

Hello ${userName}!

Thank you for joining ThriftStore - your premier destination for sustainable and affordable shopping!

To complete your registration and start exploring our amazing collection of pre-loved treasures, please verify your email address using the OTP below:

Your Email Verification Code: ${otp}

Enter this code on the verification page to activate your account.

⚠️ Important:
- This code will expire in 10 minutes
- Never share this code with anyone
- If you didn't request this code, please ignore this email

Once verified, you'll be able to:
- Browse and purchase from our curated collection
- Connect with other thrift enthusiasts
- Access exclusive deals and promotions
- Contribute to sustainable shopping practices

Welcome to the ThriftStore community! 🌟

If you have any questions, feel free to reach out to our support team.

© 2024 ThriftStore. All rights reserved.
Making sustainable shopping accessible to everyone.
    `;

    return { html, text };
};

const createPasswordResetTemplate = (userName, otp) => {
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset - ThriftStore</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f8f9fa;
            }
            .container {
                background-color: #ffffff;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #e9ecef;
            }
            .logo {
                font-size: 28px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
            .tagline {
                color: #7f8c8d;
                font-size: 16px;
                margin-bottom: 0;
            }
            .otp-container {
                background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                margin: 25px 0;
            }
            .otp-code {
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 4px;
                margin: 10px 0;
                font-family: 'Courier New', monospace;
            }
            .message {
                margin: 25px 0;
                font-size: 16px;
            }
            .warning {
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
                padding: 15px;
                margin: 20px 0;
                color: #856404;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e9ecef;
                color: #6c757d;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛍️ ThriftStore</div>
                <p class="tagline">Your Sustainable Shopping Destination</p>
            </div>
            
            <div class="message">
                <h2>Hello ${userName}! 🔐</h2>
                <p>We received a request to reset your password for your <strong>ThriftStore</strong> account.</p>
                <p>To proceed with the password reset, please use the OTP below:</p>
            </div>
            
            <div class="otp-container">
                <h3>Your Password Reset Code</h3>
                <div class="otp-code">${otp}</div>
                <p>Enter this code on the password reset page</p>
            </div>
            
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>This code will expire in <strong>10 minutes</strong></li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't request a password reset, please ignore this email</li>
                    <li>Your account security is important to us</li>
                </ul>
            </div>
            
            <div class="message">
                <p>If you have any concerns about your account security, please contact our support team immediately.</p>
            </div>
            
            <div class="footer">
                <p>Stay safe and happy thrifting! 🛒</p>
                <p>© 2024 ThriftStore. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;

    const text = `
🛍️ ThriftStore - Password Reset

Hello ${userName}!

We received a request to reset your password for your ThriftStore account.

To proceed with the password reset, please use the OTP below:

Your Password Reset Code: ${otp}

Enter this code on the password reset page.

⚠️ Security Notice:
- This code will expire in 10 minutes
- Never share this code with anyone
- If you didn't request a password reset, please ignore this email
- Your account security is important to us

If you have any concerns about your account security, please contact our support team immediately.

Stay safe and happy thrifting! 🛒

© 2024 ThriftStore. All rights reserved.
    `;

    return { html, text };
};

const createLoginVerificationTemplate = (userName, otp) => {
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Verification - ThriftStore</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f8f9fa;
            }
            .container {
                background-color: #ffffff;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #e9ecef;
            }
            .logo {
                font-size: 28px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
            .tagline {
                color: #7f8c8d;
                font-size: 16px;
                margin-bottom: 0;
            }
            .otp-container {
                background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                margin: 25px 0;
            }
            .otp-code {
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 4px;
                margin: 10px 0;
                font-family: 'Courier New', monospace;
            }
            .message {
                margin: 25px 0;
                font-size: 16px;
            }
            .warning {
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
                padding: 15px;
                margin: 20px 0;
                color: #856404;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e9ecef;
                color: #6c757d;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛍️ ThriftStore</div>
                <p class="tagline">Your Sustainable Shopping Destination</p>
            </div>
            
            <div class="message">
                <h2>Hello ${userName}! 🔐</h2>
                <p>We received a login request for your <strong>ThriftStore</strong> account.</p>
                <p>To complete your login and access your account, please use the verification code below:</p>
            </div>
            
            <div class="otp-container">
                <h3>Your Login Verification Code</h3>
                <div class="otp-code">${otp}</div>
                <p>Enter this code to complete your login</p>
            </div>
            
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>This code will expire in <strong>5 minutes</strong></li>
                    <li>Never share this code with anyone</li>
                    <li>If you didn't attempt to login, please contact support immediately</li>
                    <li>This helps keep your account secure</li>
                </ul>
            </div>
            
            <div class="message">
                <p>Once verified, you'll have access to:</p>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>🛒 Your shopping cart and wishlist</li>
                    <li>📦 Order history and tracking</li>
                    <li>👤 Profile and account settings</li>
                    <li>💬 Messages and notifications</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>Welcome back to ThriftStore! 🛒</p>
                <p>© 2024 ThriftStore. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;

    const text = `
🛍️ ThriftStore - Login Verification

Hello ${userName}!

We received a login request for your ThriftStore account.

To complete your login and access your account, please use the verification code below:

Your Login Verification Code: ${otp}

Enter this code to complete your login.

⚠️ Security Notice:
- This code will expire in 5 minutes
- Never share this code with anyone
- If you didn't attempt to login, please contact support immediately
- This helps keep your account secure

Once verified, you'll have access to:
- Your shopping cart and wishlist
- Order history and tracking
- Profile and account settings
- Messages and notifications

Welcome back to ThriftStore! 🛒

© 2024 ThriftStore. All rights reserved.
    `;

    return { html, text };
};

module.exports = {
    sendEmail,
    createEmailVerificationTemplate,
    createPasswordResetTemplate,
    createLoginVerificationTemplate
};
