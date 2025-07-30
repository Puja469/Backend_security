const nodemailer = require("nodemailer");

// Use environment variables for email configuration
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER || "poojapurbey469@gmail.com", // Use env var or fallback
        pass: process.env.EMAIL_PASS || "cozyaamsjrepckwo" // Use env var or fallback
    }
});

const sendEmail = async (to, subject, text) => {
    try {
        // Check if email configuration is properly set
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
            console.warn("⚠️ Email credentials not configured in environment variables. Using fallback credentials.");
        }

        const mailOptions = {
            from: process.env.EMAIL_USER || "poojapurbey469@gmail.com",
            to,
            subject,
            text
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

module.exports = sendEmail;
