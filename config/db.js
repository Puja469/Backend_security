const mongoose = require("mongoose");

const connectDB = async () => {
    try {
        const mongoURI = process.env.MONGODB_URI || "mongodb://localhost:27017/db_thrift_store_app";

        const options = {
            // Modern MongoDB connection options
            maxPoolSize: 10, // Maximum number of connections in the pool
            serverSelectionTimeoutMS: 5000, // Timeout for server selection
            socketTimeoutMS: 45000, // Timeout for socket operations
            // Authentication if provided
            ...(process.env.MONGODB_USER && process.env.MONGODB_PASS && {
                auth: {
                    username: process.env.MONGODB_USER,
                    password: process.env.MONGODB_PASS
                },
                authSource: process.env.MONGODB_AUTH_SOURCE || 'admin'
            })
        };

        await mongoose.connect(mongoURI, options);
        console.log("✅ MongoDB connected successfully");

        // Handle connection events
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err);
        });

        mongoose.connection.on('disconnected', () => {
            console.warn('⚠️ MongoDB disconnected');
        });

        // Graceful shutdown
        process.on('SIGINT', async () => {
            await mongoose.connection.close();
            console.log('MongoDB connection closed through app termination');
            process.exit(0);
        });

    } catch (error) {
        console.error("❌ MongoDB connection failed:", error.message);
        process.exit(1);
    }
};

module.exports = connectDB;