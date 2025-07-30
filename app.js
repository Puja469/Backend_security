require("dotenv").config({ path: "./config/config.env" });

const express = require("express");
const helmet = require("helmet");
const { Server } = require("socket.io");
const connectDb = require("./config/db");
const path = require("path");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const errorHandler = require("./middleware/errorHandler");
const fs = require("fs");
const https = require("https");

const app = express();

// ---------------- HTTPS Server Setup ----------------
const key = fs.readFileSync("key.pem");      // Your private key
const cert = fs.readFileSync("cert.pem");    // Your certificate
const server = https.createServer({ key, cert }, app);

// ---------------- Security Middleware ----------------
const FRONTEND_ORIGINS = [
  "https://localhost:5173",
  "https://localhost:5177",
  "https://localhost:3000",
];

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "wss:", ...FRONTEND_ORIGINS],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

// ---------------- CORS ----------------
const corsOptions = {
  origin: FRONTEND_ORIGINS,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  exposedHeaders: ["Set-Cookie"],
  maxAge: 86400,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());
if (process.env.NODE_ENV !== "test") app.use(morgan("combined"));

// ---------------- Health Check Endpoint ----------------
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", https: false });
});

// ---------------- Static Folders ----------------
app.use("/item_images", express.static("item_images"));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// ---------------- Routers ----------------
app.use("/api/user", require("./routes/UserRoute"));
app.use("/api/item", require("./routes/ItemRoute"));
app.use("/api/category", require("./routes/CategoryRoute"));
app.use("/api/subcategory", require("./routes/SubCategoryRoute"));
app.use("/api/auth", require("./routes/AuthRoute"));
app.use("/api/notifications", require("./routes/NotificationRoute"));
app.use("/api/comments", require("./routes/CommentRoute"));
app.use("/api/orders", require("./routes/OrderRoute"));
app.use("/api/security", require("./routes/SecurityRoute"));
app.use("/api/csrf", require("./routes/CSRFRoute"));

// ---------------- Database ----------------
connectDb();

// ---------------- Socket.IO ----------------
const io = new Server(server, {
  cors: {
    origin: FRONTEND_ORIGINS,
    methods: ["GET", "POST"],
    credentials: true,
  },
  transports: ["websocket", "polling"],
});

io.on("connection", (socket) => {
  console.log("✅ User connected:", socket.id);

  socket.on("joinNotifications", (userId) => {
    if (!userId) return console.error("UserId is missing for notifications");
    socket.join(userId);
    console.log(`📢 User ${userId} joined notifications room.`);
  });

  socket.on("sendNotification", ({ userId, notification }) => {
    if (!userId || !notification)
      return console.error("Notification/UserId missing");
    console.log(`📩 Notification for ${userId}:`, notification);
    io.to(userId).emit("newNotification", notification);
  });

  socket.on("disconnect", () => {
    console.log("❌ User disconnected:", socket.id);
  });
});

app.set("socketio", io);

// ---------------- Start HTTP Server ----------------
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`🚀 HTTP server running at https://localhost:${port}`);
});

// ---------------- Error Handlers ----------------
app.use(errorHandler);
app.use("*", (req, res) => {
  res.status(404).json({
    status: "error",
    message: `Route ${req.originalUrl} not found`,
  });
});

module.exports = app;
