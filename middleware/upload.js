const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

// Max file size: 5MB (from environment variable)
const maxSize = parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024;

// Allowed MIME types for images
const allowedMimeTypes = [
  'image/jpeg',
  'image/jpg', 
  'image/png',
  'image/gif',
  'image/webp'
];

// Allowed file extensions
const allowedExtensions = [".jpg", ".jpeg", ".png", ".gif", ".webp"];

// ===========================
// Secure storage configuration
// ===========================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "../public/uploads");
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Generate secure random filename
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    const fileName = `${randomBytes}${ext}`;
    cb(null, fileName);
  }
});

// ===========================
// Enhanced file filter with MIME type validation
// ===========================
const secureFileFilter = (req, file, cb) => {
  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase();
  if (!allowedExtensions.includes(ext)) {
    return cb(
      new Error("Unsupported file type. Only JPG, JPEG, PNG, GIF, and WebP are allowed."),
      false
    );
  }

  // Check MIME type
  if (!allowedMimeTypes.includes(file.mimetype)) {
    return cb(
      new Error("Invalid file type detected. Only image files are allowed."),
      false
    );
  }

  // Additional security checks
  if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
    return cb(
      new Error("Invalid filename detected."),
      false
    );
  }

  cb(null, true);
};

// ===========================
// Virus scanning simulation (replace with actual antivirus service)
// ===========================
const scanForViruses = (file) => {
  return new Promise((resolve, reject) => {
    // Simulate virus scanning
    setTimeout(() => {
      // Check for suspicious patterns in filename
      const suspiciousPatterns = [
        /\.exe$/i,
        /\.bat$/i,
        /\.cmd$/i,
        /\.scr$/i,
        /\.pif$/i,
        /\.com$/i
      ];
      
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(file.originalname)) {
          return reject(new Error("Suspicious file type detected"));
        }
      }
      
      resolve(true);
    }, 100);
  });
};

// ===========================
// Enhanced multer configuration
// ===========================
const upload = multer({
  storage: storage,
  fileFilter: secureFileFilter,
  limits: { 
    fileSize: maxSize,
    files: 1 // Only allow 1 file at a time
  },
}).single("image"); // Expect field name to be "image"

// ===========================
// Enhanced upload middleware with virus scanning
// ===========================
module.exports = async (req, res, next) => {
  upload(req, res, async function (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ 
          status: 'error',
          message: `File too large. Maximum size is ${Math.round(maxSize / 1024 / 1024)}MB` 
        });
      }
      return res.status(400).json({ 
        status: 'error',
        message: `Upload error: ${err.message}` 
      });
    } else if (err) {
      return res.status(400).json({ 
        status: 'error',
        message: err.message 
      });
    }

    // If file was uploaded, scan for viruses
    if (req.file) {
      try {
        await scanForViruses(req.file);
        
        // Add file metadata to request
        req.fileInfo = {
          originalName: req.file.originalname,
          filename: req.file.filename,
          size: req.file.size,
          mimetype: req.file.mimetype,
          uploadedAt: new Date()
        };
        
      } catch (scanError) {
        // Remove the uploaded file if virus scan fails
        if (req.file.path && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        return res.status(400).json({ 
          status: 'error',
          message: scanError.message 
        });
      }
    }

    next();
  });
};
