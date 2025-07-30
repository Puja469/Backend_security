module.exports = (req, res, next) => {
    const password = req.body.password;
    const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,20}$/;
  
    if (!pattern.test(password)) {
      return res.status(400).json({
        message:
          "Password must be 8–20 characters with uppercase, lowercase, number, and special character."
      });
    }
  
    next();
  };
  