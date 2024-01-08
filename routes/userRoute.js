const express = require('express');
const router = express.Router();
const { createUser, deleteUser, updateUser } = require('../controllers/userController');
const { auth } = require('../middlewares/auth');
const {signup , login} = require('../controllers/authController');
const { verifyOtp } = require('../controllers/authController');


router.post("/login", login);
router.post("/signup", signup);

// Routes that require authentication
router.delete("/", auth, deleteUser);
router.put("/", auth, updateUser);

// TODO GOOGLE AUTH
// router.get('/google', userController.googleAuth);
// router.get('/google/redirect', authController.googleRedirect);

//TODO OTP AUTH
router.post('/otp/verify',auth,verifyOtp);
router.post('/otp/resend',auth, authController.resendOtp);

module.exports = router;
