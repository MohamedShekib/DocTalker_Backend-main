// authController.js
const User = require("../models/user");
const bcrypt = require("bcrypt");
const OTP = require("../models/otp");
const { generateToken } = require("../utils/generateToken");
// TODO : sperate the email utils from the auth controller in th efuture
const { sendOTPEmail } = require("../utils/emailUtils");
const { generateOTP } = require("../utils/generateOTP");
const { validateEmail } = require("../utils/emailVaildation");
const nodemailer = require('nodemailer');


const transporter = nodemailer.createTransport({
  service: 'hotmail',
  auth: {
    user: process.env.HOTMAIL_EMAIL, 
    pass: process.env.HOTMAIL_PASSWORD,
  },
});



exports.signup = async (req, res) => {

  try {

  const { firstName, lastName, email, password } = req.body;
  
  // check if user already exists
  let user = await User.findOne({ email });
  if (user) {
    return res.status(400).json({ error: "Email already registered." });
  }
  
  // Hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  
  // Create (Add) a new user
  user = new User({
    firstName,
    lastName,
    email,
    password: hashedPassword,
  });

  await user.save();

  // Generate and store OTP
  const otp = generateOTP();
  const otpExpiresIn = new Date(Date.now() + 20 * 60 * 1000);
  console.log(otp, otpExpiresIn);

  const mailOptions = {
    from: process.env.HOTMAIL_EMAIL,
    to: email,
    subject: 'Your OTP for Verification',
    text: `Your OTP is: ${otp}`,
  };


  // the email is sent to the user
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      // Handle error by deleting the user and the OTP document
      User.findByIdAndDelete(user._id)
        .then(() => {
          console.error("Signup Error:", error);
          res.status(500).json({ error: 'Failed to send OTP' });
        })
        .catch((deleteError) => {
          console.error("Delete User Error:", deleteError);
          res.status(500).json({ error: 'Failed to send OTP and delete user' });
        });
      }else{
        // sent successfully
        // TODO: filter the user object before sending it to the client
        res.status(200).json({ ...user._doc, token: generateToken({ _id: user._id }) });
      }
    });



  const otpDocument = new OTP({
    email,
    otp,
    otpExpiresIn,
  });

  await otpDocument.save();

  

  } catch (error) {

    // handle error by deleting the user and the otp document
    const { email } = req.body;

    let user = await User.findOne({ email });
    if (user) {
      await User.findByIdAndDelete(user._id);
    }

    // if (otpDocument) {
    //   await OTP.findByIdAndDelete(otpDocument._id);
    // }
    console.error("Signup Error:", error);
    res.status(500).json({ message: "Unexpected error during signup." });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email format." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found." });
    }

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password." });
    }

    res.status(200).json({ ...user._doc, token: generateToken({ _id: user._id }) });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: "Unexpected error during login." });
  }
};

exports.verifyOtp = async (req, res) => {
    try {
      const { email, otp } = req.body;
  
      const otpDocument = await OTP.findOne({ email });
  
      if (!otpDocument) {
        return res.status(400).json({ error: 'No OTP found for the provided email.' });
      }
      
      // handle OTP expiry
      if (otpDocument.otp !== otp || otpDocument.otpExpiresIn < new Date(Date.now())) {
        return res.status(400).json({ error: 'Invalid or expired OTP.' });
      }
  
      // Mark the user as verified
      const user = await User.findOne({ email });
      user.isVerified = true;
      await user.save();

      // now user can login
  
      // Delete the OTP document
      await OTP.deleteOne({ _id: otpDocument._id });
  
      // Generate and return the JWT token using the existing function
      const token = generateToken({ _id: user._id });
      res.json({ token });
    } catch (error) {
      console.error("OTP Verification Error:", error);
      res.status(500).json({ error: "Unexpected error during OTP verification." });
    }
  };

 
  

// Other necessary imports and functions (e.g., generateOTP) go here
