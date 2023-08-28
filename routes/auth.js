// routes/auth.js
const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../models/User");
const sendMail = require("../utils/sendMail");
const jwt = require("jsonwebtoken");

const router = express.Router();

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const alreadyEmail = await User.findOne({ email: email });
    if (alreadyEmail) {
      return res.status(400).json({ message: "Email already exists" });
    }
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a new user
    const user = new User({ 
      name,
      email,
      password: hashedPassword, 
    });
    // Save the user to the database
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error }); 
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email });

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Compare the provided password with the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.status(200).json({ message: "Login successful", userinfo:user });
    } else {
      res.status(401).json({ message: "Invalid credentials"});
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "An error occurred" });
  }
});

// create activation token
const createActivationToken = (user) => {
  return jwt.sign(user, "sdfsdfsdgsdgsdg", {
    expiresIn: "5m",
  });
};

router.post("/resetpassword", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }
  const finaluser = {
    email: user.email,
    name: user.name,
  };

  const activationToken = createActivationToken(finaluser);
  console.log(
    "🚀 ~ file: auth.js:80 ~ router.post ~ activationToken:",
    activationToken
  );

  const activationUrl = `http://localhost:3000/changepassword/${activationToken}`;

  try {
    await sendMail({
      email: user.email,
      subject: "Reset Your password by clicking on the link below",
      message: `Hello ${user.name}, please click on the link to activate your account: ${activationUrl}`,
    });
    res.status(201).json({
      success: true,
      message: `please check your email:- ${user.email} to activate your account!`,
    });
  } catch (error) {
    return res.status(500).json({ message: error });
  }
});

router.post("/verifyToken", async (req, res) => {
  try {
    const { activation_token, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const verify = jwt.verify(activation_token, "sdfsdfsdgsdgsdg");

    if (!verify) {
      return res.status(400).json({ message: "Invalid token" });
    }

    const email = verify.email;
    const filter = { email: email };
    const update = { password: hashedPassword };

    let user = await User.findOneAndUpdate(filter, update, {
      new: true,
    });
    res
      .status(200)
      .json({
        message: "Password updated successfully",
        updateuser: user,
      });
  } catch (error) {
    return res
      .status(400)
      .json({ message:error.message, error: error.message });
  }
});

module.exports = router;
