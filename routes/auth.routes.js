const authRouter = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User.model");

authRouter.post("/signup", async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    res.status(401).json({ message: "All input fields are required." });
    return;
  }

  try {
    const foundUser = await User.findOne({ email: email });
    if (foundUser) {
      res.status(401).json({ message: "User already exist." });
      return;
    }
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);
    const createdUser = await User.create({
      email,
      password: hashedPassword,
      name,
    });
    res.json(createdUser);
  } catch (error) {
    res.status(500).json({ message: "internal server error" });
  }
});

authRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(401).json({ message: "All input fields are required." });
    return;
  }
  try {
    const foundUser = await User.findOne({ email });
    if (!foundUser) {
      res
        .status(401)
        .json({ message: "Email does not exist, please register first" });
      return;
    }
    const passwordMatch = await bcrypt.compare(password, foundUser.password);
    if (!passwordMatch) {
      res.status(401).json({ message: "wrong email or password" });
      return;
    }

    const payload = {
      _id: foundUser._id,
      email: foundUser.email,
      name: foundUser.name,
    };

    const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
      algorithm: "HS256",
      expiresIn: "6h",
    });

    res.status(200).json({ authToken });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "internal server error" });
  }
});

module.exports = authRouter;
