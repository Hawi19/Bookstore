import express from "express";
import bcrypt from 'bcryptjs'
import jwt from "jsonwebtoken";
import { SECRET_KEY } from "../authMiddleware.js";
import { User } from "../models/userModel.js";

const router = express.Router();
router.post("/signup", async (request, response) => {
  try {
    const { username, email, password } = request.body;
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return response
        .status(400)
        .json({ message: "Username or email already exist" });
    }
    //hash the pasworod
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    //create a new user
    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
    });
    return response.status(201).json(newUser);
  } catch (error) {
    console.error("Signup error:", error);
    response.status(500).send({ message: error.message });
  }
});

router.post("/login", async (request, response) => {
  try {
    const { username, password } = request.body;
    //Find the user by username
    const user = await User.findOne({ username });
    if (!user) {
      return response.status(400).json({ message: "User not found" });
    }
    //check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return response.status(401).json({ message: "Invalid Password" });
    }

    const token = jwt.sign(
      { userId: user._id, isLogged: true },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    console.log(token);

    return response.status(200).json({ token, username: user.username });
  } catch (error) {
    console.log(error.message);
    response.status(500).send({ message: error.message });
  }
});

export default router;
