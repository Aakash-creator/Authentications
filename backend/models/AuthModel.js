const mongoose = require("mongoose");

const loginModel = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});

const registerModel = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["Admin", "User", "Owner"], default: "User" },
  },
  { timestamps: true }
);

const login = mongoose.model("login", loginModel);
const register = mongoose.model("register", registerModel);

module.exports = { login, register };
