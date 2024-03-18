const express = require("express");
const router = express.Router();
const { registerUser, loginUser, isUserValid } = require("../controller/AuthCtrlr");

router.get("/login", (req, res) => {
  res.status(200).send("working fine");
});

router.post("/login", loginUser);

router.post("/register", registerUser);

router.get("/test", isUserValid, (req, res) => {
  res.send("working at auth.js");
});

module.exports = router;
