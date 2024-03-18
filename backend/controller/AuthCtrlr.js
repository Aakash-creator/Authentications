const { login, register } = require("../models/AuthModel");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const isThere = await register.findOne({ username });

    if (isThere === null) {
      res.status(400).send("User does not exist, register user before trying.");
    } else {
      const userId = isThere._id;
      if (isThere.username === username) {
        if (await bcrypt.compare(password, isThere.password)) {
          const accesstoken = JWT.sign({ username, userId }, process.env.JWTACCESSTOKENSECRET, {
            expiresIn: "8s",
          });
          const refreshtoken = JWT.sign({ username, userId }, process.env.JWTREFRESHTOKENSECRET, {
            expiresIn: "12m",
          });

          res.cookie("accesstoken", accesstoken, {
            // maxAge: 60000,
            httpOnly: true,
            secure: true,
            // sameSite: "Strict",
          });

          res.cookie("refreshtoken", refreshtoken, {
            // maxAge: 300000,
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
          });
          res.status(200).json({ accesstoken, refreshtoken, login: true });
        } else {
          res.status(401).json({ login: false });
        }
      }
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
};

const registerUser = async (req, res) => {
  try {
    const { name, username, password } = req.body;
    const isThere = await register.findOne({ username }); //check if user exists returns an object|null

    if (isThere === null) {
      //if null then then user does not exist
      const hashPass = await bcrypt.hash(password, 12);
      const data = await register.create({ name, username, password: hashPass }).then((dt) => {
        //create register user
        console.log(dt); // remove later
        res.status(201).send("User Created Sucessfully");
      });
    } else {
      if (isThere.username === username) {
        res.status(400).send(`User already exist using username ${username}, try other usernames`); // if user exist retn 400
      }
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
};

const isUserValid = async (req, res, next) => {
  try {
    const accesstoken = req.cookies.accesstoken;
    if (!accesstoken) {
      renewToken(req, res, next);
      next();
    } else {
      JWT.verify(accesstoken, process.env.JWTACCESSTOKENSECRET, (err, decode) => {
        if (err) {
          console.log(err);
          res.status(401).json({ valid: false, message: "Invalid access token" });
        } else {
          res.status(200).json({ msg: "Accesstoken Valid" });
          next();
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
};

const renewToken = async (req, res, next) => {
  try {
    const refreshtoken = req.cookies.refreshtoken;
    if (refreshtoken) {
      JWT.verify(refreshtoken, process.env.JWTREFRESHTOKENSECRET, (err, decode) => {
        if (err) {
          console.log(err);
          res.status(401).json({ valid: false, message: "Invalid refresh token" });
        } else {
          username = decode.username;
          userId = decode.userId;
          const accesstoken = JWT.sign({ username, userId }, process.env.JWTACCESSTOKENSECRET, {
            expiresIn: "10s",
          });

          res.cookie("accesstoken", accesstoken, {
            maxAge: 60000,
            httpOnly: true,
            secure: true,
          });
          res.status(200).json({ msg: "Accesstoken Renewed" });
          next();
        }
      });
    } else {
      // res.status(401).json({ valid: false, message: "No token provided" });
      next();
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
};

module.exports = { loginUser, registerUser, isUserValid };
