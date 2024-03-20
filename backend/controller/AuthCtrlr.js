const { login, register } = require("../models/AuthModel");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

//get user data as profile

const UserData = async (req, res) => {
  const { username } = req.body;
  res.status(200).json(username);
  try {
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
};

const loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const isThere = await register.findOne({ username });

    if (isThere === null) {
      res.json("User does not exist, register user before trying"); //.status(400)
    } else {
      const userId = isThere._id;
      if (isThere.username === username) {
        if (await bcrypt.compare(password, isThere.password)) {
          const accesstoken = JWT.sign({ username, userId }, process.env.JWTACCESSTOKENSECRET, {
            expiresIn: "10m",
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
          res.status(200).json("Login Sucessfull!"); // for testing send accesstoken, refreshtoken
        } else {
          res.json("Incorrect Credentials");
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
    const role = "User";
    const isThere = await register.findOne({ username }); //check if user exists returns an object|null

    if (isThere === null) {
      //if null then then user does not exist
      const hashPass = await bcrypt.hash(password, 12);
      const data = await register.create({ name, username, password: hashPass }).then((dt) => {
        //create register user
        console.log(dt); // remove later
        res.status(201).json(dt);
      });
    } else {
      if (isThere.username === username) {
        res.json(`User already exist using username ${username}, try other usernames`);
      }
    }
  } catch (err) {
    console.log(err);
    res.status(500).json("Internal Server Error");
  }
};

const isUserValid = async (req, res, next) => {
  try {
    const accesstoken = req.cookies.accesstoken;
    const refreshtoken = req.cookies.refreshtoken;

    if (!accesstoken) {
      if (!refreshtoken) {
        return res.status(401).json({ message: "User not logged in" });
      } else {
        JWT.verify(refreshtoken, process.env.JWTREFRESHTOKENSECRET, (err, decode) => {
          if (err) {
            console.log(err);
            return res.status(401).json({ valid: false, message: "Invalid refresh token" });
          } else {
            username = decode.username;
            userId = decode.userId;
            const newAccessToken = JWT.sign(
              { username, userId },
              process.env.JWTACCESSTOKENSECRET,
              {
                expiresIn: "10s",
              }
            );

            res.cookie("accesstoken", newAccessToken, {
              maxAge: 60000,
              httpOnly: true,
              secure: true,
            });
            next();
          }
        });
      }
    } else {
      JWT.verify(accesstoken, process.env.JWTACCESSTOKENSECRET, (err, decode) => {
        if (err) {
          console.log(err);
          return res.status(401).json({ valid: false, message: "Invalid access token" });
        } else {
          return next();
        }
      });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).send("Internal Server Error");
  }
};

// const isUserValid = async (req, res, next) => {
//   try {
//     const accesstoken = req.cookies.accesstoken;
//     if (!accesstoken) {
//       renewToken(req, res, next);
//       next();
//     } else {
//       JWT.verify(accesstoken, process.env.JWTACCESSTOKENSECRET, (err, decode) => {
//         if (err) {
//           console.log(err);
//           res.status(401).json({ valid: false, message: "Invalid access token" });
//         } else {
//           res.status(200).json({ msg: "Accesstoken Valid" });
//           next();
//         }
//       });
//     }
//   } catch (err) {
//     console.log(err);
//     res.status(500).send("Internal Server Error");
//   }
// };

// const renewToken = async (req, res, next) => {
//   try {
//     const refreshtoken = req.cookies.refreshtoken;
//     if (refreshtoken) {
//       JWT.verify(refreshtoken, process.env.JWTREFRESHTOKENSECRET, (err, decode) => {
//         if (err) {
//           console.log(err);
//           res.status(401).json({ valid: false, message: "Invalid refresh token" });
//         } else {
//           username = decode.username;
//           userId = decode.userId;
//           const accesstoken = JWT.sign({ username, userId }, process.env.JWTACCESSTOKENSECRET, {
//             expiresIn: "10s",
//           });

//           res.cookie("accesstoken", accesstoken, {
//             maxAge: 60000,
//             httpOnly: true,
//             secure: true,
//           });
//           res.status(200).json({ msg: "Accesstoken Renewed" });
//           next();
//         }
//       });
//     } else {
//       // res.status(401).json({ valid: false, message: "No token provided" });
//       next();
//     }
//   } catch (err) {
//     console.log(err);
//     res.status(500).send("Internal Server Error");
//   }
// };

module.exports = { loginUser, registerUser, isUserValid, UserData };
