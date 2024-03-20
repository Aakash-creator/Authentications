const express = require("express");
const app = express();
require("dotenv").config();
require("./DBConnect");
app.use(express.json());
const cors = require("cors");
app.use(cors());

const cookieParser = require("cookie-parser");
app.use(cookieParser());

const auth = require("./routes/Auth");
app.use(auth);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.get("*", (req, res) => {
  res.status(404).send("Resource you are finding is not available!");
});

app.listen(process.env.PORT, () => {
  console.log(`Example app listening on port ${process.env.PORT}`);
});
