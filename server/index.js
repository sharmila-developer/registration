const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const userModel = require("./model/model");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(cookieParser());

mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => {
    console.log("Database connected");
  })
  .catch((err) => {
    console.log(err);
  });

app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  bcrypt.hash(password, 10).then((hash) => {
    userModel
      .create({ username, email, password: hash })
      .then((user) => res.json("Success"))
      .catch((err) => res.json(err));
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  userModel.findOne({ email: email }).then((user) => {
    if (user) {
      bcrypt.compare(password, user.password, (err, response) => {
        if (response) {
          const token = jwt.sign({ email: user.email }, "jwt-secret-key", {
            expiresIn: "1d",
          });
          res.cookie("token", token);
          return res.json({ status: "Success" });
        } else {
          return res.json("The password is incorrect");
        }
      });
    } else {
      return res.json("No record existed");
    }
  });
});

app.post("/forgotpassword", (req, res) => {
  const { email } = req.body;
  userModel.findOne({ email: email }).then((user) => {
    if (!user) {
      return res.send({ status: "User not existed" });
    }
    const token = jwt.sign({ id: user._id }, "jwt-secret-key", {
      expiresIn: "1d",
    });
    var transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: "sharmianut@gmail.com",
        password: "mqtscuobkyrifvvl",
      },
    });

    const mailOptions = {
      from: "sharmianut@gmail.com",
      to: "2802sharmi@gmail.com",
      subject: "Reset your password",
      text: `http://localhost:3000/reset-password/${user._id}/${token}`,
    };
    transporter.sendMail(mailOptions, function (err, info) {
      if (err) {
        console.log(err);
      } else {
        return res.send({ status: "Success" });
      }
    });
  });
});

app.post("/resetpassword/:id/:token", (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  jwt.verify(token, "jwt_secret_key", (err, decoded) => {
    if (err) {
      return res.json({ status: "Error with token" });
    } else {
      bcrypt.hash(password, 10).then((hash) => {
        userModel
          .findByIdAndUpdate({ _id: id }, { password: hash })
          .then((u) => res.send({ status: "Success" }))
          .catch((err) => res.send({ status: err }));
      });
    }
  });
});

app.listen(4000, () => {
  console.log("Server running");
});
