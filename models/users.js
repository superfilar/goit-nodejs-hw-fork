const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { User } = require("./User");
const gravatar = require("gravatar");
const sgMail = require("@sendgrid/mail");
const { nanoid } = require("nanoid");

const registration = async (body) => {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);

  try {
    const { email, password } = body;
    const user = new User({
      email,
      password: await bcrypt.hash(password, 10),
      avatarURL: gravatar.url(email, { protocol: "http", s: 250 }),
      verificationToken: nanoid(),
    });

    await user.save();

    const msg = {
      to: email,
      from: process.env.SENDER_EMAIL,
      subject: "Please, confirm Your Email!",
      text: `Here is Your verification link - http://127.0.0.1:3000/users/verify/${user.verificationToken}`,
      html: `Here is Your verification <a href=http://127.0.0.1:3000/users/verify/${user.verificationToken}>link</a>`,
    };

    await sgMail.send(msg);

    const newUser = { email: user.email, subscription: user.subscription };
    return newUser;
  } catch (error) {
    console.log("error", error.message);
  }
};

const login = async (body) => {
  try {
    const { email, password } = body;
    const findUser = await User.findOne({ email });

    if (!findUser) return "Wrong email";
    if (!(await bcrypt.compare(password, findUser.password)))
      return "Wrong password";

    const token = jwt.sign(
      {
        _id: findUser._id,
      },
      process.env.JWT_SECRET
    );
    await User.updateOne({ _id: findUser.id }, { token });
    const user = {
      token: token,
      user: { email: findUser.email, subscription: findUser.subscription },
    };
    return user;
  } catch (error) {
    console.log("error", error.message);
  }
};

const logout = async (userId) => {
  try {
    return (result = await User.updateOne({ _id: userId }, { token: null }));
  } catch (error) {
    console.log("error", error.message);
  }
};

const current = async (userId) => {
  try {
    const user = await User.findById({ _id: userId });
    const userData = { email: user.email, subscription: user.subscription };
    return userData;
  } catch (error) {
    console.log("error", error.message);
  }
};

const confirmEmail = async (verificationToken) => {
  try {
    const user = await User.findOneAndUpdate(
      { verificationToken },
      { verificationToken: null, verify: true }
    );
    if (!user) return false;

    return user;
  } catch (error) {
    console.log("error", error.message);
  }
};

const confirmEmailSecondTime = async (email, res) => {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  try {
    const user = await User.findOne({ email });
    if (!user) return `No user with email ${email}`;
    if (user.verify === true) return "Verification has already been passed";

    const msg = {
      to: email,
      from: process.env.SENDER_EMAIL,
      subject: "Please, confirm Your Email!",
      text: `Here is Your verification link - http://127.0.0.1:3000/users/verify/${user.verificationToken}`,
      html: `Here is Your verification <a href=http://127.0.0.1:3000/users/verify/${user.verificationToken}>link</a>`,
    };

    await sgMail.send(msg);
    return user;
  } catch (error) {
    console.log("error", error.message);
    return false;
  }
};

module.exports = {
  registration,
  login,
  logout,
  current,
  confirmEmail,
  confirmEmailSecondTime,
};
