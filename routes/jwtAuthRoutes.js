const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");

// const validateRegisterInput = require("../../validation/register");
// const validateLoginInput = require("../../validation/login");
const User = require("../models/userModel");

// const User = require("../../models/User");
const jwtSecret = require("../config/keys").secret;

// router.get("/test", (req, res) => {
//   res.json({ msg: "User Router Works" });
// });

module.exports = app => {
  app.post("/register", async (req, res, done) => {
    console.log("Body ", req.body);
    try {
      const result = await User.findOne({ where: { email: req.body.email } });
      // console.log(result);
      // console.log(result !== null);
      if (result !== null) {
        // return done(null, false, {
        //   message: "Email is in use"
        // });
        return res.json({ message: "Email is in use" });
      }
      const pwd = await bcrypt.hash(req.body.password, 5);

      try {
        const userCreate = await User.create({
          email: req.body.email,
          password: pwd,
          name: req.body.name
        });

        res.json(userCreate);
      } catch (err) {
        console.log(err);
      }
    } catch (err) {
      console.log(err);
    }
  });

  app.post("/login", async (req, res) => {
    try {
      const result = await User.findOne({ where: { email: req.body.email } });
      // console.log(result);

      if (result === null) {
        return res
          .status(401)
          .json({ message: `Email or Password isn't correct` });
      }

      bcrypt.compare(req.body.password, result.dataValues.password, function(
        err,
        check
      ) {
        console.log("Check ", check);
        if (err) {
          console.log("Error while checking passwords");
          //   return done(null, false, {
          //     message: "Invalid email or password"
          //   });
          return res
            .status(401)
            .json({ message: "Invalid email or passwords" });
        } else if (check) {
          const payload = req.body; // JWT Payload

          jwt.sign(payload, jwtSecret, { expiresIn: 36000 }, (err, token) => {
            // console.log("Jwt ", jwt, " Token ", token);

            // res.setHeader("Cache-Control", "private");
            // res.cookie("__session", token);
            // res.cookie("jwt", token, {
            //   maxAge: 900000,

            //   httpOnly: true
            // });

            // res.cookie("test_jwt", token, {
            //   expires: new Date(Date.now() + 9999999),
            //   httpOnly: true,
            //   secure: truee
            // });
            // const decoded = jwt.verify(token, jwtSecret);
            // console.log("Decoded ", decoded);
            res.send({
              success: true,
              token: "Bearer " + token
            });
          });
        } else {
          // req.flash("danger", "Oops. Incorrect login details.");
          // return done(null, false, {
          //   message: "Invalid email or password"
          // });
          res.status(401).json({ message: "Invalid email or passwords" });
          // return done(null, false);
        }
      });

      // return done(null, result);
    } catch (err) {
      console.log(err);
    }
  });

  // function authorized(request, response, next) {
  //   passport.authenticate("jwt", { session: false }, async (error, token) => {
  //     console.log("Error ", error);
  //     console.log("Token ", token);
  //     if (error || !token) {
  //       response.status(401).json({ message: "Unauthorized" });
  //     }
  //     // try {
  //     //   // const user = await User.findOne({
  //     //   //     where: { id: token.id },
  //     //   // });
  //     //   const result = await User.findOne({ where: { email: token.email } });
  //     //   request.user = result;
  //     // } catch (error) {
  //     //   next(error);
  //     // }
  //     next();
  //   })(request, response, next);
  // }

  // function verifyToken(req, res, next) {
  //   //get auth header value
  //   const bearerHeader = req.headers["authorization"];
  //   if (typeof bearerHeader !== "undefined") {
  //     const bearer = bearerHeader.split(" ");
  //     const bearerToken = bearer[1];
  //     req.token = bearerToken;
  //     next();
  //   } else {
  //     res.sendStatus(403);
  //   }
  // }

  // app.get(
  //   "/current_user",
  //   verifyToken,
  //   (req, res) => {
  //     jwt.verify(req.token, jwtSecret, (err, data) => {
  //       if (err) {
  //         res.sendStatus(403);
  //       } else {
  //         res.json(data);
  //       }
  //     });
  //   }
  // );

  app.get(
    "/current_user",
    passport.authenticate("jwt", { session: false }),
    // authorized,
    // verifyToken,
    (req, res) => {
      // jwt.verify(req.token, jwtSecret, (err, data) => {
      //   if (err) {
      //     res.sendStatus(403);
      //   } else {
      //     res.json(data);
      //   }
      // });
      res.json(req.user);
    }
  );

  app.get(
    "/protected_page",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
      res.send("Protected Route from Server");
    }
  );

  app.get("/logout", (req, res) => {
    // req.logout();
    // res.redirect("/");
    req.logout();
    res.cookie();
    console.log("Authenticated " + req.isAuthenticated());
    // res.status(200).json({ message: "Fuck" });
    res.redirect("/");
  });
};

// router.get(
//   "/current_user",
//   passport.authenticate("jwt", { session: false }),
//   (req, res) => {
//     res.json({
//       id: req.user.id,
//       name: req.user.name,
//       email: req.user.email
//     });
//   }
// );
