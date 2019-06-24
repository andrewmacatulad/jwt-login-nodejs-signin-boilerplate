const passport = require("passport");
const jwt = require("jsonwebtoken");
module.exports = app => {
  // Social Media Login
  app.get(
    "/auth/google",
    passport.authenticate(
      "google",
      {
        scope: ["profile", "email"]
      },
      { session: false }
    )
  );

  app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
      session: false,
      //successRedirect: "http://localhost:3000",
      failureRedirect: "http://localhost:3000/login"
    }),
    (req, res) => {
      const payload = req.user; // JWT Payload
      // console.log("Body google pass ", req.body);
      // console.log("Payload google pass ", payload.dataValues);
      jwt.sign(
        payload.dataValues,
        "sampleSecret",
        { expiresIn: 36000 },
        (err, token) => {
          console.log("Token ", token);
          res.cookie("test", `Bearer ${token}`, {
            maxAge: 900000
          });
          res.redirect("http://localhost:3000");

          // res.send({
          //   success: true,
          //   token: "Bearer " + token
          // });
        }
      );
    }
    // (req, res) => {
    //   res.redirect("http://localhost:3000");
    // }
  );

  app.get(
    "/auth/twitter",
    passport.authenticate("twitter-token"),
    (req, res) => {
      // do something with req.user
      // res.send(req.user ? 200 : 401);
    }
  );

  app.get(
    "/auth/twitter/callback",
    passport.authenticate("twitter-token", {
      failureRedirect: "http://localhost:3000/login"
    }),
    (req, res) => {
      const payload = req.user; // JWT Payload
      // console.log("Body google pass ", req.body);
      // console.log("Payload google pass ", payload.dataValues);
      jwt.sign(
        payload.dataValues,
        "sampleSecret",
        { expiresIn: 36000 },
        (err, token) => {
          console.log("Token ", token);
          res.cookie("test", `Bearer ${token}`, {
            maxAge: 900000
          });
          res.redirect("http://localhost:3000");

          // res.send({
          //   success: true,
          //   token: "Bearer " + token
          // });
        }
      );
    }
  );

  app.get(
    "/auth/facebook",
    passport.authenticate("facebook", {
      scope: [
        "user_friends",
        "user_posts",
        "manage_pages",
        "email",
        "user_likes"
      ]
    })
  );

  app.get(
    "/auth/facebook/callback",
    passport.authenticate("facebook", {
      failureRedirect: "/"
    }),
    (req, res) => {
      const payload = req.user; // JWT Payload
      // console.log("Body google pass ", req.body);
      // console.log("Payload google pass ", payload.dataValues);
      jwt.sign(
        payload.dataValues,
        "sampleSecret",
        { expiresIn: 36000 },
        (err, token) => {
          console.log("Token ", token);
          res.cookie("test", `Bearer ${token}`, {
            maxAge: 900000
          });
          res.redirect("http://localhost:3000");

          // res.send({
          //   success: true,
          //   token: "Bearer " + token
          // });
        }
      );
    }
  );

  app.get(
    "/auth/twitch",
    passport.authenticate("twitch", { forceVerify: true })
  );

  app.get(
    "/auth/twitch/callback",
    passport.authenticate("twitch", {
      successRedirect: "http://localhost:3000",
      failureRedirect: "http://localhost:3000/login"
    })
  );

  app.get("/auth/instagram", passport.authenticate("instagram"));

  app.get(
    "/auth/instagram/callback",
    passport.authenticate("instagram", {
      successRedirect: "http://localhost:3000",
      failureRedirect: "http://localhost:3000/login"
    })
  );

  app.get("/auth/github", passport.authenticate("github"));

  app.get(
    "/auth/github/callback",
    passport.authenticate("github", {
      successRedirect: "http://localhost:3000",
      failureRedirect: "http://localhost:3000/login"
    })
  );

  // app.get("/api/logout", (req, res) => {
  //   req.session.destroy();
  //   req.logout();
  //   // req.session = null;

  //   res.redirect("http://localhost:3000/");
  //   // res.send("logout");
  //   // req.session.destroy(function(err) {
  //   //   res.clearCookie("connect.sid");
  //   //   console.log("Authenticated " + req.isAuthenticated());
  //   //   res.redirect("/");
  //   // });

  //   // if (req.session) {
  //   //   req.session = null;
  //   //   // Delete Session
  //   //   // req.session.destroy(function(err) {
  //   //   //   if (err) {
  //   //   //     return next(err);
  //   //   //   } else {

  //   //   //     return res.redirect("/");
  //   //   //   }
  //   //   // });
  //   // }
  // });
};
