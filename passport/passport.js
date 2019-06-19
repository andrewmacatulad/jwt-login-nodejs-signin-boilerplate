//@ts-check
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");

const keys = require("../config/keys");
const User = require("../models/userModel");
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findByPk(id).then(user => {
    done(null, user);
  });
});

const jwtOptions = {
  // the extractjwt will check the value of the header with the key authorization
  // this is where you put the token
  // so the jwtFromRequest will get the value from there
  // jwtFromRequest: ExtractJwt.fromHeader("authorization"),
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  //jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("Bearer"),
  // to decode the token you must also get the secret which you can get from config.secret
  secretOrKey: keys.secret
};

passport.use(
  new GoogleStrategy(
    {
      clientID: keys.googleClientID,
      clientSecret: keys.googleClientSecret,
      callbackURL: "/auth/google/callback"
    },
    async (req, accessToken, refreshToken, profile, done) => {
      if (!req.user) {
        let existingUser;
        try {
          existingUser = await User.findOne({
            where: { email: profile.emails[0].value }
          });
          // console.log(existingUser);
        } catch (error) {
          return done(error);
        }

        if (existingUser) {
          return done(null, existingUser);
        }

        try {
          const data = {
            email: profile.emails[0].value,
            name: profile.displayName
          };

          // jwt.sign(data, "sampleSecret", { expiresIn: 36000 }, (err, token) => {
          //   console.log("Jwt ", jwt, " Token ", token);
          // });

          User.create(data).then(function(newUser, created) {
            if (!newUser) {
              return done(null, false);
            }

            if (newUser) {
              return done(null, newUser);
            }
          });

          // const user = await new User({
          //   username: profile.emails[0].value,
          //   name: profile.displayName
          // }).save();
          // done(null, user);
        } catch (error) {
          console.dir(error.message, { colors: true });
        }
      }
    }
  )
);

passport.use(
  new JwtStrategy(jwtOptions, async function(payload, done) {
    // See if the user ID in the payload exists in our database
    // If it does, call 'done' with that other
    // otherwise, call done without a user object
    const user = await User.findOne({ where: { email: payload.email } });
    try {
      if (user) {
        done(null, user);
      } else {
        done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
    console.log(user.dataValues);
  })
);
