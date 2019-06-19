const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const morgan = require("morgan");
const passport = require("passport");

const server = express();
const sequelize = require("./database/sequelizeDatabase");

sequelize
  .sync()
  .then(result => {
    // console.log(result);
    server.listen(5000);
  })
  .catch(err => {
    console.log(err);
  });

server.use(cors({ origin: "http://localhost:3000", credentials: true }));

// server.use(cors());
// server.use(cookieParser());

server.use(bodyParser.json());

server.use(morgan("combined"));

server.use(passport.initialize());

require("./passport/passport");

require("./routes/authRoutes")(server);
require("./routes/jwtAuthRoutes")(server);

server.get("/", (req, res) => {
  res.send("<h1>Home</h1>");
});
