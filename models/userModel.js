const Sequelize = require("sequelize");

const sequelize = require("../database/sequelizeDatabase");

const User = sequelize.define("users", {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    allowNull: false,
    primaryKey: true
  },
  username: Sequelize.STRING,
  password: Sequelize.STRING,
  email: Sequelize.STRING,
  name: Sequelize.STRING,
  fb_id: Sequelize.STRING,
  twitter_id: Sequelize.STRING,
  instagram_id: Sequelize.STRING,
  profile_pic_url: Sequelize.STRING
  // email: Sequelize.STRING,
  // password: Sequelize.STRING,
  // name: Sequelize.STRING
});

module.exports = User;
