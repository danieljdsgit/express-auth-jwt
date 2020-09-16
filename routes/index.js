var express = require('express');
var router = express.Router();

const withAuth = require("../helpers/middleware");

/**
 * @route   GET /
 * @desc    Home page
 * @access  Public
 */

// necesitamos el middleware en la home, ya que en este configuramos las variables locals isUserLoggedIn y currentUserInfo que usaremos en las plantillas
router.get("/", withAuth, (req, res, next) => {
  res.render("home");
});

module.exports = router;
