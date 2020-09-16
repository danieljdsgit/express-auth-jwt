const jwt = require("jsonwebtoken");

const secret = process.env.SECRET_SESSION;

const withAuth = function (req, res, next) {
  // obtenemos el token de las cookies
  const token = req.cookies.token;
  // si no hay token, seteamos el valor de la variable isUserLoggedIn en false y pasamos el control a la siguiente función de middleware
  if (!token) {
    res.locals.isUserLoggedIn = false;
    next();
  } else {
    // verificamos el token
    jwt.verify(token, secret, function (err, decoded) {
      if (err) {
        res.locals.isUserLoggedIn = false;
        // si hay un error, renderizamos la home y devolvemos un mensaje
        res.status(401).render("home", {
          errorMessage: "Unauthorized: No token provided",
        });
      } else {
        // si el token valida, configuramos req.user con el valor del decoded userWithoutPass
        req.user = decoded.userWithoutPass;
        res.locals.currentUserInfo = req.user;
        res.locals.isUserLoggedIn = true;
        next();
      }
    });
  }
};

module.exports = withAuth;
