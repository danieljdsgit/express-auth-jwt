const jwt = require("jsonwebtoken");

const secret = process.env.SECRET_SESSION;

const withAuth = async (req, res, next) => {
  try {
    // obtenemos el token de las cookies
    const token = req.cookies.token;
    // si no hay token, seteamos el valor de la variable isUserLoggedIn en false y pasamos el control a la siguiente función de middleware
    if (!token) {
      res.locals.isUserLoggedIn = false;
      next();
    } else {
      // verificamos el token
      const decoded = await jwt.verify(token, secret);

      // si el token valida, configuramos req.user con el valor del decoded userWithoutPass
      req.user = decoded.userWithoutPass;
      console.log(req.user);
      res.locals.currentUserInfo = req.user;
      res.locals.isUserLoggedIn = true;
      next();
    }
  } catch (err) {
    // si hay un error, configuramos el valor de la variable isUserLoggedIn en false y pasamos el control a la siguiente ruta
    console.error(err);
    res.locals.isUserLoggedIn = false;
    next(err);
  }
};

module.exports = withAuth;
