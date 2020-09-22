// routes/auth.js

const express = require("express");
const router = express.Router();

const User = require("../models/user");

const bcrypt = require("bcryptjs");
const bcryptSalt = 10;

const jwt = require("jsonwebtoken");

const withAuth = require("../helpers/middleware");

/**
 * @route   GET signup
 * @desc    Signup user
 * @access  Public
 */

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

/**
 * @route   POST signup
 * @desc    Register new user
 * @access  Public
 */

router.post("/signup", async (req, res, next) => {
  // desestructuramos el email y el password de req.body
  const { email, password } = req.body;

  // si alguna de estas variables no tiene un valor, renderizamos la vista de auth/signup con un mensaje de error
  if (email === "" || password === "") {
    res.render("auth/signup", {
      errorMessage: "Indicate a username and a password to sign up",
    });
    return;
  }

  try {
    // buscamos el usuario por el campo email
    const user = await User.findOne({ email });
    // si existiera en la base de datos, renderizamos la vista de auth/signup con un mensaje de error
    if (user !== null) {
      res.render("auth/signup", {
        errorMessage: "The username already exists!",
      });
      return;
    }
    // creamos la salt y hacemos hash del password
    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);

    // creamos el usuario y luego renderizamos la vista de home con un mensaje de éxito
    await User.create({
      email,
      password: hashPass,
    });
    res.render("home", { message: "User created!" });
  } catch (error) {
    next(error);
  }
});

/**
 * @route   GET login
 * @desc    Login user
 * @access  Public
 */

router.get("/login", (req, res, next) => {
  res.render("auth/login");
});

/**
 * @route   POST login
 * @desc    Login user
 * @access  Public
 */

router.post("/login", async function (req, res) {
  // desestructuramos el email y el password de req.body
  const { email, password } = req.body;

  // si alguna de estas variables no tiene un valor, renderizamos la vista de auth/signup con un mensaje de error
  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, username and password to sign up.",
    });
    return;
  }

  try {
    // revisamos si el usuario existe en la BD
    const user = await User.findOne({ email });
    // si el usuario no existe, renderizamos la vista de auth/login con un mensaje de error
    if (!user) {
      res.render("auth/login", {
        errorMessage: "The username doesn't exist.",
      });
      return;
    }
    // si el usuario existe, hace hash del password y lo compara con el de la BD
    else if (bcrypt.compareSync(password, user.password)) {
      // Issue token
      const userWithoutPass = await User.findOne({ email }).select("-password");
      const payload = { userWithoutPass };
      //console.log('payload', payload);
      // si coincide, creamos el token usando el método sign, el string de secret session y el expiring time
      const token = jwt.sign(payload, process.env.SECRET_SESSION, {
        expiresIn: "1h",
      });
      // enviamos en la respuesta una cookie con el token y luego redirigimos a la home
      res.cookie("token", token, { httpOnly: true });
      res.status(200).redirect("/");
    } else {
      // en caso contrario, renderizamos la vista de auth/login con un mensaje de error
      res.render("auth/login", {
        errorMessage: "Incorrect password",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

/**
 * @route   GET secret
 * @desc    Secret page
 * @access  Private
 */

router.get("/secret", withAuth, (req, res, next) => {
  //console.log(req.user);
  // si existe req.user, quiere decir que el middleware withAuth ha devuelto el control a esta ruta y renderizamos la vista secret con los datos del user
  if (req.user) {
    res.render("secret", { user: req.user });
  } else {
    // en caso contrario (si no hay token) redirigimos a la home
    res.redirect("/");
    /* res.status(401).render("home", {
      errorMessage: "Unauthorized: No token provided",
    }); */
  }
});

/**
 * @route   GET logout
 * @desc    Logout user
 * @access  Private
 */

router.get("/logout", withAuth, function (req, res) {
  // seteamos el token con un valor vacío y una fecha de expiración en el pasado (Jan 1st 1970 00:00:00 GMT)
  res.cookie("token", "", { expires: new Date(0) });
  res.redirect("/");
});

/**
 * @route   GET me
 * @desc    Get user data
 * @access  Private
 */

// obtenemos los datos del usuario en formato json
router.get("/me", withAuth, function (req, res) {
  if (req.user) {
    // devolvemos el usuario
    res.status(200).json(req.user);
  } else {
    res.redirect("/");
  }
});

module.exports = router;
