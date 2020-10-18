//jshint esversion:6
//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");  // Level 5
const passport = require("passport");       // Level 5
const passportLocalMongoose = require("passport-local-mongoose"); // Level 5


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({                          // Level 5
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());    // Level 5
app.use(passport.session());   // Level 5

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true, useUnifiedTopology: true});

mongoose.set("useCreateIndex", true);  // for deprecation issue  // Level 5

const userSchema = new mongoose.Schema ({     // enabling encrypted Mongoose
  email: String,
  password: String
});


// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});   // do this before creating mongoose model

userSchema.plugin(passportLocalMongoose);   // use passport-local-mongoose // Level 5

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());    // Level 5
passport.serializeUser(User.serializeUser());     // Level 5
passport.deserializeUser(User.deserializeUser());    // Level 5


app.get("/", function(req, res) {
  res.render("home");
});
app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});
app.get("/logout", function(req, res) {   // level 5
  req.logout();                           // de-authenticate
  res.redirect("/");
});

app.post("/register", function(req, res) {
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      })
    }
  })
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});






app.listen(3000, function() {
  console.log("Server started on port 3000");
});
