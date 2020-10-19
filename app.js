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
const GoogleStrategy = require('passport-google-oauth20').Strategy;   // Level 6 google authentication
const findOrCreate = require("mongoose-findorcreate");  // Level 6 google authentication

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
  password: String,
  googleId: String,
  secret: String
});


// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});   // do this before creating mongoose model

userSchema.plugin(passportLocalMongoose);   // use passport-local-mongoose // Level 5
userSchema.plugin(findOrCreate);  //// Level 6 google authentication
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());    // Level 5
// passport.serializeUser(User.serializeUser());     // Level 5
// passport.deserializeUser(User.deserializeUser());    // Level 5

passport.serializeUser(function(user, done) {     // Level 6 universal
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {   // Level 6 universal
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({     // Level 6 google authentication
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"   // Level 6 special
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({secret: {$ne: null}}, function(err, foundUsers) {
    if (err) console.log(err);
    else if (foundUsers) {
      res.render("secrets", {usersWithSecrets: foundUsers});
    }
  });

});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
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
