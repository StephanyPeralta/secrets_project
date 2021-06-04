//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const flash = require("connect-flash");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const MongoStore = require("connect-mongo");

// Initialization
const app = express();

// Settings
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(express.static("public"));

// Middlewares
app.use(session({
    secret: "This is a long little secret.",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ 
      mongoUrl: process.env.MONGODB_URI,
      touchAfter: 24 * 3600 
    })
}));

app.use(passport.initialize());
app.use(passport.session());

// Database
(async () => {
    try {
      const db = await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useFindAndModify: false,
        useCreateIndex: true,
      });
      console.log("Mongodb is connected to", db.connection.host);
    } catch (error) {
      console.error(error);
    }
})();

const userSchema = new mongoose.Schema({
    email: {type: String},
    password: {type: String},
    googleId: {type: String},
    secret: [{type: String}]
},  { timestamps: true });

// Passport Config
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: `${process.env.APP_HOST || process.env.LOCAL_HOST}/auth/google/secrets`,
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.use(flash());

// Global Variables
app.use((req, res, next) => {
    res.locals.success_msg = req.flash("success_msg");
    res.locals.error_msg = req.flash("error_msg");
    res.locals.error = req.flash("error");
    next();
  });

// Routes
app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login "}),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    return res.redirect("/secrets");
  });

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            const foundUsers =  await User.find({"secret": {$ne: null}});
            return res.render("secrets", {usersWithSecrets: foundUsers});
        } else {
            req.flash("error_msg", "Unauthorized user, please login/register.");
            return res.redirect("/");
        }
    } catch (e) {
        console.error(e);
        return res.status(400).render("/login", { title: "Error 404", alert: "An error occurred, please try later.." });
    }
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        req.flash("error_msg", "Unauthorized user, please login/register.");
        res.redirect("/");
    }
});

app.post("/submit", async (req, res) => {
    try {
        const submittedSecret = req.body.secret;

        await User.findById(req.user.id, function(err, foundUser){
            if (err) {
                console.log(err);
                req.flash("error_msg", "An error occurred, please try later..");
                res.redirect("/submit");
            } else {
                if (foundUser) {
                    // foundUser.secret = submittedSecret;
                    foundUser.secret.push(submittedSecret);
                    foundUser.save(function(){
                        req.flash("success_msg", "Secret submitted successfully!");
                        res.redirect("/secrets");
                    });
                }
            }
        });
    } catch (e) {
        console.error(e);
        return res.status(400).render("/submit", { title: "Error 404", alert: "An error occurred, please try later.." });
    }
});


app.get("/logout", function(req, res){
    req.logout();
    req.flash("success_msg", "Session closed successfully");
    res.redirect("/");
});

app.post("/register", async (req, res) => {
    try {
        await User.register({username: req.body.username}, req.body.password, function(err, user){
            if (err) {
                console.log(err);
                req.flash("error_msg", "Incorrect data!");
                return res.redirect("/register");
            } else {
                req.flash("success_msg", "Account created successfully, please login!");
                return res.redirect("/login");
            }
        });
    } catch (e) {
        console.error(e);
        return res.status(400).render("/register", { title: "Error 404", alert: "An error occurred, please try later.." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const username = req.body.username;
        const userExist = await User.findOne({username: username});

        if (userExist) {
            passport.authenticate("local")(req, res, function(){
                return res.redirect("/secrets");
            });
        } else {
            req.flash("error_msg", "Incorrect data or user does not exist!");
            return res.redirect("/login");
        }
    } catch (error) {
        console.error(e);
        return res.status(400).render("/login", { title: "Error 404", alert: "An error occurred, please try later.." });
    }
});

// Server status
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started, app is running on port ${ PORT }`);
});