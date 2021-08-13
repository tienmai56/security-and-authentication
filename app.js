require("dotenv").config()
const express = require("express");
const bodyParser = require("body-parser")
const ejs = require("ejs")
const mongoose = require("mongoose")
const session = require('express-session');
const passport = require("passport")
const passportLocal = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findorcreate=require("mongoose-findorcreate")

const app = express()

// const encrypt = require("mongoose-encryption")
// const md5=require("md5")
// const bcrypt = require("bcrypt")
// const saltRounds = 10



app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }))

//set up app session 
app.use(session({
    secret:"secret project",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",
    { useNewUrlParser: true });


const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//silent the warning
mongoose.set("useCreateIndex");

//set up user schema to use plugin 
userSchema.plugin(passportLocal);
//add the package as a plugin
userSchema.plugin(findorcreate);

//encrypt entire databse 
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] })
const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRETS,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oath2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //find or create find a user find id, if not existed then it will create a new ont
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
    res.render("home")
})

app.get("/auth/google", function(Req,res){
    //triggers the pop-up for users to signup with google
    passport.authenticate("google",{scope:["profile"]})

});

app.get('auth/google/secrets',
passport.authenticate('google',{failureRedirect:'/login'}),
function(req,res){
    //successful authentication -> direct home
    res.redirect("/secrets")
}
);





app.get("/login", function (req, res) {
    res.render("login")
})

app.get("/register", function (req, res) {
    res.render("register")
})

//hash password
// app.post("/register", function (req, res) {
//     bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save(function (err) {
//             if (err) {
//                 console.log(err)
//             } else {
//                 res.render("secrets")
//             }
//         })
//     });

// })
//if users are already authenticated -> secrete page
// else (not logged in/authenticaed) -> login
app.get("/secrets", function(req,res){
    if(req.isAuthenticated()){
        res.render("secrets")
    }else{
        res.redirect("/login")
    }
})

app.get("/logout", function(req,res){
    req.logout()
    res.redirect("/")
});

app.post("/register", function(req,res){
    User.register({username:req.body.username}, req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register")
        } else{
            //authenticate successfully sets up a new session for users
            passport.authenticate("local")(req,res, function(){
                //this callback is triggered when authentication is successful
                res.redirect("/secrets")
            })
        }
    })
})

//log in comparing input password versus our hash stored in db
// app.post("/login", function (req, res) {
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({ email: username }, function (err, foundUser) {
//         if (err) {
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 bcrypt.compare(password, foundUser.password, function (err, result) {
//                     if (result === true) {
//                         res.render("secrets")
//                     }

//                 });

//             }
//         }
//     }
    
//     )
// })

//use authenticate local to authenticate users using username and password
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function (err) {
        if (err) {
            console.log(err)
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })

})



app.listen(3000, function () {
    console.log("server started successfully")
})