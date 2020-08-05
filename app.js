require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const app = express();
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');
//oauth
const GoogleStrategy = require('passport-google-oauth20').Strategy;


app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// session

app.use(session({
    secret: "thisismysecret.",
    resave: false,
    saveUninitialized: false
}));

// passport

app.use(passport.initialize());
app.use(passport.session());

// oauth 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// database

mongoose.connect('mongodb://localhost/user', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true}), (err) => {
    if (!err) {
        console.log('MongoDB Connection Succeeded.')
    } else {
        console.log('Error in DB connection: ' + err)
    }
};

// schemas and models

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});



// secret (must use before model)

// passport plugin

userSchema.plugin(passportLocalMongoose);

//findorcreate plugin
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields:['password']});

const User = new mongoose.model("User", userSchema);

//passport serialise and deserialise user

passport.use(User.createStrategy());

passport.serializeUser((user, done) =>{
    done(null, user);
});
  
passport.deserializeUser((id, done) =>{
    User.findById(id,(err,user)=>{
        done(null, user);
    })
});




// routes

app.get('/', (req, res) => {
    res.render('home');
});


// google oauth route

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }), (req, res)=> {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
});



app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/secrets', (req, res) => {
    User.find({'secret':{$ne:null}}, (err,foundUsers)=>{
        if(err){
            console.log(err);
        } else{
            res.render('secrets', {usersWithSecrets:foundUsers});
        }
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});



// using passportjs


app.post('/register', (req, res) => {
    
    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err);
            res.redirect('register');
        } else{
            passport.authenticate('local')(req,res,()=>{
                res.redirect('secrets');
            });                
        }
    })

});

app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        } else{
            passport.authenticate('local')(req,res,()=>{
                res.redirect('secrets');
            });
        }
    });
});

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});


app.get('/submit', (req, res) => {
    if(req.isAuthenticated()){          // checks to see if user is authenticated
        res.render('submit');
    } else {
        res.redirect('login');
    }
});

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, (err, foundUser)=>{
        if(err){
            console.log(err);
        } else{
            foundUser.secret = submittedSecret;
            foundUser.save(()=>{
                res.redirect('secrets');
            });
        }
    });
});



//  using bcrypt


// app.post('/register', (req, res) => {

//     bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save((err)=>{
//             if(err){
//                 console.log(err);
//             } else {
//                 res.render('secrets');
//             }
//         });
//     });

// });

// app.post('/login', (req, res) => {
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({email: username}, (err, foundUser)=>{
//         if(err){
//             console.log(err);
//         } else{
//             if(foundUser){
//                 bcrypt.compare(password, foundUser.password, function(err, result) {
//                     if(result === true){
//                          res.render('secrets');
//                     }
//                 });
//             } else{
//                 res.send('No such user!');
//             }
//         }
//     });
// });






app.listen(3000, () => {
    console.log('App listening on port 3000!');
});