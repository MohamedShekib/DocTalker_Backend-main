const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2');
const User = require('../models/user');
const bcrypt = require("bcrypt");

// SHKIB WILL TELL US

passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'http://localhost:5000/auth/google/redirect',
        // passReqToCallback: true
      },
      async function(accessToken, refreshToken, profile,done)  {
      
      try {
        // console.log(profile);
            // Check if a user with the same Google ID already exists in your database
          let user = await User.findOne({email: profile.email});
  
          if (user) {
            // User already exists, return the user
            return done(null, user);
          } else {
            // User doesn't exist, create a new user using Google profile information
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync(profile.id, salt);
            const profilejson = profile._json;
            user = new User({
              googleId: profilejson.id,
              firstName: profilejson.given_name,
              lastName: profilejson.family_name,
              email: profilejson.email,
              password: hashedPassword
              // You can set other default values here as needed
            });
  
            await user.save();
            return done(null, user);
          }
          }  catch (error) {
        return done(error, null);
      }
      
        // return done(null, profile);
        }
        
        )
      
  );
passport.serializeUser(function (user, done)
{
  done(null, user);
}
 )
 passport.deserializeUser(function (user, done)
{
  done(null, user);
}
 )

    // // Check if a user with the same Google ID already exists in your database
          // let user = await User.findOne({ googleId: profile.id });
  
          // if (user) {
          //   // User already exists, return the user
          //   return done(null, user);
          // } else {
          //   // User doesn't exist, create a new user using Google profile information
          //   user = new User({
          //     googleId: profile.id,
          //     Fname: profile.given_name,
          //     Lname: profile.family_name,
          //     email: profile.email,
          //     // You can set other default values here as needed
          //   });
  
          //   await user.save();
          //   return done(null, user);
          // }