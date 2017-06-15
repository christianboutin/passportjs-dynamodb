// config/passport.js

// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;

var bcrypt   = require('bcrypt-nodejs');

var aws = require('aws-sdk')
aws.config.update({region: "us-west-2"});
aws.config.credentials = new aws.SharedIniFileCredentials({profile: 'default'});
var dd = new aws.DynamoDB();
var tableName = "user"

// expose this function to our app using module.exports
module.exports = function(passport) {
  // =========================================================================
  // passport session setup ==================================================
  // =========================================================================
  // required for persistent login sessions
  // passport needs ability to serialize and unserialize users out of session

  // used to serialize the user for the session
  passport.serializeUser(function(user, done) {
    done(null, user.id.N);
  });

  // used to deserialize the user
  passport.deserializeUser(function(id, done) {
    dd.getItem({"TableName":tableName,"Key": {"id":{"N":id}}}, function(err,data){
      if (err){
        done(err,data);
      }
      done(err,{"id": data.Item.id.N, "email": data.Item.email.S, "pw": data.Item.pw.S});
    })
  });

  // =========================================================================
  // LOCAL SIGNUP ============================================================
  // =========================================================================
  // we are using named strategies since we have one for login and one for signup
  // by default, if there was no name, it would just be called 'local'

  passport.use('local-signup', new LocalStrategy({
    // by default, local strategy uses username and password, we will override with email
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass back the entire request to the callback
  },
  function(req, email, password, done) {
    var params = {
      "TableName":tableName,
      "IndexName":"email-index",
      "KeyConditions":{
        "email":{
          "ComparisonOperator":"EQ",
          "AttributeValueList":[{"S":email}]
        }
      }
    }

    console.log("Scanning for :"+JSON.stringify(params))//.Items["email"].name)

    // find a user whose email is the same as the forms email
    // we are checking to see if the user trying to login already exists
    dd.query(params, function(err,data){
      // if there are any errors, return the error
      if (err){
        return done(err);
      }

      // check to see if theres already a user with that email
      if (data.Items.length > 0) {
        return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
      } else {

        var params = {
          "TableName":tableName,
          "Item" : {
            "id":{"N":(Math.floor(Math.random() * 4294967296)).toString()},
            "email":{"S":email},
            "pw":{"S":bcrypt.hashSync(password)}
          }
        }
        dd.putItem(params, function(err,data){
          if (err){
            return done(null, false, req.flash('signupMessage', "Apologies, please try again now. ("+err+")"));
          }else{
            return done(null, params.Item);
          }
        })

      }

    });

  }));

  // =========================================================================
  // LOCAL LOGIN =============================================================
  // =========================================================================
  // we are using named strategies since we have one for login and one for signup
  // by default, if there was no name, it would just be called 'local'

  passport.use('local-login', new LocalStrategy({
    // by default, local strategy uses username and password, we will override with email
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass back the entire request to the callback
  },
  function(req, email, password, done) { // callback with email and password from our form
    var params = {
      "TableName":tableName,
      "IndexName":"email-index",
      "KeyConditions":{
        "email":{
          "ComparisonOperator":"EQ",
          "AttributeValueList":[{"S":email}]
        }
      }
    }
    dd.query(params, function(err,data){
      if (err){
        return done(err);
      }
      if (data.Items.length == 0){
        return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash
      }
      dd.getItem({"TableName":tableName,"Key": {"id":data.Items[0]["id"]}}, function(err,data){
        if (err){
          return done(err);
        }
        if (!bcrypt.compareSync(password, data.Item.pw.S)){
          return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata
        }else{
          return done(null, data.Item);
        }
      })
    });
  }));
};
