const dotenv = require('dotenv');
const express = require('express');
const app = express();
const mongoose = require("mongoose");
const logger = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken');
//Routes
const Requests = require('./Routes/Requests');
const Auth = require('./Auth');

//Models 
const Resellers = require('./Models/Resellers');


// Set up Global configuration access
dotenv.config();

app.use(cors());
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.header("Access-Control-Allow-Headers", "x-access-token, Origin, X-Requested-With, Content-Type, Accept, token");
  next();
});

app.use(['/reseller', '/check', '/reg', '/us/status', '/fr/status','/fr2/status', '/nl/status', '/de/status', '/de/add', '/us/add', '/nl/add', '/fr/add', '/fr2/add', '/nl/inbounds', '/us/inbounds', '/de/inbounds', '/fr/inbounds', '/fr2/inbounds', '/fr/userslist', '/fr2/userslist', '/de/userslist', '/nl/userslist', '/us/userslist', '/fi/revise', '/nl/revise', '/de/revise', '/us/revise', '/fr/revise', '/fr2/revise'], async (req, res, next) => {
  if (req.headers.token) {
      const token = jwt.verify(req.headers.token, process.env.TOKEN, async (err,result) => {
          if (err) {
              res.status(400).json({
                  code: 400,
                  error: 'Invalid Access',
                  message: 'Please Login again!'
              });
          } else {
              const user = await Resellers.findOne({
                  username: result.username
              });
              if (user) {
                  next();
              } else {
                  res.status(400).json({
                      code: 400,
                      error: 'Invalid Access',
                      message: 'Please Login again!'
                  });
              }
          }
      });
  } else {
      res.status(400).json({
          code: 400,
          error: 'Invalid Access',
          message: 'No Header token found'
      });
  }
});
app.use(logger('dev'));

const server_port = process.env.PORT;
const server_host = process.env.BASE_URL;


// Connect to MongoDB database
mongoose.connect(process.env.MONGODBASE_URL, { useNewUrlParser: true })
.then(() => {
    app.use('/', Requests);
    app.use('/login', Auth);

    app.listen(server_port,server_host, () => {
    console.log(`Resellers App Started on ${server_port}`)
    })
  })


