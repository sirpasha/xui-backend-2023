const dotenv = require('dotenv');
const express = require('express');
const app = express();
const mongoose = require("mongoose");
const logger = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken');
//Routes
const Requests = require('./Routes/Requests');

const De = require('./Routes/De');
const De2 = require('./Routes/De2');

const Fi = require('./Routes/Fi');
const Fi2 = require('./Routes/Fi2');

const Fr = require('./Routes/Fr');
const Fr2 = require('./Routes/Fr2');

const Nl = require('./Routes/Nl');

const Us = require('./Routes/Us');

const Auth = require('./Auth');

//Models 
const Resellers = require('./Models/Resellers');


// Set up Global configuration access
dotenv.config();

app.use(cors({
    origin: '*',
    methods: ['GET','POST','DELETE','UPDATE','PUT','PATCH'],
    header: ["x-access-token", "Origin", "X-Requested-With", "Content-Type", "Accept", "token"]
}));
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.header("Access-Control-Allow-Headers", "x-access-token, Origin, X-Requested-With, Content-Type, Accept, token");
  next();
});

app.use(['/de', '/de2', '/fi', '/fi2', '/fr', '/fr2', '/nl', '/us', '/reseller', '/check', '/reg'], async (req, res, next) => {
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
    app.use('/login', Auth);
    app.use('/', Requests);
    app.use('/de', De);
    app.use('/de2', De2);
    app.use('/fi', Fi);
    app.use('/fi2', Fi2);
    app.use('/fr', Fr);
    app.use('/fr2', Fr2);
    app.use('/nl', Nl);
    app.use('/us', Us);
    app.listen(server_port,server_host, () => {
    console.log(`Resellers App Started on ${server_port}`)
    })
  })


