const dotenv = require('dotenv');
const express = require('express');
const app = express();
const logger = require('morgan');
const cors = require('cors');

//Routes
const Requests = require('./Routes/Requests');


// Set up Global configuration access
dotenv.config();

app.use(cors());
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    res.header("Access-Control-Allow-Headers", "x-access-token, Origin, X-Requested-With, Content-Type, Accept");
    next();
  }); 

app.use(logger('dev'));

const server_port = process.env.PORT;
const server_host = process.env.BASE_URL;



app.use('/', Requests);

app.listen(server_port,server_host, () => {
console.log(`Resellers App Started on ${server_port}`)
})
