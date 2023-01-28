const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const Resellers = require('./Models/Resellers');

// Middleware
router.use((req, res, next) => {
    next()
})
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

// Authenticate User
router.post('/', async (req, res, next) => {
    if (!req.is("application/json")) {
        next(error);
    }
    const username = req.body.username;
    const password = req.body.password;
    try {
        const user = await Resellers.findOne({ username: username});
        const compare = bcrypt.compareSync(password, user.password);
        if (!compare) {
            next(error);
        }
        const dateNow = Math.floor(new Date().getTime()/1000.0);
        const availablity= 2629743; // a month! change expiresIn Too!
        const expTime = dateNow + availablity;
        const token = jwt.sign({ id: user._id, username: user.username, credit: user.credit, prefix: user.prefix }, process.env.TOKEN, {
            expiresIn: '30d'
        });
        res.status(200).json({
            code: 200,
            message: 'OK',
            token: token,
            exp: expTime
        });
    } catch (error) {
        res.status(404).json({
            code: 404,
            message: "Not Authenticated"
        })
    }
    
});

module.exports = router;