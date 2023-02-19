const dotenv = require('dotenv');
const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const axios = require('axios');
const jtfd = require("json-to-form-data");
const https = require('https');
const httpsAgent = new https.Agent({ rejectUnauthorized: false });
const { v4: uuidv4 } = require('uuid');
const base64json = require('base64json');
const jwt = require('jsonwebtoken');

const bcrypt = require('bcrypt');

const Resellers = require('../Models/Resellers');

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
dotenv.config();


const data = {
    'username': process.env.LOGIN,
    'password': process.env.PASSWORD
};

// Middleware
router.use((req, res, next) => {
    next()
})
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());


// NODEJS SERVER STATUS
router.get('/check', async (req, res, err) => {
    res.status(200).json({
        ENV: process.env.NODE_ENV,
        DEVELOPER: process.env.DEVELOPER,
        VERSION: process.env.VERSION
    });
});


router.post('/reg', async (req, res, err) => {
    try {
        if (!req.is('application/json')) {
            throw err;
        }
        const username = req.body.username;
        const password = req.body.password;
        const encryptedPass = bcrypt.hashSync(req.body.password, 10);
        const credit = req.body.credit;
        const prefix = req.body.prefix;
        const userDetails = {
            username: username,
            password: encryptedPass,
            credit: credit,
            prefix: prefix
        };
        const data = new Resellers(userDetails);
        const newData = await data.save();
        res.status(201).json({
            status: 201,
            response: newData
        });
    } catch (err) {
        res.status(400).json({
            status: 400,
            error: err.message
        });
    };
});


router.post('/user', async (req, res, err) => {
    try {
        const uri = req.body.uri;
        const checkURI = async () => {
            if (uri.startsWith("vmess://")) {
                const theURI = await uri.slice(8);
                const userDetails = await base64json.parse(theURI);
                return userDetails;
            } else if (uri.startsWith("trojan://")) {
                const theURI = await uri.slice(9);
                const server = theURI.substring(
                    theURI.indexOf("@") + 1, 
                    theURI.lastIndexOf(":")
                );
                const port = theURI.substring(
                    theURI.indexOf(":") + 1, 
                    theURI.lastIndexOf("#")
                );
                const remarkMain = theURI.substring(
                    theURI.indexOf("#") + 1
                );
                const remark = remarkMain.replace('%20', " ");
                const userDetails = {
                    add: server,
                    ps: remark,
                    port: port
                };
                return userDetails;
            } else if (uri.startsWith("vless://")) {
                const theURI = await uri.slice(8);
                const server = theURI.substring(
                    theURI.indexOf("@") + 1, 
                    theURI.lastIndexOf(":")
                );
                const port = theURI.substring(
                    theURI.indexOf(":") + 1, 
                    theURI.lastIndexOf("?")
                );
                const remark = theURI.substring(
                    theURI.indexOf("#") + 1
                );
                const userDetails = {
                    add: server,
                    ps: remark,
                    port: port
                };
                return userDetails;
            } else {
                throw err;
            }
        };
        const theUser = await checkURI(uri);
        await axios.post(`https://${theUser.add}:61501/login`, data, { httpsAgent: httpsAgent})
        .then (async (response) => {
            const receivedCookie = response.headers['set-cookie'];
            const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
            const theCookie = cookie.replace('"', '');
            const headers = {
                headers: {
                    "Cookie": theCookie
                }
            };
            await axios.post(`https://${theUser.add}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
            .then(async (response) => {
                const users = response.data.obj;
                const user = await users.find(el => el.remark == theUser.ps);
                if (user.remark == theUser.ps && user.port == theUser.port) {
                    const theCreatedUser = await base64json.stringify(theUser, null, 2);
                    res.status(200).json({
                        uri: `vmess://${theCreatedUser}`,
                        res: user,
                    });
                } else {
                    throw err;
                }
            })
            .catch(err => {
                res.status(400).json({
                    err: "User Not found"
                });
            })
        })
        .catch(err => {
            res.status(400).json({
                err: "Error Logging In to Access Server"
            });
        })
    } catch {
        res.status(400).json({
            err: "input link error"
        });
    };
});

// Get Resellers Credit ##########################################################################################################################
router.get('/reseller', async (req, res, error) => {
    try {
        const token = jwt.verify(req.headers.token, process.env.TOKEN, async (err,result) => {
            if (err) {
                throw err;
            } else {
                const user = await Resellers.findOne(
                    {username: result.username}
                );
                res.status(200).json({
                    username: user.username,
                    credit: user.credit,
                    prefix: user.prefix
                });
            }
        });
    } catch (err) {
        res.status(400).json({
            err: "Error Getting Information"
        });
    }
});

const creditManage = async (value) => {
    const token = jwt.verify(value, process.env.TOKEN, async (err,result) => {
        const user = await Resellers.findOneAndUpdate(
            {username: result.username},
            { $inc: {credit: - 1} }
        );
    });
};

module.exports = router;
