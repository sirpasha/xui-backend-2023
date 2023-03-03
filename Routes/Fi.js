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
const Logs = require('../Models/Logs');
const {Telegraf} = require('telegraf')
const bot = new Telegraf('6117756292:AAGrRDyqOqJtVQytB8VLk7V3l-1tEZOhXoE');

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
dotenv.config();

const theServerUrl = "fi.aqaqomi.ir";
const serverAddress= process.env.FI;
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



// Get Server's Status DE2 ###########
router.get('/status', async (req, res, err) => {
    await axios.post(`${serverAddress}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie
            }
        };

        await axios.post(`${serverAddress}:61501/server/status`,{}, headers, { httpsAgent: httpsAgent })
        .then (response => {
            const serverStatus = response.data;
            res.status(200).json({
                status: serverStatus
            });
        })
        .catch(err => {
            res.status(400).json({
                err: "Error Getting Status"
            });
        });
    })
    .catch(err => {
        res.status(400).json({
            err: "Invalid Login"
        });
    });
});


// Add User to DE2 Server ##########################################################################################################################
router.post('/add', async (req, res, err) => {
    await axios.post(`${serverAddress}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie,
                "Content-type": 'application/x-www-form-urlencoded'
            }
        };

        
        function unixTimestamp () {  
            return Math.floor(Date.now() / 1000)
        }

        const remark = req.body.remark;
        
        
        await axios.post(`${serverAddress}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
        .then(async (response) => {
            const users = response.data.obj;
            const user = users.find(el => el.remark == remark);
            if (!user || user.port != thePort) {
                const total = 53687091200;
                const month = 30 * 24 * 3600;
                const expTime = (unixTimestamp() + month) * 1000;
                const thePort = Math.floor(Math.random()*50000) + 10000;
                const theUUID = uuidv4();
                const raw = `up=0&down=0&total=${total}&remark=${remark}&enable=true&expiryTime=${expTime}&listen=&port=${thePort}&protocol=vmess&settings=%7B%0A%20%20%22clients%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22id%22%3A%20%22${theUUID}%22%2C%0A%20%20%20%20%20%20%22alterId%22%3A%200%0A%20%20%20%20%7D%0A%20%20%5D%2C%0A%20%20%22disableInsecureEncryption%22%3A%20false%0A%7D&streamSettings=%7B%0A%20%20%22network%22%3A%20%22ws%22%2C%0A%20%20%22security%22%3A%20%22tls%22%2C%0A%20%20%22tlsSettings%22%3A%20%7B%0A%20%20%20%20%22serverName%22%3A%20%22${theServerUrl}%22%2C%0A%20%20%20%20%22certificates%22%3A%20%5B%0A%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%22certificateFile%22%3A%20%22%2Froot%2Fcert%2F${theServerUrl}.cer%22%2C%0A%20%20%20%20%20%20%20%20%22keyFile%22%3A%20%22%2Froot%2Fcert%2F${theServerUrl}.key%22%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%2C%0A%20%20%20%20%22alpn%22%3A%20%5B%5D%0A%20%20%7D%2C%0A%20%20%22wsSettings%22%3A%20%7B%0A%20%20%20%20%22acceptProxyProtocol%22%3A%20false%2C%0A%20%20%20%20%22path%22%3A%20%22%2F%22%2C%0A%20%20%20%20%22headers%22%3A%20%7B%7D%0A%20%20%7D%0A%7D&sniffing=%7B%0A%20%20%22enabled%22%3A%20true%2C%0A%20%20%22destOverride%22%3A%20%5B%0A%20%20%20%20%22http%22%2C%0A%20%20%20%20%22tls%22%0A%20%20%5D%0A%7D`;
                
                await axios.post(`${serverAddress}:61501/xui/inbound/add`,raw, headers, { httpsAgent: httpsAgent })
                .then (async (response) => {
                    await axios.post(`${serverAddress}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
                    .then(async (response) => {
                        const users = response.data.obj;
                        const user = await users.find(el => el.remark == remark);
                        if (user || user.port == thePort) {
                            const userPrefix = {
                                "v": "2",
                                "ps": user.remark,
                                "add": serverAddress.replace("https://", ""),
                                "port": user.port,
                                "id": theUUID,
                                "aid": 0,
                                "net": "ws",
                                "type": "none",
                                "host": "",
                                "path": "/",
                                "tls": "tls"
                            };
                            creditManage(req.headers.token, user.remark, user.port, 'ایجاد');
                            sendToTelegram(user, "ایجاد");
                            const theCreatedUser = await base64json.stringify(userPrefix, null, 2);
                        res.status(200).json({
                            uri: `vmess://${theCreatedUser}`,
                            id: user.id,
                            up: user.up,
                            down: user.down,
                            total: user.total,
                            remark: user.remark,
                            enable: user.enable,
                            expiryTime: user.expiryTime,
                            port: user.port,
                            protocol: user.protocol,
                            streamSettings: user.streamSettings
                        });
                    } else {
                        throw err;
                    }
                    })
                    .catch(err => {
                        res.status(400).json({
                            err: "User added but couldn't get its details"
                        });
                    });
                    
                })
                .catch(err => {
                    res.status(400).json({
                        err: "Error Adding User"
                    });
                });
            } else {
                throw err;
            }
                
        })
        .catch(err => {
            res.status(400).json({
                err: "Error Getting User details"
            });
        });


    })
    .catch(err => {
        res.status(400).json({
            err: "Invalid Login"
        });
    });
});

// Get Inbounds Count Status DE2 ##########################################################################################################################
router.get('/inbounds', async (req, res, err) => {
    await axios.post(`${serverAddress}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie
            }
        };

        await axios.post(`${serverAddress}:61501/xui/inbound/list`,{}, headers, { httpsAgent: httpsAgent })
        .then (response => {
            const serverStatus = response.data.obj;
            res.status(200).json({
                count: serverStatus.length
            });
        })
        .catch(err => {
            res.status(400).json({
                err: "Error Getting Status"
            });
        });
    })
    .catch(err => {
        res.status(400).json({
            err: "Invalid Login"
        });
    });
});

// Get Inbounds List DE2 ##########################################################################################################################
router.post('/userslist', async (req, res, err) => {
    try {
        const token = jwt.verify(req.headers.token, process.env.TOKEN, async (err,result) => {
            if (err) {
                res.status(400).json({
                    code: 400,
                    error: 'Invalid Access',
                    message: 'Please Login again!'
                });
            } else {
                const foundedUser = await Resellers.findOne({
                    username: result.username
                });
                await axios.post(`${serverAddress}:61501/login`, data, { httpsAgent: httpsAgent})
                .then (async (response) => {
                    const receivedCookie = response.headers['set-cookie'];
                    const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
                    const theCookie = cookie.replace('"', '');
                    const headers = {
                        headers: {
                            "Cookie": theCookie
                        }
                    };
                    await axios.post(`${serverAddress}:61501/xui/inbound/list`,{}, headers, { httpsAgent: httpsAgent })
                    .then (async (response) => {
                        const users = response.data.obj;
                        let theUsers = [];
                        if (foundedUser.prefix) {
                            users.forEach(user => {
                                if ((user.remark).startsWith(foundedUser.prefix)) {
                                    theUsers.push(user);
                                }
                                return
                                
                            });
                        } else {
                            users.forEach(user => {
                                theUsers.push(user)
                            });
                        }
                        res.status(200).json({
                            users: theUsers
                        });
                    })
                    .catch(err => {
                        res.status(200).json({
                            users: []
                        });
                    });
                    })
                    .catch(err => {
                        res.status(400).json({
                            err: "Invalid Login"
                        });
                    });
            }
        });    
    } catch (err) {
        res.status(400).json({
            err: "Something Wrong"
        });
    }
});

// Update User on DE2 Server ##########################################################################################################################
router.post('/revise', async (req, res, err) => {
    await axios.post(`${serverAddress}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie,
                "Content-type": 'application/x-www-form-urlencoded'
            }
        };

        
        function unixTimestamp () {  
            return Math.floor(Date.now() / 1000)
        }

        const id = req.body.id;
        const remark = req.body.remark;
        const port = req.body.port;
        const theUUId = req.body.uuid;
        const total = 53687091200;
        const month = 30 * 24 * 3600;
        const expTime = (unixTimestamp() + month) * 1000;
        const raw = `up=0&down=0&total=${total}&remark=${remark}&enable=true&expiryTime=${expTime}&listen=&port=${port}&protocol=vmess&settings=%7B%0A%20%20%22clients%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22id%22%3A%20%22${theUUId}%22%2C%0A%20%20%20%20%20%20%22alterId%22%3A%200%0A%20%20%20%20%7D%0A%20%20%5D%2C%0A%20%20%22disableInsecureEncryption%22%3A%20false%0A%7D&streamSettings=%7B%0A%20%20%22network%22%3A%20%22ws%22%2C%0A%20%20%22security%22%3A%20%22tls%22%2C%0A%20%20%22tlsSettings%22%3A%20%7B%0A%20%20%20%20%22serverName%22%3A%20%22${theServerUrl}%22%2C%0A%20%20%20%20%22certificates%22%3A%20%5B%0A%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%22certificateFile%22%3A%20%22%2Froot%2Fcert%2F${theServerUrl}.cer%22%2C%0A%20%20%20%20%20%20%20%20%22keyFile%22%3A%20%22%2Froot%2Fcert%2F${theServerUrl}.key%22%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%2C%0A%20%20%20%20%22alpn%22%3A%20%5B%5D%0A%20%20%7D%2C%0A%20%20%22wsSettings%22%3A%20%7B%0A%20%20%20%20%22acceptProxyProtocol%22%3A%20false%2C%0A%20%20%20%20%22path%22%3A%20%22%2F%22%2C%0A%20%20%20%20%22headers%22%3A%20%7B%7D%0A%20%20%7D%0A%7D&sniffing=%7B%0A%20%20%22enabled%22%3A%20true%2C%0A%20%20%22destOverride%22%3A%20%5B%0A%20%20%20%20%22http%22%2C%0A%20%20%20%20%22tls%22%0A%20%20%5D%0A%7D`;
        const user = {
            id: id,
            port: port,
            remark: remark
        };
        try {
            await axios.post(`${serverAddress}:61501/xui/inbound/update/${id}`, raw, headers, { httpsAgent: httpsAgent })
            .then(response => {
                creditManage(req.headers.token, remark, port, 'تمدید');
                sendToTelegram(user, "تمدید");
                res.status(200).json({
                    msg: "User Updated Successfully"
                });
            })
            .catch(err => {
                throw err;
            });
        } catch {
            res.status(400).json({
                err: "Error Updating User"
            });
        }
        
                
        })
        .catch(err => {
            res.status(400).json({
                err: "Invalid Login"
            });
        });


});

const sendToTelegram = async (user, status) => {
    await bot.telegram.sendMessage(-1001832726797, `کاربر ${user.remark} با پورت ${user.port} و شناسه ${user.id} روی سرور ${theServerUrl} با موفقیت ${status} شد.`)
    .then(response => console.log(response))
    .catch(err => console.log(err));
};

const creditManage = async (value, remark, port, theState) => {
    const token = jwt.verify(value, process.env.TOKEN, async (err,result) => {

        const findReseller = await Resellers.findOne({username: result.username})
        .then(async (res) => {
            const logs = new Logs({ reseller: res.username, credit: res.credit - 1, description: `کاربر ${remark} با پورت ${port} بر روی سرور ${theServerUrl} ${theState} شد و یک اعتبار از حساب شما کسر گردید.` });

            logs.save(function (err, logs) {
                if (err) return console.error(err);
                console.log(logs);
            });
            
            const user = await Resellers.findOneAndUpdate(
                {username: result.username},
                { $inc: {credit: - 1} }
            );
        })
        .catch(err => {
            console.error(err);
        });
    });
};

module.exports = router;