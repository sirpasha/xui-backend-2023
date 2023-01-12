const dotenv = require('dotenv');
const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const axios = require('axios');
const jtfd = require("json-to-form-data");
const https = require('https');
const httpsAgent = new https.Agent({ rejectUnauthorized: false });
const { v4: uuidv4 } = require('uuid');
const base64json = require('base64json');

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
dotenv.config();

const data = {
    'username': process.env.LOGIN,
    'password': process.env.PASSWORD
};

// Middleware
router.use((req, res, next) => {
    console.clear();
    next()
})
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());


// NODEJS SERVER STATUS
router.get('/check', async (req, res, err) => {
	console.log('Received Request');
    res.status(200).json({
        ENV: process.env.NODE_ENV,
        DEVELOPER: process.env.DEVELOPER,
        VERSION: process.env.VERSION
    });
});

// Get Server's Status FR ##########################################################################################################################
router.get('/fr/status', async (req, res, err) => {
    await axios.post(`${process.env.FR}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie
            }
        };

        await axios.post(`${process.env.FR}:61501/server/status`,{}, headers, { httpsAgent: httpsAgent })
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

// Get Server's Status NL ##########################################################################################################################
router.get('/nl/status', async (req, res, err) => {
    await axios.post(`${process.env.NL}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie
            }
        };

        await axios.post(`${process.env.NL}:61501/server/status`,{}, headers, { httpsAgent: httpsAgent })
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

// Get Server's Status DE ##########################################################################################################################
router.get('/de/status', async (req, res, err) => {
    await axios.post(`${process.env.DE}:61501/login`, data, { httpsAgent: httpsAgent})
    .then (async (response) => {
        const receivedCookie = response.headers['set-cookie'];
        const cookie = JSON.stringify(receivedCookie).replace(/[\])}[{(]/g, '');
        const theCookie = cookie.replace('"', '');
        const headers = {
            headers: {
                "Cookie": theCookie
            }
        };

        await axios.post(`${process.env.DE}:61501/server/status`,{}, headers, { httpsAgent: httpsAgent })
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


// Add User to DE Server ##########################################################################################################################
router.post('/de/add', async (req, res, err) => {
    const serverUrl = process.env.DE;
    await axios.post(`${serverUrl}:61501/login`, data, { httpsAgent: httpsAgent})
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
        
        
        await axios.post(`${serverUrl}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
        .then(async (response) => {
            const users = response.data.obj;
            const user = users.find(el => el.remark == remark);
            if (!user || user.port != thePort) {
                const total = 53687091200;
                const month = 30 * 24 * 3600;
                const expTime = (unixTimestamp() + month) * 1000;
                const thePort = Math.floor(Math.random()*50000) + 10000;
                const theUUID = uuidv4();
                const raw = `up=0&down=0&total=${total}&remark=${remark}&enable=true&expiryTime=${expTime}&listen=&port=${thePort}&protocol=vmess&settings=%7B%0A%20%20%22clients%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22id%22%3A%20%22${theUUID}%22%2C%0A%20%20%20%20%20%20%22alterId%22%3A%200%0A%20%20%20%20%7D%0A%20%20%5D%2C%0A%20%20%22disableInsecureEncryption%22%3A%20false%0A%7D&streamSettings=%7B%0A%20%20%22network%22%3A%20%22ws%22%2C%0A%20%20%22security%22%3A%20%22tls%22%2C%0A%20%20%22tlsSettings%22%3A%20%7B%0A%20%20%20%20%22serverName%22%3A%20%22de.aqaqomi.ir%22%2C%0A%20%20%20%20%22certificates%22%3A%20%5B%0A%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%22certificateFile%22%3A%20%22%2Froot%2Fcert%2Fde.aqaqomi.ir.cer%22%2C%0A%20%20%20%20%20%20%20%20%22keyFile%22%3A%20%22%2Froot%2Fcert%2Fde.aqaqomi.ir.key%22%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%2C%0A%20%20%20%20%22alpn%22%3A%20%5B%5D%0A%20%20%7D%2C%0A%20%20%22wsSettings%22%3A%20%7B%0A%20%20%20%20%22acceptProxyProtocol%22%3A%20false%2C%0A%20%20%20%20%22path%22%3A%20%22%2F%22%2C%0A%20%20%20%20%22headers%22%3A%20%7B%7D%0A%20%20%7D%0A%7D&sniffing=%7B%0A%20%20%22enabled%22%3A%20true%2C%0A%20%20%22destOverride%22%3A%20%5B%0A%20%20%20%20%22http%22%2C%0A%20%20%20%20%22tls%22%0A%20%20%5D%0A%7D`;
                
                await axios.post(`${serverUrl}:61501/xui/inbound/add`,raw, headers, { httpsAgent: httpsAgent })
                .then (async (response) => {
                    await axios.post(`${serverUrl}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
                    .then(async (response) => {
                        const users = response.data.obj;
                        const user = await users.find(el => el.remark == remark);
                        if (user || user.port == thePort) {
                        const userPrefix = {
                            "v": "2",
                            "ps": user.remark,
                            "add": serverUrl.replace("https://", ""),
                            "port": user.port,
                            "id": theUUID,
                            "aid": 0,
                            "net": "ws",
                            "type": "none",
                            "host": "",
                            "path": "/",
                            "tls": "tls"
                          };
                        const theCreatedUser = await base64json.stringify(userPrefix, null, 2);
                        res.status(200).json({
                            user: `vmess://${theCreatedUser}`
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

// Add User to NL Server ##########################################################################################################################
router.post('/nl/add', async (req, res, err) => {
    const serverUrl = process.env.NL;
    await axios.post(`${serverUrl}:61501/login`, data, { httpsAgent: httpsAgent})
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
        
        
        await axios.post(`${serverUrl}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
        .then(async (response) => {
            const users = response.data.obj;
            const user = users.find(el => el.remark == remark);
            if (!user || user.port != thePort) {
                const total = 32212254720;
                const month = 30 * 24 * 3600;
                const expTime = (unixTimestamp() + month) * 1000;
                const thePort = Math.floor(Math.random()*50000) + 10000;
                const theUUID = uuidv4();
                const raw = `up=0&down=0&total=${total}&remark=${remark}&enable=true&expiryTime=${expTime}&listen=&port=${thePort}&protocol=vmess&settings=%7B%0A%20%20%22clients%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22id%22%3A%20%22${theUUID}%22%2C%0A%20%20%20%20%20%20%22alterId%22%3A%200%0A%20%20%20%20%7D%0A%20%20%5D%2C%0A%20%20%22disableInsecureEncryption%22%3A%20false%0A%7D&streamSettings=%7B%0A%20%20%22network%22%3A%20%22ws%22%2C%0A%20%20%22security%22%3A%20%22tls%22%2C%0A%20%20%22tlsSettings%22%3A%20%7B%0A%20%20%20%20%22serverName%22%3A%20%22nl.aqaqomi.ir%22%2C%0A%20%20%20%20%22certificates%22%3A%20%5B%0A%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%22certificateFile%22%3A%20%22%2Froot%2Fcert%2Fnl.aqaqomi.ir.cer%22%2C%0A%20%20%20%20%20%20%20%20%22keyFile%22%3A%20%22%2Froot%2Fcert%2Fnl.aqaqomi.ir.key%22%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%2C%0A%20%20%20%20%22alpn%22%3A%20%5B%5D%0A%20%20%7D%2C%0A%20%20%22wsSettings%22%3A%20%7B%0A%20%20%20%20%22acceptProxyProtocol%22%3A%20false%2C%0A%20%20%20%20%22path%22%3A%20%22%2F%22%2C%0A%20%20%20%20%22headers%22%3A%20%7B%7D%0A%20%20%7D%0A%7D&sniffing=%7B%0A%20%20%22enabled%22%3A%20true%2C%0A%20%20%22destOverride%22%3A%20%5B%0A%20%20%20%20%22http%22%2C%0A%20%20%20%20%22tls%22%0A%20%20%5D%0A%7D`;
                
                await axios.post(`${serverUrl}:61501/xui/inbound/add`,raw, headers, { httpsAgent: httpsAgent })
                .then (async (response) => {
                    await axios.post(`${serverUrl}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
                    .then(async (response) => {
                        const users = response.data.obj;
                        const user = await users.find(el => el.remark == remark);
                        if (user || user.port == thePort) {
                        const userPrefix = {
                            "v": "2",
                            "ps": user.remark,
                            "add": serverUrl.replace("https://", ""),
                            "port": user.port,
                            "id": theUUID,
                            "aid": 0,
                            "net": "ws",
                            "type": "none",
                            "host": "",
                            "path": "/",
                            "tls": "tls"
                          };

                          console.log(userPrefix);
                        const theCreatedUser = await base64json.stringify(userPrefix, null, 2);
                        res.status(200).json({
                            user: `vmess://${theCreatedUser}`
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

// Add User to FR Server ##########################################################################################################################
router.post('/fr/add', async (req, res, err) => {
    const serverUrl = process.env.FR;
    await axios.post(`${serverUrl}:61501/login`, data, { httpsAgent: httpsAgent})
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
        
        
        await axios.post(`${serverUrl}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
        .then(async (response) => {
            const users = response.data.obj;
            const user = users.find(el => el.remark == remark);
            if (!user || user.port != thePort) {
                const total = 53687091200;
                const month = 30 * 24 * 3600;
                const expTime = (unixTimestamp() + month) * 1000;
                const thePort = Math.floor(Math.random()*50000) + 10000;
                const theUUID = uuidv4();
                const raw = `up=0&down=0&total=${total}&remark=${remark}&enable=true&expiryTime=${expTime}&listen=&port=${thePort}&protocol=vmess&settings=%7B%0A%20%20%22clients%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22id%22%3A%20%22${theUUID}%22%2C%0A%20%20%20%20%20%20%22alterId%22%3A%200%0A%20%20%20%20%7D%0A%20%20%5D%2C%0A%20%20%22disableInsecureEncryption%22%3A%20false%0A%7D&streamSettings=%7B%0A%20%20%22network%22%3A%20%22ws%22%2C%0A%20%20%22security%22%3A%20%22tls%22%2C%0A%20%20%22tlsSettings%22%3A%20%7B%0A%20%20%20%20%22serverName%22%3A%20%22fr.aqaqomi.ir%22%2C%0A%20%20%20%20%22certificates%22%3A%20%5B%0A%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%22certificateFile%22%3A%20%22%2Froot%2Fcert%2Ffr.aqaqomi.ir.cer%22%2C%0A%20%20%20%20%20%20%20%20%22keyFile%22%3A%20%22%2Froot%2Fcert%2Ffr.aqaqomi.ir.key%22%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%2C%0A%20%20%20%20%22alpn%22%3A%20%5B%5D%0A%20%20%7D%2C%0A%20%20%22wsSettings%22%3A%20%7B%0A%20%20%20%20%22acceptProxyProtocol%22%3A%20false%2C%0A%20%20%20%20%22path%22%3A%20%22%2F%22%2C%0A%20%20%20%20%22headers%22%3A%20%7B%7D%0A%20%20%7D%0A%7D&sniffing=%7B%0A%20%20%22enabled%22%3A%20true%2C%0A%20%20%22destOverride%22%3A%20%5B%0A%20%20%20%20%22http%22%2C%0A%20%20%20%20%22tls%22%0A%20%20%5D%0A%7D`;
                
                await axios.post(`${serverUrl}:61501/xui/inbound/add`,raw, headers, { httpsAgent: httpsAgent })
                .then (async (response) => {
                    await axios.post(`${serverUrl}:61501/xui/inbound/list`, {}, headers, { httpsAgent: httpsAgent })
                    .then(async (response) => {
                        const users = response.data.obj;
                        const user = await users.find(el => el.remark == remark);
                        if (user || user.port == thePort) {
                        const userPrefix = {
                            "v": "2",
                            "ps": user.remark,
                            "add": serverUrl.replace("https://", ""),
                            "port": user.port,
                            "id": theUUID,
                            "aid": 0,
                            "net": "ws",
                            "type": "none",
                            "host": "",
                            "path": "/",
                            "tls": "tls"
                          };

                          console.log(userPrefix);
                        const theCreatedUser = await base64json.stringify(userPrefix, null, 2);
                        res.status(200).json({
                            user: `vmess://${theCreatedUser}`
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

module.exports = router;
