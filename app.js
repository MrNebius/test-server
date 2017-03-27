const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const MongoClient = require('mongodb').MongoClient;
const bcrypt = require('bcrypt-nodejs');
const jwt = require('jsonwebtoken');

let collection;
const config = require('./config'); // get our config file
app.set('superSecret', config.secret); // secret variable

const getJwt = (username) => {
    return jwt.sign({username}, app.get('superSecret'), {
        expiresIn: '24h'
    });
};

const defender = (body) => {
    return (body.username.length < 21 && body.password.length < 21 && body.username.length > 0 && body.password.length > 0);
};

MongoClient.connect("mongodb://localhost:27017/usersStorage", (err, db) => {
    if (!err) {
        collection = db.collection('users');
        console.log("We are connected to db");
    } else {
        console.log("error connection", err);
    }
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, token");
    res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT");
    console.log('Something is happening. ');
    if (req.method === 'OPTIONS') res.sendStatus(200);
    else next();
});

app.post('/auth/new', (req, res) => {
    if (defender(req.body)) {
        collection.findOne({username: req.body.username}, (err, user) => {
            if (!user) {
                bcrypt.hash(req.body.password, null, null, (err, hash) => {
                    collection.insert({username: req.body.username, password: hash}, (err) => {
                        if (err) {
                            res.send("error");
                        } else {
                            res.json({token: getJwt(req.body.username), message: 'sucsess'});
                        }
                    });
                });
            } else {
                res.sendStatus(401);
            }
        });
    } else {
        res.status(403).send({message: 'error'});
    }
});

app.post('/auth', (req, res) => {
    if (defender(req.body)) {
        collection.findOne({username: req.body.username}, (err, user) => {
            if (user) {
                bcrypt.compare(req.body.password, user.password, (err, result) => {
                    if (result) {
                        res.json({
                            message: 'Enjoy your token!',
                            token: getJwt(req.body.username)
                        });
                    } else {
                        res.sendStatus(401);
                    }
                });
            } else {
                res.sendStatus(401);
            }
        });
    } else {
        res.status(403).send({message: 'error'});
    }
});

app.use((req, res, next) => {
    const token = req.headers['token'];
    if (token) {
        jwt.verify(token, app.get('superSecret'), (err, decoded) => {
            if (err) {
                res.json({success: false, message: 'Invalid user, please relogin '});
            } else {
                req.decoded = decoded;
                next();
            }
        });
    } else {
        res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
    }
});

app.get('/auth', (req, res) => {
    res.json({success: true, token: getJwt(req.decoded['username'])})
});

app.get('/markers', (req, res) => {
    collection.findOne({username: req.decoded['username']}, (err, user) => {
        if (err || !user.markers) {
            res.json({message: 'You have no markers saved', markers: []});
        } else {
            res.json({success: true, message: 'Success', markers: user.markers})
        }
    });
});

app.put('/markers', (req, res) => {
    collection.updateOne({username: req.decoded['username']}, {$set: {markers: req.body.markers}}, (err, result) => {
        if (err) {
            res.json({message: 'Error'});
        } else {
            res.json({message: 'Successfully saved'});
        }
    });
});

app.delete('/markers', (req, res) => {
    collection.updateOne({username: req.decoded['username']}, {$unset: {markers: 1}}, (err, result) => {
        if (err) {
            res.json({message: 'Error'});
        } else {
            res.json({message: 'Successfully deleted'});
        }
    });
});

app.listen(8080);