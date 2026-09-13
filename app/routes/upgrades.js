// Reimplementacao fiel de routes/upgrades.js do cr0wnair original.

const express = require('express');
const jwt = require('jwt-simple');
const router = express.Router();

const config = require('../config');

function getLoyaltyStatus(req, res, next) {
  if (req.headers.authorization) {
    let token = req.headers.authorization.split(' ')[1];
    try {
      var decoded = jwt.decode(token, config.pubkey); // sem especificar o algoritmo -- o bug
    } catch (err) {
      return res.json({ msg: 'Token is not valid.' });
    }
    res.locals.token = decoded;
  }
  next();
}

router.post('/flag', [getLoyaltyStatus], function (req, res, next) {
  if (res.locals.token && res.locals.token.status == 'gold') {
    var response = { msg: config.flag };
  } else {
    var response = { msg: 'You do not qualify for this upgrade at this time.' };
  }
  res.json(response);
});

module.exports = router;
