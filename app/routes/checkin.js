// Reimplementacao fiel de routes/checkin.js do cr0wnair original,
// confirmada via write-up publico (ret2school). Artefatos (chave,
// flag) sao proprios do grupo -- ver ../config.js.

const express = require('express');
const jpv = require('jpv');
const jwt = require('jwt-simple');
const path = require('path');
const router = express.Router();

const config = require('../config');

const pattern = {
  firstName: /^\w{1,30}$/,
  lastName: /^\w{1,30}$/,
  passport: /^[0-9]{9}$/,
  ffp: /^(|CA[0-9]{8})$/,
  extras: [
    { sssr: /^(BULK|UMNR|VGML)$/ },
  ],
};

function isSpecialCustomer(passport, frequentFlyerNumber) {
  return false;
}

function createToken(passport, frequentFlyerNumber) {
  var status = isSpecialCustomer(passport, frequentFlyerNumber) ? 'gold' : 'bronze';
  var body = { status: status, ffp: frequentFlyerNumber };
  return jwt.encode(body, config.privkey, 'RS256');
}

router.post('/checkin', function (req, res, next) {
  if (!req.body) return res.sendStatus(400);
  var data = req.body;

  if (jpv.validate(data, pattern, { debug: false, mode: 'strict' })) {
    if (data['firstName'] == 'Tony' && data['lastName'] == 'Abbott') {
      var response = { msg: 'You have successfully checked in!' };
    } else if (data['ffp']) {
      var response = { msg: 'You have successfully checked in.' };
      for (const e in data['extras']) {
        if (data['extras'][e]['sssr'] && data['extras'][e]['sssr'] === 'FQTU') {
          var token = createToken(data['passport'], data['ffp']);
          var response = { msg: 'Checked in and marked for upgrade.', token: token };
        }
      }
    } else {
      var response = { msg: 'You have successfully checked in!' };
    }
  } else {
    var response = { msg: 'Invalid checkin data provided, please try again.' };
  }

  res.json(response);
});

module.exports = router;
