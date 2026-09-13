// Versao CORRIGIDA de upgrades.js -- politica de algoritmos permitidos.
//
// Unica mudanca em relacao ao upgrades.js original: o algoritmo e
// forcado explicitamente ('RS256'), no lugar de deixar o token
// declarar (via header.alg) como verificar a propria assinatura.
//
// jwt-simple (lib/jwt.js): `var signingMethod = algorithmMap[algorithm || header.alg]`
// Passando 'RS256' aqui, o `algorithm` vence o `header.alg` -- o
// token forjado (header.alg = HS256) sera verificado como se fosse
// RS256, e a assinatura HMAC forjada falha nessa verificacao.

const express = require('express');
const jwt = require('jwt-simple');
const router = express.Router();

const config = require('../config');

const ALGORITMOS_PERMITIDOS = 'RS256'; // <-- a correcao

function getLoyaltyStatusSeguro(req, res, next) {
  if (req.headers.authorization) {
    let token = req.headers.authorization.split(' ')[1];
    try {
      var decoded = jwt.decode(token, config.pubkey, false, ALGORITMOS_PERMITIDOS);
    } catch (err) {
      return res.json({ msg: 'Token is not valid.', erro: err.message });
    }
    res.locals.token = decoded;
  }
  next();
}

router.post('/flag', [getLoyaltyStatusSeguro], function (req, res, next) {
  if (res.locals.token && res.locals.token.status == 'gold') {
    var response = { msg: config.flag };
  } else {
    var response = { msg: 'You do not qualify for this upgrade at this time.' };
  }
  res.json(response);
});

module.exports = router;
