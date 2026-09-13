// config.js -- NAO commitar chaves/flag fixas no repositorio.
// Este arquivo le os artefatos gerados por scripts/gerar_ambiente.js
// (chave RSA propria + flag propria do grupo), conforme orientacao
// do professor: nunca reaproveitar segredos do desafio original.

const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, 'keys');

if (!fs.existsSync(path.join(KEYS_DIR, 'privkey.pem'))) {
  throw new Error(
    'Chaves nao encontradas. Rode "node scripts/gerar_ambiente.js" primeiro.'
  );
}

module.exports = {
  privkey: fs.readFileSync(path.join(KEYS_DIR, 'privkey.pem'), 'utf8'),
  pubkey: fs.readFileSync(path.join(KEYS_DIR, 'pubkey.pem'), 'utf8'),
  flag: fs.readFileSync(path.join(KEYS_DIR, 'flag.txt'), 'utf8').trim(),
};
