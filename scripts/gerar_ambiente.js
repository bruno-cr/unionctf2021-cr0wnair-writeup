// Gera os artefatos PROPRIOS do grupo (chave RSA + flag) na hora,
// em vez de commitar segredos fixos no repositorio.
//
// Uso: node scripts/gerar_ambiente.js

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, '..', 'app', 'keys');

if (!fs.existsSync(KEYS_DIR)) {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 1024, // apenas para demonstracao didatica -- nao usar em producao
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

fs.writeFileSync(path.join(KEYS_DIR, 'privkey.pem'), privateKey);
fs.writeFileSync(path.join(KEYS_DIR, 'pubkey.pem'), publicKey);
fs.writeFileSync(
  path.join(KEYS_DIR, 'flag.txt'),
  'grupo{flag_propria_de_demonstracao_cr0wnair}\n'
);

console.log('Ambiente gerado com sucesso em app/keys/:');
console.log('  - privkey.pem (chave RSA propria, 1024 bits)');
console.log('  - pubkey.pem');
console.log('  - flag.txt (flag propria do grupo)');
