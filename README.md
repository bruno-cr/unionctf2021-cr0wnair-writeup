# Union CTF 2021 — cr0wnair (Web)

Write-up e reprodução do desafio **cr0wnair**, categoria Web do
Union CTF 2021, desenvolvido como avaliação (E2) da disciplina
**Segurança Cibernética (CCO-04.2.01)** — PPGCC, UFSCar.

## Membros do grupo

- Bruno Camargo Ribeiro
- Bruno Hiroki Nagao Anhaia
- Cilene Renata Real
- Emerson Hermann Lira dos Santos
- Gabriel Alves Moreira
- Jonathan Choy Rivera
- Stephanie Maria Braga
- Thayná Marostica Machado da Silva
---

## 1. Identificação do desafio e objetivo

**cr0wnair** é uma aplicação Node.js de check-in de voo. Ao completar
um check-in, o servidor emite um **JWT** (JSON Web Token) assinado
com **RS256** (RSA + SHA-256), contendo o status do passageiro
(`bronze` ou `gold`).

**Objetivo:** obter um JWT com `{"status": "gold"}` aceito pelo
endpoint `/upgrades/flag`, revelando a flag — sem nunca ter acesso
direto à chave privada nem à chave pública do servidor.

Esse foi o desafio que estabelece uma integração entre os mecanismos de autenticação Web e os recursos de criptografia aplicada, evidenciando que a validação do algoritmo criptográfico, da chave empregada e da representação do token constitui uma única fronteira de confiança no processo de autenticação.

**O processo acontece nas etapas:** 

1. A aplicação Web disponibilizada utiliza versões desatualizadas das bibliotecas jpv e jwt-simple, apresentando possíveis vulnerabilidades decorrentes dessas dependências. 

A aplicação implementa uma verificação para impedir a utilização de determinados algoritmos na assinatura dos tokens JWT. Entretanto, essa validação pode ser contornada por meio da manipulação do construtor do objeto, especificamente quando sua propriedade name coincide com o valor de name de [].constructor. 

Após o contorno da validação, é possível recuperar a chave pública utilizada no processo de autenticação a partir de dois tokens JWT. 

Por fim, a chave pública obtida é utilizada indevidamente como segredo para gerar uma assinatura utilizando o algoritmo HS256, de natureza simétrica, em substituição ao RS256, que emprega um mecanismo de assinatura assimétrica. 

A exploração pode ser entendida em quatro etapas principais: 

Obtenção do token JWT 
A aplicação utiliza a biblioteca jpv para validar os dados enviados no endpoint /checkin. Entretanto, uma falha na validação de arrays permite contornar essa proteção. Ao fornecer um objeto manipulado no campo extras, é possível fazer a aplicação acreditar que recebeu um array válido e, ao mesmo tempo, inserir o valor sssr: "FQTU". Essa condição faz com que a aplicação gere e exponha um JWT.  

Obtenção da chave pública RSA 
 Os tokens obtidos são assinados originalmente com RS256, utilizando uma chave privada RSA. A partir de dois tokens válidos, o código explora propriedades matemáticas da assinatura RSA para calcular o módulo n da chave pública. O gcd (máximo divisor comum) entre os valores derivados das duas assinaturas permite recuperar esse módulo e, consequentemente, reconstruir a chave pública.  

Confusão entre RS256 e HS256 
O endpoint /upgrades utiliza jwt.decode(token, config.pubkey) sem restringir explicitamente o algoritmo esperado. Isso permite uma situação de algorithm confusion: em vez de verificar um token RS256 com a chave pública RSA, o servidor pode interpretar um token declarado como HS256 e utilizar a própria chave pública como segredo HMAC.  

Forjamento do token e obtenção da flag 
 Com a chave pública recuperada, é criado um novo JWT com alg: HS256 e payload contendo status: "gold". A assinatura é produzida utilizando HMAC-SHA256 e a chave pública como segredo. Como o servidor aceita essa combinação, o token falsificado é considerado válido e permite acessar /upgrades/flag. 

---

## 2. A vulnerabilidade

### 2.1 — Bypass do filtro de validação (`jpv`)

Código-fonte real do endpoint de check-in (`routes/checkin.js`):

```javascript
const pattern = {
  firstName: /^\w{1,30}$/,
  lastName: /^\w{1,30}$/,
  passport: /^[0-9]{9}$/,
  ffp: /^(|CA[0-9]{8})$/,
  extras: [
    { sssr: /^(BULK|UMNR|VGML)$/ },
  ],
};

router.post('/checkin', function (req, res, next) {
  var data = req.body;
  if (jpv.validate(data, pattern, { debug: true, mode: 'strict' })) {
    for (e in data['extras']) {
      if (data['extras'][e]['sssr'] && data['extras'][e]['sssr'] === 'FQTU') {
        var token = createToken(data['passport'], data['ffp']);
        // token devolvido na resposta
      }
    }
  }
});
```

Para receber um token, `extras` precisa conter `sssr: "FQTU"` — mas
o *pattern* declarado exige que `extras` seja um **array**, e
`FQTU` nem bate com o regex esperado (`BULK|UMNR|VGML`). Enviando um
array de verdade, a validação barra.

**O bypass:** a biblioteca `jpv` (na versão vulnerável, confirmada
como **2.0.1**, publicada em fevereiro de 2019 — a mesma "versão de
2 anos atrás" citada nos write-ups públicos em relação a fev/2021)
pode ser enganada a tratar um **objeto comum** como se fosse um
array, bastando incluir uma propriedade `constructor: {name:
"Array"}`, imitando a propriedade interna que o JavaScript usa para
identificar o tipo de um valor:

```json
{
  "firstName": "aa",
  "lastName": "aaa",
  "passport": "123456789",
  "ffp": "CA12345678",
  "extras": {
    "a": {"sssr": "FQTU"},
    "constructor": {"name": "Array"}
  }
}
```

Repetindo essa requisição variando o campo `ffp`, obtemos **vários
tokens RS256 válidos**, assinados sobre mensagens diferentes — o
material bruto necessário para o próximo passo.

### 2.2 — Confusão de algoritmo RS256 → HS256

Código-fonte real do endpoint de verificação (`routes/upgrades.js`):

```javascript
function getLoyaltyStatus(req, res, next) {
  if (req.headers.authorization) {
    let token = req.headers.authorization.split(' ')[1];
    var decoded = jwt.decode(token, config.pubkey); // sem especificar o algoritmo!
    res.locals.token = decoded;
  }
  next();
}
```

A biblioteca `jwt-simple` usa o algoritmo **declarado no header do
próprio token** (`header.alg`) para decidir como verificar a
assinatura — em vez de um algoritmo fixo esperado pelo servidor.

- **RS256** (assimétrico): assina com a chave **privada**, verifica
  com a **pública**.
- **HS256** (simétrico): assina **e** verifica com a **mesma**
  chave secreta.

Se o atacante muda o header para `"alg":"HS256"` e assina o token
usando a **chave pública** como se fosse o segredo HMAC, o servidor
— ao decodificar — usa essa mesma chave pública, mas agora como
segredo HMAC, e a verificação **bate**. É a vulnerabilidade
catalogada como **CVE-2017-11424**.

**A condição que falta:** o atacante precisa conhecer a chave
pública — e ela nunca é exposta diretamente pela aplicação. Daí a
necessidade da Seção 2.3.

### 2.3 — Recuperando a chave pública via MDC (GCD)

Uma assinatura RSA satisfaz: `assinatura^e ≡ mensagem_com_padding (mod N)`.

Isso significa que `assinatura^e - mensagem_com_padding` é **um
múltiplo exato de N**. Calculando essa conta para **várias
assinaturas diferentes** (mesma chave), todos os resultados são
múltiplos de `N` — e o **MDC (GCD)** entre eles tende a isolar
justamente `N`.

**Detalhe descoberto durante a implementação:** usando **apenas 2**
assinaturas, o GCD pode trazer um **fator espúrio extra**
compartilhado por coincidência entre as duas (na nossa primeira
tentativa, um fator `93 = 3×31`). A solução: usar **4 tokens** e
calcular o **GCD cumulativo** — fatores espúrios tendem a não se
repetir simultaneamente em todos os pares.

### 2.4 — Fechando com uma política de algoritmos permitidos (mitigação)

A causa raiz de toda a cadeia (Seção 2.2) é o servidor **confiar no
próprio token** para decidir como verificá-lo. A correção não exige
trocar de biblioteca — o `jwt-simple` já aceita um algoritmo forçado
como argumento:

```javascript
// routes/upgrades.js (ORIGINAL, vulneravel):
var decoded = jwt.decode(token, config.pubkey);

// routes/upgrades_seguro.js (CORRIGIDO):
var decoded = jwt.decode(token, config.pubkey, false, 'RS256');
```

No código-fonte do `jwt-simple` (`lib/jwt.js`):

```javascript
var signingMethod = algorithmMap[algorithm || header.alg];
```

Passar `'RS256'` como 4º argumento faz esse valor **vencer** o que
está escrito no header do token — ou seja, o servidor sempre verifica
como RS256, **não importa o que o atacante declare** no `alg`. Um
token forjado com `alg: HS256` é avaliado como se fosse RS256, a
assinatura HMAC forjada falha na verificação RSA, e o token é
rejeitado — **antes** de qualquer possibilidade de confusão de
algoritmo.

Implementamos essa correção como uma rota **paralela**
(`/upgrades-seguro/flag`), ao lado da vulnerável (`/upgrades/flag`),
para poder comparar o comportamento das duas contra o **mesmo** token
forjado (evidência na Seção 9.3).

---

## 3. Teoria necessária

- **Estrutura de um JWT:** `header.payload.assinatura`, cada parte
  em Base64url.
- **RSA (nível conceitual):** chave pública `(N, e)`, chave privada
  `d`; assinar é `mensagem^d mod N`, verificar é `assinatura^e mod N`.
- **PKCS#1 v1.5:** formatação aplicada à mensagem antes de assinar
  com RSA — inclui um identificador fixo do algoritmo de hash
  (SHA-256) e um preenchimento de bytes `0xFF`.
- **MDC/GCD aplicado a criptoanálise:** mesmo "espírito" do CRT
  usado no desafio Share (E1) — usar múltiplas equações relacionadas
  para extrair um segredo, mas aqui via máximo divisor comum em vez
  de reconstrução por congruências.

---

## 4. Ambiente, dependências e versões

### A aplicação-alvo (Node.js)

Reimplementada fielmente a partir do código-fonte confirmado em
write-ups públicos, com **artefatos próprios do grupo** (chave RSA e
flag geradas localmente, nunca reaproveitando as do desafio
original):

- `jpv@2.0.1` — versão vulnerável confirmada (bypass testado contra
  2.2.2, 2.1.2, 2.1.0 — todas já corrigidas — e 2.0.1, 2.0.0, 1.5.1,
  onde o bypass funciona).
- `jwt-simple@0.5.1` — versão citada no write-up de referência
  (ret2school), com a falha de não verificar o algoritmo declarado.
- `express` — servidor HTTP.

### O ataque (Python)

- **Python 3.8+** — só uma dependência externa: **`gmpy2`**.
  Motivo: calcular `assinatura^65537` sem módulo gera um número de
  **milhões de bits**; a aritmética nativa do Python trava nessa
  escala (testamos: excedeu 300s sem `gmpy2`). O próprio write-up
  original (Kalmarunionen) recomenda a mesma solução, pelo mesmo
  motivo.
- Todo o resto — PKCS#1 v1.5, codificação DER/PEM, base64url — foi
  implementado **do zero**, sem `pycryptodome`, `cryptography` ou
  `PyJWT`.

---

## 5. Estrutura do repositório

```
cr0wnair-writeup/
├── app/                        # aplicacao-alvo (vulneravel, reimplementada)
│   ├── package.json            # fixa jpv@2.0.1 e jwt-simple@0.5.1
│   ├── config.js               # le os artefatos gerados (nunca commita segredos)
│   ├── app.js                  # servidor Express (monta as 3 rotas abaixo)
│   └── routes/
│       ├── checkin.js          # emissao do JWT -- ponto de entrada do bypass jpv
│       ├── upgrades.js         # verificacao VULNERAVEL -- confusao RS256/HS256
│       └── upgrades_seguro.js  # verificacao CORRIGIDA -- politica de algoritmos (Secao 2.4)
├── scripts/
│   └── gerar_ambiente.js       # gera chave RSA + flag PROPRIAS do grupo, na hora
├── exploit/                    # o ataque, em Python puro + gmpy2
│   ├── rsa_jwt_lib.py          # PKCS#1, DER/PEM, GCD, forja de JWT (reutilizavel)
│   ├── demo_cr0wnair_attack.py # simulacao completa, sem precisar do servidor
│   ├── ataque_real.py          # ataque via HTTP contra o servidor Node.js real (testa os 2 endpoints)
│   ├── politica_algoritmos.py  # demonstra a mitigacao em Python puro (sem precisar do servidor)
│   └── requirements.txt        # gmpy2
├── docs/
│   └── plano-estudo-cr0wnair.md
└── .gitignore                  # ignora node_modules/, app/keys/, venv/
```

---

## 6. Origem dos artefatos e adaptações do grupo

- **Código-fonte da aplicação:** reconstruído a partir do que está
  publicamente documentado nos write-ups (ret2school, Kalmarunionen,
  STT/sectt) do Union CTF 2021 — o `source.zip` original não foi
  reaproveitado diretamente; o código foi digitado/adaptado a partir
  do que os write-ups reproduzem.
- **Chave RSA e flag:** geradas do zero pelo grupo
  (`scripts/gerar_ambiente.js`), nunca reaproveitando os artefatos
  do desafio original — conforme exigido pelo professor.
- **Técnica de ataque:** a lógica central (bypass `jpv` + GCD +
  confusão RS256/HS256) é **conhecida e catalogada** como
  **CVE-2017-11424**, com uma ferramenta pública completa
  (`rsa_sign2n`, da Silent Signal) já implementando exatamente esse
  ataque. **Não usamos essa ferramenta como dependência** — toda a
  matemática foi reimplementada do zero em Python puro (ver Seção 8).

---

## 7. Como rodar (instruções de ponta a ponta)

Requer dois terminais abertos simultaneamente: um para o servidor,
outro para o ataque.

### Linux / macOS

**Terminal 1 — subir a aplicação-alvo:**

```bash
cd app
npm install
node ../scripts/gerar_ambiente.js
node app.js
```

Deve aparecer: `cr0wnair (reimplementacao) rodando na porta 3000`.

**Terminal 2 — rodar o ataque:**

```bash
cd exploit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# opcional: simulação local, sem precisar do servidor
python3 demo_cr0wnair_attack.py

# ataque real, contra o servidor do Terminal 1
python3 ataque_real.py
```

### Windows (PowerShell)

**Terminal 1 — subir a aplicação-alvo:**

```powershell
cd app
npm install
node ../scripts/gerar_ambiente.js
node app.js
```

**Terminal 2 — rodar o ataque:**

```powershell
cd exploit
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

python demo_cr0wnair_attack.py
python ataque_real.py
```

> Se `gmpy2` falhar ao instalar no Windows, use:
> `pip install gmpy2 --only-binary :all:`

---

## 8. Explicação das etapas do código

### `rsa_jwt_lib.py` (módulo compartilhado)

- **`pkcs1_v1_5_encode`** — monta o bloco de padding exigido antes
  de assinar/verificar com RSA: `0x00 0x01 [FF...FF] 0x00
  [identificador SHA-256] [hash]`.
- **Codificador DER (`der_integer`, `der_sequence`, `der_bitstring`,
  `der_oid_rsa_encryption`)** — monta a estrutura ASN.1 de uma
  chave pública RSA (`SubjectPublicKeyInfo`) byte a byte, sem
  depender de OpenSSL.
- **`recupera_modulo_n`** — para cada token, calcula `magic =
  assinatura^e - mensagem_com_padding` (usando `gmpy2` pela escala
  do número) e tira o **GCD cumulativo** de todos — isola `N`.
- **`limpa_fatores_pequenos`** — salvaguarda: remove fatores
  pequenos residuais comparando o tamanho em bits contra o esperado.
- **`forja_token_hs256`** — monta um JWT novo, assinando
  `header.payload` com **HMAC-SHA256 usando o PEM como segredo**.

### `demo_cr0wnair_attack.py` (simulação local)

Reimplementa a classe do servidor (`ServidorCr0wnair`) inteiramente
em Python, incluindo o mesmo bug de `decode()` — permite testar e
demonstrar o ataque sem precisar do Node.js rodando.

### `ataque_real.py` (ataque via HTTP)

- **`checkin_com_bypass`** — envia o payload de bypass do `jpv`
  (Seção 2.1) via HTTP real, repetido com `ffp` diferentes.
- Descobre o tamanho de `N` a partir do **tamanho da assinatura**
  recebida (não precisa ser informado manualmente).
- Reaproveita `rsa_jwt_lib` para recuperar `N`, montar o PEM, forjar
  o token, e testa o **mesmo** token forjado contra dois endpoints:
  `/upgrades/flag` (vulnerável) e `/upgrades-seguro/flag`
  (corrigido) — evidência lado a lado na Seção 9.3.

### `routes/upgrades_seguro.js` (mitigação, Seção 2.4)

Idêntica a `upgrades.js`, com uma única linha alterada: o algoritmo
é passado explicitamente para `jwt.decode()`, em vez de deixar o
token declarar. Montada em paralelo no `app.js`
(`/upgrades-seguro`), sem alterar a rota vulnerável original — as
duas convivem no mesmo servidor para permitir a comparação direta.

### `politica_algoritmos.py` (mitigação, versão simulada)

Mesmo princípio de `upgrades_seguro.js`, mas em Python puro: define
`decode_seguro()` com uma allowlist de algoritmos, e testa o mesmo
par de tokens (legítimo e forjado) contra a versão vulnerável e a
corrigida, sem precisar do servidor Node.js rodando.

---

## 9. Evidência de reprodução

### 9.1 — Simulação local (`demo_cr0wnair_attack.py`)

```
Chave gerada: N tem 511 bits, e=65537
Gerados 4 tokens RS256 (ffp diferentes).
Recuperando N via MDC (GCD cumulativo) das assinaturas...
N real:       4827094155224569492139564905616862436645903368972623249698554312646711061571671574817049684367201220125669778432084578612122671982171695100017754263214731
N recuperado: 4827094155224569492139564905616862436645903368972623249698554312646711061571671574817049684367201220125669778432084578612122671982171695100017754263214731
[OK] N recuperado corretamente, sem acesso direto a chave publica.

Token forjado (HS256): eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Resposta do servidor ao token forjado:
  union{demo_local_sem_node_js}
[SUCESSO] Ataque completo: RSA quebrado via GCD + confusao RS256/HS256.
tempo total: 6.95 s
```

**Reproduzido de forma independente pelo grupo (Windows, venv
próprio):** mesma sequência, `N` recuperado batendo exatamente,
`tempo total: 6.3 s`.

### 9.2 — Ataque real, contra o servidor Node.js (`ataque_real.py`)

Executado com o servidor de verdade rodando (`app.js`), gerando os
próprios artefatos (`gerar_ambiente.js`):

```
Atacando servidor real em: http://localhost:3000

  Token obtido (ffp=CA12345678): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
  Token obtido (ffp=CA12345677): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
  Token obtido (ffp=CA12345676): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
  Token obtido (ffp=CA12345675): eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...

Tamanho da assinatura (= tamanho de N): 128 bytes (1024 bits)

Recuperando N via MDC (GCD cumulativo)...
N recuperado: 141583624389789801102035775194692024395326479849020701040171439668642036548531628790706901424890449372077637437069829009314522676469776475764874603793113650881459651830575993959044151940167961997698017980033982161439736864684950460116254331020107859307891349299327567031231081722654476966861869506897483219559
Bits: 1024

Chave publica reconstruida:
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJnyyP13is+EPbrzTsNdr07mkD
8YNO2xFWd/e/kfFeODbEEUcdMk+eFhBRk8pVSobIvi57h6QxZ17jmb/1sEK0J0EG
qCx6PM7lXYGIbBBqRE9LSt6FkgWHVsMmRiEZqhak+2sqXUMzJ8Phr0Gp4O82oPXd
4gcYwnU+Rh39MVFCZwIDAQAB
-----END PUBLIC KEY-----

Token forjado (HS256): eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

Resposta do servidor real ao token forjado:
  grupo{flag_propria_de_demonstracao_cr0wnair}
```

**Confirmação independente:** o `N` recuperado foi conferido byte a
byte contra o `pubkey.pem` gerado localmente — bateu exatamente.

**Executado de forma independente pelo grupo, em Windows** (venv
próprio, aplicação Node.js rodando localmente): mesmo resultado —
os 4 tokens obtidos via bypass real, `N` de 1024 bits recuperado, e
a flag própria (`grupo{flag_propria_de_demonstracao_cr0wnair}`)
retornada corretamente pelo servidor real.

Essa dupla evidência — simulação local **e** ataque real contra a
aplicação Node.js verdadeira, reproduzida em dois sistemas
operacionais diferentes — confirma que a reprodução funciona de
ponta a ponta, não apenas em teoria.

### 9.3 — Mitigação: mesmo token forjado, contra o endpoint corrigido

Executando `ataque_real.py` (versão estendida) contra o servidor
real, com a rota `/upgrades-seguro/flag` (Seção 2.4) montada em
paralelo à vulnerável:

```
Resposta do endpoint VULNERAVEL (/upgrades/flag) ao token forjado:
  grupo{flag_propria_de_demonstracao_cr0wnair}

Resposta do endpoint CORRIGIDO (/upgrades-seguro/flag) ao MESMO token forjado:
  Token is not valid.
```

**Mesma chave, mesmo token forjado, mesma execução** — a única
diferença é a linha `jwt.decode(token, config.pubkey, false,
'RS256')` na rota corrigida. Isso comprova que a causa raiz da
vulnerabilidade é especificamente a ausência de uma política de
algoritmos permitidos, e que a correção proposta (Seção 2.4) resolve
exatamente esse problema, sem quebrar o fluxo legítimo (tokens
RS256 reais continuam sendo aceitos normalmente).

A mesma comparação foi confirmada também em Python puro, sem
depender do servidor (`exploit/politica_algoritmos.py`), com
resultado idêntico.

---

## 10. Contribuições próprias do grupo

- **Reimplementação completa em Python puro**, sem depender da
  ferramenta pública já existente para essa CVE (`rsa_sign2n`) —
  usada apenas como referência de conferência, nunca como
  dependência do código entregue.
- **Codificador DER/ASN.1 escrito do zero**, sem OpenSSL nem
  bibliotecas de criptografia — monta a chave pública em PEM
  manualmente.
- **Identificação e correção do problema do fator espúrio no GCD**
  (2 tokens trazendo um fator `93` extra) — solução com 4 tokens e
  GCD cumulativo, mais uma salvaguarda de limpeza de fatores
  pequenos residuais. Esse é um detalhe prático não coberto em
  profundidade nos write-ups públicos consultados.
- **Identificação da versão exata vulnerável do `jpv`** (`2.0.1`),
  testando sistematicamente contra 6 versões diferentes do pacote
  para confirmar em qual o bypass funciona e em qual foi corrigido.
- **Automação da geração de artefatos** (`gerar_ambiente.js`) —
  chave RSA e flag geradas localmente a cada execução, nunca
  commitadas, reforçando de forma automática a exigência de usar
  artefatos próprios.
- **Ataque real via HTTP** (`ataque_real.py`), além da simulação —
  descobre o tamanho de `N` dinamicamente a partir do tamanho da
  assinatura recebida, sem valores fixos hardcoded.
- **Reprodução testada em dois sistemas operacionais** (Linux e
  Windows), por dois membros diferentes do grupo, de forma
  independente.
- **Mitigação implementada e testada lado a lado com a
  vulnerabilidade** (Seção 2.4 e 9.3) — não apenas descrita em
  texto: uma rota corrigida real (`upgrades_seguro.js`) rodando no
  mesmo servidor, comprovando que o mesmo ataque que funciona contra
  a rota original falha contra a corrigida.

---

## 11. Nota sobre divergência nos materiais da disciplina

A coluna "Escopo" do desafio, na planilha da disciplina, menciona
"conservar `fast-json-stringify` e `jsonwebtoken` nas versões
vulneráveis". Nos três materiais públicos fornecidos (write-up do
sectt, `source.zip`, e o repositório de write-ups de
matheuspd) e em write-ups adicionais consultados de forma
independente, **não encontramos nenhuma referência a essas duas
bibliotecas** — todas as fontes, sem exceção, confirmam `jpv` e
`jwt-simple` como as bibliotecas reais do desafio original.
Interpretamos isso como uma possível inconsistência na planilha
(talvez texto de outro desafio) e seguimos com as bibliotecas
confirmadas pelas fontes públicas. Ficamos à disposição para ajustar
caso o professor confirme que `fast-json-stringify`/`jsonwebtoken`
eram de fato esperadas.

---

## 12. Referências

- Código-fonte e mecânica do desafio: write-up de **ret2school**,
  *"[UnionCTF 2021 - web] Cr0wnAir"* — inclui o código-fonte
  reproduzido de `routes/checkin.js` e `routes/upgrades.js`.
- Técnica de recuperação de `N` via GCD: write-up de
  **Kalmarunionen** (Nicolai Søborg), *"Union CTF 2021: Cr0wnAir"* —
  inclui a implementação de referência em Python com `gmpy2`.
- Write-up adicional consultado: **STT/sectt** (IST), *"cr0wnair –
  Union CTF 2021"*.
- Write-up adicional consultado: **qxxxb/ARESx**, *"Cr0wnAir"*
  (CTFtime) — confirma independentemente as versões `jpv@2.0.1` e
  `jwt-simple@0.5.2`.
- Vulnerabilidade catalogada: **CVE-2017-11424** (confusão de
  algoritmo RS256/HS256 em bibliotecas JWT).
- Ferramenta pública de referência (não usada como dependência):
  **`rsa_sign2n`**, Silent Signal — *"Abusing JWT Public Keys
  Without the Public Key"*.
- Biblioteca vulnerável: **`jpv`** (versões testadas: 1.5.1 a 3.1.2;
  bypass confirmado até a 2.0.1, corrigido a partir da 2.1.0).
- Biblioteca vulnerável: **`jwt-simple`** versão 0.5.1.
