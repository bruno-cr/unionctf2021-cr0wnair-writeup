const express = require('express');
const app = express();

app.use(express.json());
app.use('/', require('./routes/checkin'));
app.use('/upgrades', require('./routes/upgrades'));
app.use('/upgrades-seguro', require('./routes/upgrades_seguro'));

const PORT = 3000;
app.listen(PORT, () => console.log(`cr0wnair (reimplementacao) rodando na porta ${PORT}`));
