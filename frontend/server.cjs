const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5173;

// simple healthcheck for Railway
app.get('/health', (_req, res) => res.status(200).send('ok'));

app.use((req, _res, next) => {
  console.log('[frontend]', req.method, req.url);
  next();
});

// serve static files from dist
app.use(express.static(path.join(__dirname, 'dist')));

// fallback to index.html for SPA routes
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🌐 Frontend listening on ${PORT}`);
});
