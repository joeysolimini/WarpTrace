const fs = require('fs');
const path = require('path');
const express = require('express');

// Ensure the service runs from the frontend folder
process.chdir(__dirname);

const app = express();
const PORT = process.env.PORT || 5173;
const distDir = path.resolve(__dirname, 'dist');
const indexFile = path.join(distDir, 'index.html');

if (!fs.existsSync(indexFile)) {
  console.error('❌ dist/index.html not found. Did the build step run in /frontend?');
}

app.get('/health', (_req, res) => res.status(200).send('ok'));

app.use((req, _res, next) => {
  console.log('[frontend]', req.method, req.url);
  next();
});

// Serve built assets
app.use(express.static(distDir, {
  maxAge: '1h',
  setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=3600')
}));

// SPA fallback
app.get('*', (_req, res) => {
  res.sendFile(indexFile, (err) => {
    if (err) {
      console.error('sendFile error:', err);
      res.status(err.statusCode || 500).end();
    }
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🌐 Frontend listening on ${PORT}, serving ${distDir}`);
});
