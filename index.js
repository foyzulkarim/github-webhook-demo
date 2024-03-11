require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = 3000;
const webhookSecret = process.env.SECRET;

app.use(bodyParser.json());

function verifyWebhookSignature(req) {
  console.log(req.headers);
  const sigHeader = req.headers['x-hub-signature-256'];
  const payload = req.body;

  if (!sigHeader) {
    return false;
  }

  console.log('sigHeader', sigHeader);
  console.log('payload', payload);

  const signature = crypto
    .createHmac('sha256', webhookSecret)
    .update(JSON.stringify(req.body))
    .digest('hex');
  let trusted = Buffer.from(`sha256=${signature}`, 'ascii');
  let untrusted = Buffer.from(sigHeader, 'ascii');
  return crypto.timingSafeEqual(trusted, untrusted);
}

app.post('/github-webhook', (req, res) => {
  if (!verifyWebhookSignature(req)) {
    console.error('Signature mismatch');
    return res.status(401).send("Unauthorized");
  }

  // Signature verified - Process the payload
  console.log('Webhook payload received and verified:', req.body);

  // Example: Log the event type
  console.log('Event type:', req.body.event);

  res.sendStatus(200); // OK
});

// Catch-all request handler (for testing)
app.all('*', (req, res) => {
  console.log('Webhook payload and headers:', {
    payload: req.body,
    headers: req.headers,
  });

  if (!verifyWebhookSignature(req)) {
    console.error('Signature mismatch');
    return res.sendStatus(403); // Forbidden
  }
  res.send('Webhook payload received and verified');
});

app.listen(port, () => {
  console.log(`Webhook receiver listening on port ${port}`);
});
