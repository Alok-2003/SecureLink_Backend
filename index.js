import dotenv from 'dotenv';
import cors from 'cors';
import express from 'express';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import nodemailer from 'nodemailer';

dotenv.config();
const app = express();

// Enable CORS for your frontend origin only
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'https://secure-link-canara.vercel.app',
    'https://secure-link-canara.vercel.app/shopping',
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
};
app.use(cors(corsOptions));
app.use(bodyParser.json());

// Razorpay credentials using environment variables
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,  // Correct environment variable name
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});


// Route to create an order
app.post('/create-order', async (req, res) => {
  try {
    const { amount, currency, notes } = req.body;
    const options = {
      amount: amount * 100, // Convert to paise
      currency: currency,
      receipt: 'order_rcptid_11',
      notes: notes || { null: 'null' },
    };

    const order = await razorpay.orders.create(options);
    console.log(order)

    res.json({
      id: order.id,
      currency: order.currency,
      amount: order.amount,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error creating Razorpay order');
  }
});

// Route to verify payment
app.post('/verify-payment', (req, res) => {
  const { payment_id, order_id, signature } = req.body;

  const generated_signature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(order_id + '|' + payment_id)
    .digest('hex');

  if (generated_signature === signature) {
    res.send('Payment verification successful');
  } else {
    res.status(400).send('Payment verification failed');
  }
});

app.get('/', (req, res) => {
  res.send('Welcome to the Razorpay Payment Gateway API');
});

// Route to encode data
app.post('/encode-data', (req, res) => {
  try {
    const data = req.body;
    if (!data) {
      return res.status(400).json({ error: 'No data provided in request body' });
    }
    
    // Check if platform is provided and is valid
    const validPlatforms = ['Razorpay', 'Stripe', 'Paytm', 'Phonepay'];
    const platform = data.platform ; // Default to Razorpay if not specified
    
    if (!validPlatforms.includes(platform)) {
      return res.status(400).json({ 
        error: 'Invalid platform. Must be one of: Razorpay, Stripe, Paytm, Phonepay' 
      });
    }
    
    console.log(`Encoding data for platform: ${platform}`);
    
    // Convert data to string if it's an object
    const dataString = typeof data === 'object' ? JSON.stringify(data) : String(data);
    
    // Create a buffer from the string and encode to base64
    const base64Encoded = Buffer.from(dataString).toString('base64');
    
    // Choose encryption method based on platform
    let algorithm, secretKey, iv, encrypted;
    
    // Get or create encryption key based on platform
    const getSecretKey = (platformName) => {
      const envKeyName = `ENCRYPTION_KEY_${platformName.toUpperCase()}`;
      const defaultKey = `defaultKey-${platformName.toLowerCase()}`;
      const envKey = process.env[envKeyName];
      
      if (envKey) {
        return crypto.createHash('sha256').update(String(envKey)).digest('base64').substr(0, 32);
      } else {
        return crypto.createHash('sha256').update(defaultKey).digest('base64').substr(0, 32);
      }
    };
    
    switch(platform) {
      case 'Razorpay':
        // Use AES-256-CTR for Razorpay
        algorithm = 'aes-256-ctr';
        secretKey = getSecretKey('Razorpay');
        iv = crypto.randomBytes(16);
        break;
        
      case 'Stripe':
        // Use AES-256-GCM for Stripe
        algorithm = 'aes-256-gcm';
        secretKey = getSecretKey('Stripe');
        iv = crypto.randomBytes(12); // GCM prefers 12 bytes
        break;
        
      case 'Paytm':
        // Use AES-256-CBC for Paytm
        algorithm = 'aes-256-cbc';
        secretKey = getSecretKey('Paytm');
        iv = crypto.randomBytes(16);
        break;
        
      case 'Phonepay':
        // Use Camellia-256-CBC for Phonepay (for diversity)
        algorithm = 'camellia-256-cbc';
        secretKey = getSecretKey('Phonepay');
        iv = crypto.randomBytes(16);
        break;
    }
    
    // Create cipher and encrypt data
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    encrypted = cipher.update(dataString, 'utf8', 'hex');
    
    // For GCM mode, we need to get the auth tag
    let authTag = '';
    if (algorithm === 'aes-256-gcm') {
      encrypted += cipher.final('hex');
      authTag = cipher.getAuthTag().toString('hex');
    } else {
      encrypted += cipher.final('hex');
    }
    
    // Return encodings with platform information
    res.json({
      platform,
      base64Encoded,
      encrypted: {
        algorithm,
        iv: iv.toString('hex'),
        content: encrypted,
        ...(authTag && { authTag })
      },
      originalDataType: typeof data
    });
  } catch (error) {
    console.error('Error encoding data:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to encode data' });
  }
});

// Route to decode data
app.post('/decode-data', (req, res) => {
  try {
    // Support both direct output from encode-data endpoint and the original parameter names
    const {
      // Original parameter names
      encodedData, 
      encryptedData, 
      dataType,
      platform: inputPlatform,
      
      // Names from encode-data endpoint response
      base64Encoded, 
      encrypted, 
      originalDataType,
      platform
    } = req.body;
    
    // Use the parameters with priority to encode-data response format
    const actualEncodedData = base64Encoded || encodedData;
    const actualEncryptedData = encrypted || encryptedData;
    const actualDataType = originalDataType || dataType;
    const actualPlatform = platform || inputPlatform ; // Default to Razorpay if not specified
    
    // Validate platform
    const validPlatforms = ['Razorpay', 'Stripe', 'Paytm', 'Phonepay'];
    if (!validPlatforms.includes(actualPlatform)) {
      return res.status(400).json({ 
        error: 'Invalid platform. Must be one of: Razorpay, Stripe, Paytm, Phonepay' 
      });
    }
    
    // Check if we have any data to decode
    if (!actualEncodedData && !actualEncryptedData) {
      return res.status(400).json({ 
        error: 'No data provided. Please provide encoded data in either format.' 
      });
    }
    
    console.log(`Decoding data for platform: ${actualPlatform}`);
    const results = {};
    
    // Decode base64 data if provided
    if (actualEncodedData) {
      const decodedBuffer = Buffer.from(actualEncodedData, 'base64');
      const decodedString = decodedBuffer.toString('utf8');
      
      // Try to parse as JSON if original was an object/array
      try {
        if (actualDataType === 'object') {
          results.decodedData = JSON.parse(decodedString);
        } else {
          results.decodedData = decodedString;
        }
      } catch (e) {
        // If parsing fails, return as string
        results.decodedData = decodedString;
      }
    }
    
    // Decrypt encrypted data if provided
    if (actualEncryptedData && actualEncryptedData.iv && actualEncryptedData.content) {
      // Get the algorithm from the encrypted data or determine based on platform
      const algorithm = actualEncryptedData.algorithm || (() => {
        switch(actualPlatform) {
          case 'Razorpay': return 'aes-256-ctr';
          case 'Stripe': return 'aes-256-gcm';
          case 'Paytm': return 'aes-256-cbc';
          case 'Phonepay': return 'camellia-256-cbc';
          default: return 'aes-256-ctr';
        }
      })();
      
      // Get or create encryption key based on platform
      const getSecretKey = (platformName) => {
        const envKeyName = `ENCRYPTION_KEY_${platformName.toUpperCase()}`;
        const defaultKey = `defaultKey-${platformName.toLowerCase()}`;
        const envKey = process.env[envKeyName];
        
        if (envKey) {
          return crypto.createHash('sha256').update(String(envKey)).digest('base64').substr(0, 32);
        } else {
          return crypto.createHash('sha256').update(defaultKey).digest('base64').substr(0, 32);
        }
      };
      
      // Get the secret key based on the platform
      const secretKey = getSecretKey(actualPlatform);
      
      // Convert hex IV back to Buffer
      const iv = Buffer.from(actualEncryptedData.iv, 'hex');
      
      // Create decipher
      const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
      
      // For GCM mode, we need to set the auth tag if provided
      if (algorithm === 'aes-256-gcm' && actualEncryptedData.authTag) {
        const authTag = Buffer.from(actualEncryptedData.authTag, 'hex');
        decipher.setAuthTag(authTag);
      }
      
      // Decrypt the data
      let decrypted;
      try {
        decrypted = decipher.update(actualEncryptedData.content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        // Try to parse as JSON if original was an object/array
        if (actualDataType === 'object') {
          results.decryptedData = JSON.parse(decrypted);
        } else {
          results.decryptedData = decrypted;
        }
      } catch (e) {
        console.error(`Decryption failed for platform ${actualPlatform}:`, e.message);
        // If decryption fails, we might still have base64 decoded data
        if (!results.decodedData) {
          return res.status(400).json({ 
            error: `Failed to decrypt data for platform: ${actualPlatform}. ${e.message}` 
          });
        }
      }
    }
    
    // If both decodedData and decryptedData exist, prioritize decodedData
    if (results.decodedData) {
      res.json({
        data: results.decodedData
      });
    } else if (results.decryptedData) {
      res.json({
        data: results.decryptedData
      });
    } else {
      res.status(400).json({ error: 'Could not decode or decrypt the provided data' });
    }
  } catch (error) {
    console.error('Error decoding data:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to decode data' });
  }
});

// Start server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
