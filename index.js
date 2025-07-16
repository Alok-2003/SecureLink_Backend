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
    'https://www.neeev.ai',
    'https://course-softflowai.vercel.app',
    'https://neeevai.vercel.app'
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
    const { amount, currency } = req.body;
    const options = {
      amount: amount * 100, // Convert to paise
      currency: currency,
      receipt: 'order_rcptid_11',
      notes: {
        course: 'Master Gen-AI Development',
      },
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

// Start server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
