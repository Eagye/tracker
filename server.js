const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key';
const privateKey = 'your_private_key';
const publicKey = 'your_public_key';

// Middleware
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/asset-tracking');

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ['admin', 'manager', 'employee'], default: 'employee' },
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  tagId: String,
  serialNumber: String,
  procurementDate: Date,
  signature: String,
});

const Product = mongoose.model('Product', productSchema);

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, role });
  await user.save();
  res.status(201).send('User registered');
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).send('User not found');
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send('Invalid password');
  }
  const token = jwt.sign({ userId: user._id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware to protect routes
const authenticate = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).send('Access denied');
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).send('Invalid token');
  }
};

// Middleware to check roles
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send('Access denied');
    }
    next();
  };
};

// Logging middleware
const logAction = (action) => {
  return (req, res, next) => {
    console.log(`User: ${req.user.username}, Action: ${action}, Time: ${new Date().toISOString()}`);
    next();
  };
};

// Signing data
const signData = (data) => {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, 'hex');
};

// Verifying data
const verifyData = (data, signature) => {
  const verify = crypto.createVerify('SHA256');
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature, 'hex');
};

// Add a new product
app.post('/products', authenticate, authorize(['admin', 'manager']), logAction('Add Product'), async (req, res) => {
  const { tagId, serialNumber, procurementDate } = req.body;
  const product = new Product({ tagId, serialNumber, procurementDate });

  // Sign the product data
  const productData = JSON.stringify({ tagId, serialNumber, procurementDate });
  const signature = signData(productData);
  product.signature = signature;

  await product.save();
  res.status(201).send('Product added');
});

// Get all products
app.get('/products', authenticate, authorize(['admin', 'manager', 'employee']), async (req, res) => {
  const products = await Product.find();

  // Verify the product data
  products.forEach(product => {
    const productData = JSON.stringify({ tagId: product.tagId, serialNumber: product.serialNumber, procurementDate: product.procurementDate });
    const isValid = verifyData(productData, product.signature);
    if (!isValid) {
      console.log(`Data integrity issue with product: ${product.tagId}`);
    }
  });

  res.json(products);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});