const express = require('express');
const connectDB = require('./config/db');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');


// Load environment variables
dotenv.config();

// Initialize Express
const app = express();

// Connect Database
connectDB();

// Middleware
app.use(bodyParser.json());

// Define routes
app.use('/api/auth', require('./routes/auth'));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
