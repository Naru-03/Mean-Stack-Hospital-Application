const express = require('express');
//const bcrypt = require('bcrypt');
var bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const patientRoutes = require('./routes/patientRoutes');
const doctorRoutes = require('./routes/doctorRoutes');
const appointmentRoutes = require('./routes/appointmentRoutes');
const prescriptionRoutes = require('./routes/prescriptionRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const authRoutes = require('./routes/authRoutes');

const app = express();

// Enable CORS
app.use(cors());


// Middleware for parsing JSON request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Routes
app.use('/patients', patientRoutes);
app.use('/doctors', doctorRoutes);
app.use('/appointments', appointmentRoutes);
app.use('/prescriptions', prescriptionRoutes);
app.use('/payments', paymentRoutes);
app.use('/authRoutes', authRoutes);


// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
