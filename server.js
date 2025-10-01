// --- Imports ---
const express = require('express');
const multer = require('multer');
const path = require('path');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config(); // Loads environment variables from .env file

// --- App Configuration ---
const app = express();
const port = process.env.PORT || 1337;
// --- Database Configuration ---
const dbName = 'ganeshvuyala';
const client = new MongoClient(process.env.MONGO_URL);
let db;

// --- Middleware Setup ---
app.use(express.static('public')); // Serve static files from 'public' directory
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(cookieParser()); // Parse cookies
app.set("view engine", "ejs"); // Set EJS as the view engine
app.set("views", "views"); // Specify the views directory

// --- Multer Storage Configuration for File Uploads ---
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login.html'); // If no token, redirect to login
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.redirect('/login.html'); // If token is invalid, redirect to login
        }
        req.user = user; // Attach user info to the request object
        next(); // Proceed to the next middleware or route handler
    });
};

// --- Public Routes (No login required) ---

// User Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection('users').findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.redirect('/login.html?error=invalid');
    }

    // User is valid, create JWT
    const payload = { id: user._id, email: user.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Set token in a secure, httpOnly cookie and redirect
    res.cookie('token', token, { httpOnly: true }).redirect('/home');

  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).send("An error occurred during the login process.");
  }
});

// User Signup Route
app.post("/signup", async (req, res) => {
  try {
    const { name, mobile, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { name, mobile, email, password: hashedPassword };

    await db.collection('users').insertOne(newUser);
    console.log('Record inserted for:', email);
    // Log the user in immediately after signup
    const payload = { id: newUser._id, email: newUser.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true }).redirect('/home');

  } catch (err) {
    console.error("Error inserting user record:", err);
    res.status(500).send("Error inserting record.");
  }
});

// Logout Route
app.get("/logout", (req, res) => {
    res.clearCookie('token').redirect('/login.html');
});


// --- Protected Routes (Login required) ---

// Protected route for the home/dashboard page
app.get('/home', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Protected route for the explore page
app.get('/explore', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'explore.html'));
});

// Vehicle Registration Route
app.post("/registerVehicle", authenticateToken, upload.single("vehicleImage"), async (req, res) => {
  try {
    const vehicleData = {
      name: req.body.name,
      vehicleType: req.body.vehicleType,
      vehicleNumber: req.body.vehicleNumber,
      // ... other fields ...
      vehicleImage: req.file ? req.file.filename : null,
      ownerId: req.user.id // Link the vehicle to the logged-in user
    };
    await db.collection("vehicles").insertOne(vehicleData);
    console.log("Vehicle Registered by user:", req.user.email);
    res.redirect('/explore');
  } catch (err) {
    console.error("Error registering vehicle:", err);
    res.status(500).send("Registration Failed.");
  }
});

// Dynamic Vehicle Display Route
const vehicleTypeMap = {
    "excavators": "Excavator", "bulldozers": "Bulldozer", "mini-excavators": "Miniexcavator",
    "backhoe-loaders": "Backhoe Loader", "loaders": "Loader", "motor-graders": "Motor Grader",
    "piling-rigs": "Piling Rig", "augers": "Auger", "tractors": "Tractor"
};

app.get("/vehicles/:type", authenticateToken, async (req, res) => {
    const vehicleType = vehicleTypeMap[req.params.type];
    if (!vehicleType) {
        return res.status(404).send("Vehicle category not found.");
    }
    try {
        const vehicles = await db.collection('vehicles').find({ vehicleType }).toArray();
        res.render('excavator', { data: vehicles });
    } catch (err) {
        console.error(`Error fetching ${vehicleType}:`, err);
        res.status(500).send("Failed to retrieve data.");
    }
});


// --- Server Startup ---
async function startServer() {
  try {
    await client.connect();
    db = client.db(dbName);
    console.log("Successfully connected to MongoDB. 💾");
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port} 🚀`);
    });
  } catch (err) {
    console.error("Failed to connect to MongoDB", err);
    process.exit(1);
  }
}

startServer();