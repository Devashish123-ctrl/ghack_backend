const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json()); // Parses incoming JSON requests

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/webtoons', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Webtoon Schema
const webtoonSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    characters: [String]
});

// Webtoon Model
const Webtoon = mongoose.model('Webtoon', webtoonSchema);

// User schema for authentication (Optional, if you want to implement user system)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Utility function for JWT token verification
const verifyToken = (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send('No token provided.');

    jwt.verify(token, 'secretkey', (err, decoded) => {
        if (err) return res.status(500).send('Failed to authenticate token.');
        req.userId = decoded.id;
        next();
    });
};

// Register user (for JWT-based authentication)
app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 8);
    const newUser = new User({ username: req.body.username, password: hashedPassword });
    
    try {
        const savedUser = await newUser.save();
        res.status(201).send({ message: 'User registered successfully!' });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Login user and get JWT token
app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) return res.status(404).send('User not found');

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) return res.status(401).send('Invalid password');

        const token = jwt.sign({ id: user._id }, 'secretkey', { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Get all webtoons
app.get('/webtoons', async (req, res) => {
    try {
        const webtoons = await Webtoon.find();
        res.status(200).json(webtoons);
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Add a new webtoon (Requires JWT auth)
app.post('/webtoons', verifyToken, async (req, res) => {
    const { title, description, characters } = req.body;
    const newWebtoon = new Webtoon({ title, description, characters });

    try {
        const savedWebtoon = await newWebtoon.save();
        res.status(201).json(savedWebtoon);
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Get a specific webtoon by ID
app.get('/webtoons/:id', async (req, res) => {
    try {
        const webtoon = await Webtoon.findById(req.params.id);
        if (!webtoon) return res.status(404).send('Webtoon not found');
        res.status(200).json(webtoon);
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Delete a webtoon by ID (Requires JWT auth)
app.delete('/webtoons/:id', verifyToken, async (req, res) => {
    try {
        const deletedWebtoon = await Webtoon.findByIdAndDelete(req.params.id);
        if (!deletedWebtoon) return res.status(404).send('Webtoon not found');
        res.status(200).send('Webtoon deleted');
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
