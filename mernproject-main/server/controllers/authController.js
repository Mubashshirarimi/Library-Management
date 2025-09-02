const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.signup = async (req, res) => {
  const { email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = new User({ email, password, role });
    await user.save();

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ message: 'User created successfully', token });
  } catch (err) {
    res.status(500).json({ message: 'Error during sign-up' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt for email:', email);

  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    console.log('User found, comparing passwords');
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Password invalid for user:', email);
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    
    console.log('Password valid:', isMatch);
    console.log('Generating token with userId:', user._id);
    
    // Ensure we use consistent field naming - userId, not id or _id
    const token = jwt.sign(
      { 
        userId: user._id.toString(), 
        role: user.role || 'user',
        email: user.email
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }  // Extend token validity for testing
    );
    
    console.log('Token generated successfully');
    res.status(200).json({ 
      message: 'Login successful', 
      token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role
      } 
    });
  } catch (err) {
    res.status(500).json({ message: 'Error during login' });
  }
};
