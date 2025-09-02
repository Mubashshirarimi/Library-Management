/**
 * Test script to create a user for authentication testing
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

async function createTestUser() {
  try {
    // Connect to MongoDB
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');

    // Define test user data
    const testUser = {
      name: 'Test User',
      email: 'test@example.com',
      password: 'password123',
      role: 'user'
    };

    // Check if user already exists
    console.log('Checking if user already exists...');
    const existingUser = await User.findOne({ email: testUser.email });
    
    if (existingUser) {
      console.log('User already exists, updating password...');
      existingUser.password = testUser.password;
      await existingUser.save();
      console.log('User password updated');
    } else {
      console.log('Creating new user...');
      const newUser = new User(testUser);
      await newUser.save();
      console.log('User created successfully');
    }

    // Get all users for verification
    const users = await User.find({}, 'name email role');
    console.log('All users in database:');
    console.table(users.map(u => ({ name: u.name, email: u.email, role: u.role })));

  } catch (error) {
    console.error('Error:', error);
  } finally {
    // Close MongoDB connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  }
}

// Run the function
createTestUser();
