const mongoose = require('mongoose');
const Book = require('../models/Book');
require('dotenv').config();

mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log('MongoDB connected');
    
    const testBook = new Book({
      title: 'Test Book',
      author: 'Test Author',
      genre: 'Fiction',
      description: 'This is a test book',
      imageUrl: 'https://via.placeholder.com/150'
    });
    
    await testBook.save();
    console.log('Test book added successfully');
    mongoose.disconnect();
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });