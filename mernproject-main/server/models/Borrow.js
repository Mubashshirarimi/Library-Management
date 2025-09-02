const mongoose = require('mongoose');

const borrowSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true, // Refers to the User model
  },
  bookId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Book',
    required: true, // Refers to the Book model
  },
  borrowedDate: {
    type: Date,
    default: Date.now, // Default to current date
  },
  dueDate: {
    type: Date,
    required: true, // The due date for returning the book
  },
  returnDate: {
    type: Date,
    default: null, // Default to null if not returned yet
  },
  fine: {
    type: Number,
    default: 0, // Fine starts at 0 and is updated if the book is late
  },
});

module.exports = mongoose.model('Borrow', borrowSchema);
