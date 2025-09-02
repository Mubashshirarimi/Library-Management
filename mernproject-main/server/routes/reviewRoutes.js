const express = require('express');
const router = express.Router();
const Review = require('../models/Review');
const Book = require('../models/Book');
const User = require('../models/User');
const authenticateJWT = require('../middleware/auth');

// Get reviews for a book
router.get('/book/:bookId', async (req, res) => {
  try {
    const reviews = await Review.find({ book: req.params.bookId }).populate('user', 'name');
    res.status(200).json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ message: 'Error fetching reviews', error: error.message });
  }
});

// Post a review for a book (authenticated users only)
router.post('/book/:bookId', authenticateJWT, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const bookId = req.params.bookId;

    // Basic validation
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    const book = await Book.findById(bookId);
    if (!book) return res.status(404).json({ message: 'Book not found' });

    // Try to fetch user's name for reviewer display
    let reviewerName;
    try {
      const userDoc = await User.findById(req.user.userId).select('name');
      reviewerName = userDoc?.name;
    } catch (e) {
      console.warn('Unable to fetch user name for review:', e.message || e);
    }

    const newReview = new Review({ book: bookId, user: req.user.userId, rating, comment, reviewerName });
    await newReview.save();

    // return populated review
    const populated = await Review.findById(newReview._id).populate('user', 'name');
    res.status(201).json(populated);
  } catch (error) {
    console.error('Error creating review:', error);
    res.status(500).json({ message: 'Error creating review', error: error.message });
  }
});

module.exports = router;
