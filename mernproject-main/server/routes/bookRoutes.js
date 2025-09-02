const express = require('express');
const router = express.Router();
const Book = require('../models/Book');
const authenticateJWT = require('../middleware/auth');

// Get all books (public access)
router.get('/', async (req, res) => {
  try {
    console.log('Getting all books with ratings');

    // Accept optional sort param: popularity, rating, peopleschoice
    const sort = req.query.sort || '';
    let sortStage = {};
    if (sort === 'popularity' || sort === 'peopleschoice') {
      sortStage = { reviewCount: -1 };
    } else if (sort === 'rating') {
      sortStage = { avgRating: -1 };
    }

    // Aggregate books with review statistics
    const books = await Book.aggregate([
      {
        $lookup: {
          from: 'reviews',
          localField: '_id',
          foreignField: 'book',
          as: 'reviews'
        }
      },
      {
        $addFields: {
          reviewCount: { $size: '$reviews' },
          avgRating: { $cond: [ { $gt: [ { $size: '$reviews' }, 0 ] }, { $avg: '$reviews.rating' }, null ] }
        }
      },
      {
        $project: {
          reviews: 0 // don't send full reviews in list
        }
      },
      ...(Object.keys(sortStage).length ? [{ $sort: sortStage }] : [])
    ]).exec();

    res.status(200).json(books);
  } catch (error) {
    console.error('Error getting books:', error);
    res.status(500).json({ message: 'Error fetching books', error: error.message });
  }
});

// Get a specific book by ID (public access)
router.get('/:id', async (req, res) => {
  try {
    console.log(`Getting book with ID: ${req.params.id}`);
  const book = await Book.findById(req.params.id);
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.status(200).json(book);
  } catch (error) {
    console.error('Error getting book by ID:', error);
    res.status(500).json({ message: 'Error fetching book details', error: error.message });
  }
});

// Create a new book (admin only)
router.post('/', authenticateJWT, async (req, res) => {
  try {
    // Check if admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to add books' });
    }
    
  const { title, author, imageUrl, genre, availableCount } = req.body;
    
    // Validate required fields
    if (!title || !author || !imageUrl || !genre) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    const newBook = new Book({
      title,
      author,
      imageUrl,
      genre,
      isAvailable: true,
  availableCount: typeof availableCount === 'number' ? availableCount : 10,
  countavailable: typeof availableCount === 'number' ? availableCount : 10
    });
    
    await newBook.save();
    res.status(201).json(newBook);
  } catch (error) {
    console.error('Error creating book:', error);
    res.status(500).json({ message: 'Error creating book', error: error.message });
  }
});

// Update a book (admin only)
router.put('/:id', authenticateJWT, async (req, res) => {
  try {
    // Check if admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update books' });
    }
    
  const { title, author, imageUrl, genre, availableCount } = req.body;
    
    // Validate required fields
    if (!title || !author || !imageUrl || !genre) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    const book = await Book.findById(req.params.id);
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    
  // Update fields
  book.title = title;
  book.author = author;
  book.imageUrl = imageUrl;
  book.genre = genre;
  if (typeof availableCount === 'number') book.availableCount = availableCount;
  if (typeof availableCount === 'number') book.countavailable = availableCount;
    
    await book.save();
    res.status(200).json(book);
  } catch (error) {
    console.error('Error updating book:', error);
    res.status(500).json({ message: 'Error updating book', error: error.message });
  }
});

// Delete a book (admin only)
router.delete('/:id', authenticateJWT, async (req, res) => {
  try {
    // Check if admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to delete books' });
    }
    
    const book = await Book.findById(req.params.id);
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }
    
    await Book.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Book deleted successfully' });
  } catch (error) {
    console.error('Error deleting book:', error);
    res.status(500).json({ message: 'Error deleting book', error: error.message });
  }
});

// Export routes
module.exports = router;
