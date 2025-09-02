const express = require('express');
const mongoose = require('mongoose');
const BorrowDefault = require('../models/Borrow');
const Book = require('../models/Book');
const User = require('../models/User');
const authenticateJWT = require('../middleware/auth');
const router = express.Router();

// Optional: use a separate MongoDB for borrow records when BORROW_MONGO_URI is set.
// This creates a dedicated connection and Borrow model bound to that connection.
let Borrow = BorrowDefault;
let borrowConnection = null;
if (process.env.BORROW_MONGO_URI) {
  try {
    borrowConnection = mongoose.createConnection(process.env.BORROW_MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Define schema similar to models/Borrow.js (avoid circular require)
    const borrowSchema = new mongoose.Schema({
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      bookId: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
      borrowedDate: { type: Date, default: Date.now },
      dueDate: { type: Date, required: true },
      returnDate: { type: Date, default: null },
      fine: { type: Number, default: 0 },
    }, { timestamps: true });

    Borrow = borrowConnection.model('Borrow', borrowSchema);
    console.log('Using separate borrow DB connection');
  } catch (err) {
    console.error('Failed to connect to BORROW_MONGO_URI, falling back to default Borrow model', err);
    Borrow = BorrowDefault;
    borrowConnection = null;
  }
}

// Helper function to calculate due date (1 week from current date)
function calculateDueDate() {
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + 7); // 7 days from now
  return dueDate;
}

// Helper function to calculate late fees
function calculateFine(dueDate, returnDate) {
  if (!returnDate) returnDate = new Date();
  
  // No fine if returned before due date
  if (returnDate <= dueDate) return 0;
  
  // Calculate days late
  const daysLate = Math.ceil((returnDate - dueDate) / (1000 * 60 * 60 * 24));
  
  // $1 per day late
  return daysLate * 1;
}

// GET all borrows (admin only)
router.get('/', authenticateJWT, async (req, res) => {
  try {
    // Check if admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized. Admin access required.' });
    }
    
    const borrows = await Borrow.find()
      .populate('userId', 'name email')
      .populate('bookId', 'title author imageUrl');
      
    res.json(borrows);
  } catch (err) {
    console.error('Error fetching borrows:', err);
    res.status(500).json({ message: 'Error fetching borrow records' });
  }
});

// GET user's borrows
router.get('/user', authenticateJWT, async (req, res) => {
  try {
    console.log('Getting borrows for user:', req.user);
    if (!req.user || !req.user.userId) {
      return res.status(401).json({ message: 'User ID not found in token' });
    }

    const borrows = await Borrow.find({ userId: req.user.userId })
      .populate('bookId', 'title author imageUrl');
    
    console.log(`Found ${borrows.length} borrows for user ${req.user.userId}`);
      
    // Calculate current late fees for books not yet returned
    const borrowsWithUpdatedFees = borrows.map(borrow => {
      const borrowObj = borrow.toObject();
      
      // If not returned yet, calculate current fee
      if (!borrowObj.returnDate) {
        borrowObj.currentFine = calculateFine(borrowObj.dueDate, new Date());
      }
      
      return borrowObj;
    });
    
    res.json(borrowsWithUpdatedFees);
  } catch (err) {
    console.error('Error fetching user borrows:', err);
    res.status(500).json({ message: 'Error fetching your borrowed books' });
  }
});

// POST /borrow - Borrow a book
router.post('/borrow', authenticateJWT, async (req, res) => {
  console.log('Borrow request received:', req.body);
  console.log('User from token:', req.user);
  
  // Validate user info from token
  if (!req.user || !req.user.userId) {
    console.error('Missing user ID in token payload');
    return res.status(401).json({ message: 'Authentication error: User ID missing from token' });
  }
  
  const { bookId } = req.body;
  if (!bookId) {
    return res.status(400).json({ message: 'Book ID is required' });
  }
  
  const dueDate = calculateDueDate();
  console.log('Due date calculated:', dueDate);
  console.log('User ID from token:', req.user.userId);

  // Use a session/transaction to ensure database consistency
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Check if the user exists
    const userExists = await User.findById(req.user.userId).session(session);
    if (!userExists) {
      console.error(`User with ID ${req.user.userId} not found in database`);
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found in database' });
    }
    
    console.log('Looking for book with ID:', bookId);
    const book = await Book.findById(bookId).session(session);
    console.log('Book found:', book ? 'Yes' : 'No');
    
    if (!book) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Book not found' });
    }
    
    // Check if the book has available copies
  // normalize using either field
  const available = (book.availableCount ?? book.countavailable ?? 0);
  if (available <= 0) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'No copies of this book are currently available' });
    }
    
    // Check if user already has this book
    const existingBorrow = await Borrow.findOne({ 
      userId: req.user.userId,
      bookId: bookId,
      returnDate: null // Not yet returned
    }).session(session);
    
    if (existingBorrow) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'You have already borrowed this book' });
    }

    // Create new borrow record
    const borrow = new Borrow({
      userId: req.user.userId,
      bookId,
      dueDate,
    });
    
    // Decrement available count and update availability state
    // decrement both fields
    book.availableCount = Math.max(0, (book.availableCount || book.countavailable || 0) - 1);
    book.countavailable = book.availableCount;
    book.isAvailable = book.availableCount > 0;
    if (!book.isAvailable) {
      book.currentBorrowerId = req.user.userId;
    }
    book.borrowHistory.push(borrow._id);

    console.log('Saving borrow record...');
    await borrow.save({ session });
    console.log('Saving book update...');
    await book.save({ session });
    
    // Update user's borrowed books
    console.log('Updating user record...');
    await User.findByIdAndUpdate(
      req.user.userId, 
      { $push: { borrowedBooks: bookId } },
      { session }
    );
    
    await session.commitTransaction();
    session.endSession();
    
    console.log('Book borrowed successfully');
    res.status(201).json({ 
      message: 'Book borrowed successfully', 
      dueDate: dueDate,
      borrow: await borrow.populate('bookId', 'title author')
    });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error borrowing book:', err);
    // Provide more detail in development for debugging
    if (process.env.NODE_ENV === 'development') {
      return res.status(500).json({ message: 'Error borrowing book', error: err.message, stack: err.stack });
    }
    res.status(500).json({ message: 'Error borrowing book' });
  }
});

// POST /return - Return a borrowed book
router.post('/return', authenticateJWT, async (req, res) => {
  const { borrowId } = req.body;
  if (!borrowId) return res.status(400).json({ message: 'borrowId is required' });

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const borrow = await Borrow.findById(borrowId).session(session);
    if (!borrow) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Borrow record not found' });
    }

    if (borrow.returnDate) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Book already returned' });
    }

    // Mark return
    borrow.returnDate = new Date();
    // calculate fine
    const fineAmount = calculateFine(borrow.dueDate, borrow.returnDate);
    borrow.fine = fineAmount;
    await borrow.save({ session });

    // Update book availability
    const book = await Book.findById(borrow.bookId).session(session);
    if (book) {
  // Increase available count and mark available, keep both fields in sync
  const newCount = (book.availableCount || book.countavailable || 0) + 1;
  book.availableCount = newCount;
  book.countavailable = newCount;
  book.isAvailable = true;
  book.currentBorrowerId = null;
  await book.save({ session });
    }

    // Remove from user's borrowedBooks array
    await User.findByIdAndUpdate(borrow.userId, { $pull: { borrowedBooks: borrow.bookId } }, { session });

    await session.commitTransaction();
    session.endSession();

    res.json({ message: 'Book returned successfully', fine: fineAmount });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error returning book:', err);
    res.status(500).json({ message: 'Error returning book' });
  }
});

// GET /fees - Summarize fines for user
router.get('/fees', authenticateJWT, async (req, res) => {
  try {
    if (!req.user || !req.user.userId) return res.status(401).json({ message: 'User not authenticated' });

    const borrows = await Borrow.find({ userId: req.user.userId });

    let totalPaidFines = 0;
    let currentLateFees = 0;
    let totalFines = 0;

    borrows.forEach(b => {
      if (b.returnDate && b.fine) totalPaidFines += b.fine;
      if (!b.returnDate) {
        const currentFine = calculateFine(b.dueDate, new Date());
        currentLateFees += currentFine;
      }
      if (b.fine) totalFines += b.fine;
    });

    totalFines += currentLateFees;

    res.json({ totalPaidFines, currentLateFees, totalFines });
  } catch (err) {
    console.error('Error calculating fees:', err);
    res.status(500).json({ message: 'Error calculating fees' });
  }
});

// GET /stats - Admin-only summary and top books
router.get('/stats', authenticateJWT, async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const totalBorrows = await Borrow.countDocuments();
    const activeBorrows = await Borrow.countDocuments({ returnDate: null });

    // Sum fines (returned) + current late fees for active borrows
    const allBorrows = await Borrow.find();
    let totalFees = 0;
    for (const b of allBorrows) {
      if (b.fine) totalFees += b.fine;
      if (!b.returnDate) totalFees += calculateFine(b.dueDate, new Date());
    }

    // Top borrowed books (by borrow count)
    const agg = await Borrow.aggregate([
      { $group: { _id: '$bookId', borrowCount: { $sum: 1 } } },
      { $sort: { borrowCount: -1 } },
      { $limit: 5 }
    ]);

    const topBooks = [];
    for (const item of agg) {
      const book = await Book.findById(item._id).select('title author imageUrl');
      if (book) topBooks.push({ book, borrowCount: item.borrowCount });
    }

    res.json({ totalBorrows, activeBorrows, totalFees, topBooks });
  } catch (err) {
    console.error('Error generating stats:', err);
    res.status(500).json({ message: 'Error generating stats' });
  }
});

module.exports = router;

