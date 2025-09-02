/**
 * seedBorrowData.js
 *
 * Creates a borrow record for a test user and an available book.
 * - If BORROW_MONGO_URI is set in server/.env, the borrow document will be stored
 *   in that database. Otherwise it will be stored in the main MONGO_URI database.
 *
 * Usage:
 *   node scripts/seedBorrowData.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Book = require('../models/Book');
const BorrowDefault = require('../models/Borrow');

async function run() {
  const mainUri = process.env.MONGO_URI;
  const borrowUri = process.env.BORROW_MONGO_URI || mainUri;

  if (!mainUri) {
    console.error('MONGO_URI is not set in server/.env');
    process.exit(1);
  }

  console.log('Connecting to main DB...');
  await mongoose.connect(mainUri, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to main DB');

  // Find a test user
  const user = await User.findOne({ email: 'test@example.com' });
  if (!user) {
    console.error('Test user test@example.com not found. Please create one first (see scripts/createTestUser.js)');
    await mongoose.connection.close();
    process.exit(1);
  }

  // Find an available book
  const book = await Book.findOne({ isAvailable: true });
  if (!book) {
    console.error('No available book found to borrow. Please add a book first.');
    await mongoose.connection.close();
    process.exit(1);
  }

  console.log(`Found user ${user.email} and book ${book.title} (${book._id})`);

  let BorrowModel = BorrowDefault;
  let borrowConn = null;

  if (borrowUri && borrowUri !== mainUri) {
    try {
      console.log('Connecting to borrow DB:', borrowUri);
      borrowConn = await mongoose.createConnection(borrowUri, { useNewUrlParser: true, useUnifiedTopology: true });
      const schema = new mongoose.Schema({
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        bookId: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
        borrowedDate: { type: Date, default: Date.now },
        dueDate: { type: Date, required: true },
        returnDate: { type: Date, default: null },
        fine: { type: Number, default: 0 },
      }, { timestamps: true });

      BorrowModel = borrowConn.model('Borrow', schema);
      console.log('Using separate borrow DB for seeding');
    } catch (err) {
      console.error('Failed to connect to borrow DB, falling back to main DB:', err.message);
      BorrowModel = BorrowDefault;
      borrowConn = null;
    }
  }

  // Calculate due date (7 days)
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + 7);

  // Create borrow record
  const borrow = new BorrowModel({ userId: user._id, bookId: book._id, dueDate });
  await borrow.save();

  // Update book to mark it borrowed
  book.isAvailable = false;
  book.currentBorrowerId = user._id;
  book.borrowHistory = book.borrowHistory || [];
  book.borrowHistory.push(borrow._id);
  await book.save();

  // Update user borrowedBooks in main DB
  await User.findByIdAndUpdate(user._id, { $push: { borrowedBooks: book._id } });

  console.log('Borrow record created:', borrow._id.toString());
  console.log('Due date:', dueDate.toISOString());

  if (borrowConn) await borrowConn.close();
  await mongoose.connection.close();
  console.log('Connections closed. Done.');
}

run().catch(err => {
  console.error('Error seeding borrow data:', err);
  process.exit(1);
});
