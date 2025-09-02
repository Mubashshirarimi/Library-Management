const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  imageUrl: { type: String, required: true },
  genre: { type: String, required: true },
  isAvailable: { type: Boolean, default: true },
  // number of available copies for this book
  availableCount: { type: Number, default: 10 },
  // legacy/DB field name some scripts may use
  countavailable: { type: Number, default: 10 },
  currentBorrowerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  borrowHistory: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Borrow' }],
}, { timestamps: true });

module.exports = mongoose.model('Book', bookSchema);
