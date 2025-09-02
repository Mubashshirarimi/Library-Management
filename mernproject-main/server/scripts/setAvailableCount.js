// Migration script: set availableCount to 10 for all existing books
require('dotenv').config();
const mongoose = require('mongoose');
const Book = require('../models/Book');

const MONGO_URI = process.env.MONGO_URI;

async function run() {
  try {
    if (!MONGO_URI) {
      console.error('MONGO_URI not set in server/.env');
      process.exit(1);
    }

    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

  const res = await Book.updateMany({}, { $set: { availableCount: 10, countavailable: 10 } });
  console.log('Updated books:', res.modifiedCount ?? res.nModified ?? res);

    await mongoose.disconnect();
    console.log('Migration complete.');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
}

run();
