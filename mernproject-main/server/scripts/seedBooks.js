const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const mongoose = require('mongoose');
const Book = require('../models/Book');

const books = [
  { title: 'The Pragmatic Programmer', author: 'Andrew Hunt', genre: 'Programming', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Clean Code', author: 'Robert C. Martin', genre: 'Programming', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'You Don\'t Know JS', author: 'Kyle Simpson', genre: 'Programming', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Eloquent JavaScript', author: 'Marijn Haverbeke', genre: 'Programming', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Data Communication and Networking', author: 'Behrouz Forouzan', genre: 'Networking', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Introduction to Algorithms', author: 'Cormen, Leiserson, Rivest, Stein', genre: 'Algorithms', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Design Patterns', author: 'Erich Gamma', genre: 'Software Engineering', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'The Mythical Man-Month', author: 'Frederick P. Brooks Jr.', genre: 'Software Engineering', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Effective Java', author: 'Joshua Bloch', genre: 'Programming', imageUrl: 'https://via.placeholder.com/150' },
  { title: 'Refactoring', author: 'Martin Fowler', genre: 'Programming', imageUrl: 'https://via.placeholder.com/150' },
];

async function run() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error('MONGO_URI not set in server/.env');
    process.exit(1);
  }

  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to MongoDB');

    const del = await Book.deleteMany({});
    console.log(`Deleted ${del.deletedCount || 0} existing books`);

    const docs = books.map(b => ({ ...b, isAvailable: true }));
    const inserted = await Book.insertMany(docs, { ordered: true });
    console.log(`Inserted ${inserted.length} books.`);
    inserted.forEach(b => console.log(b._id.toString(), '-', b.title));

    const count = await Book.countDocuments({ isAvailable: true });
    console.log(`Available books count: ${count}`);

    await mongoose.disconnect();
    console.log('Disconnected. Done.');
  } catch (err) {
    console.error('Error seeding books:', err);
    try { await mongoose.disconnect(); } catch (e) {}
    process.exit(1);
  }
}

run();
