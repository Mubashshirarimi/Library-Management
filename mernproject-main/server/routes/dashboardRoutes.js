const express = require('express');
const User = require('../models/User');
const Borrow = require('../models/Borrow');
const authenticateJWT = require('../middleware/authMiddleware');
const router = express.Router();

// Get user-specific data
router.get('/dashboard', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) return res.status(404).json({ message: 'User not found' });

    const borrowedBooks = await Borrow.find({ userId: req.user.userId })
      .populate('bookId', 'title author dueDate fine');

    res.json({ user, borrowedBooks });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
