const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

/**
 * User Schema for MongoDB
 * Handles authentication and user roles
 */
const userSchema = new mongoose.Schema(
  {
    name: { 
      type: String, 
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters long']
    },
    email: { 
      type: String, 
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email address']
    },
    password: { 
      type: String, 
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters long']
    },
    role: { 
      type: String, 
      enum: ['user', 'admin', 'librarian'],
      default: 'user' 
    },
    profilePicture: {
      type: String,
      default: ''
    },
    borrowedBooks: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Book'
    }],
    isActive: {
      type: Boolean,
      default: true
    }
  },
  { 
    timestamps: true,
    toJSON: { 
      transform: function(doc, ret) {
        delete ret.password;
        return ret;
      }
    }
  }
);

// Index for faster lookups
userSchema.index({ email: 1 });

/**
 * Pre-save middleware to hash password
 * Only runs when password field is modified
 */
userSchema.pre('save', async function (next) {
  try {
    // Only hash the password if it's modified
    if (!this.isModified('password')) {
      return next();
    }
    
    // Generate salt and hash password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Method to compare password for login
 * @param {string} enteredPassword - The password attempt to verify
 * @return {boolean} True if password matches, false otherwise
 */
userSchema.methods.matchPassword = async function (enteredPassword) {
  try {
    return await bcrypt.compare(enteredPassword, this.password);
  } catch (error) {
    throw new Error('Password comparison failed');
  }
};

/**
 * Static method to find user by email
 */
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

const User = mongoose.model('User', userSchema);

module.exports = User;
