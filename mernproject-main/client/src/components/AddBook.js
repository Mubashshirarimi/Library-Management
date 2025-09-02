import React, { useState } from 'react';
import axios from '../axios';

const AddBook = ({ onBookAdded }) => {
  const [formData, setFormData] = useState({
    title: '',
    author: '',
    imageUrl: '',
    genre: '',
    availableCount: 10,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const payload = { ...formData, availableCount: Number(formData.availableCount || 10) };
      await axios.post('/books', payload);
      setSuccess('Book added successfully!');
      setFormData({
        title: '',
        author: '',
        imageUrl: '',
        genre: '',
        availableCount: 10,
      });
      if (onBookAdded) onBookAdded();
    } catch (err) {
      setError('Error while saving book: ' + (err.response?.data?.message || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h3 className="text-xl font-bold mb-4">Add New Book</h3>
      
      {success && <div className="bg-green-100 text-green-700 p-2 mb-4 rounded">{success}</div>}
      {error && <div className="bg-red-100 text-red-700 p-2 mb-4 rounded">{error}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="title">
            Title
          </label>
          <input
            type="text"
            id="title"
            className="w-full p-2 border border-gray-300 rounded-md"
            placeholder="Book Title"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            required
          />
        </div>
        
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="author">
            Author
          </label>
          <input
            type="text"
            id="author"
            className="w-full p-2 border border-gray-300 rounded-md"
            placeholder="Author Name"
            value={formData.author}
            onChange={(e) => setFormData({ ...formData, author: e.target.value })}
            required
          />
        </div>
        
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="imageUrl">
            Book Cover Image URL
          </label>
          <input
            type="url"
            id="imageUrl"
            className="w-full p-2 border border-gray-300 rounded-md"
            placeholder="https://example.com/book-cover.jpg"
            value={formData.imageUrl}
            onChange={(e) => setFormData({ ...formData, imageUrl: e.target.value })}
            required
          />
        </div>
        
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="genre">
            Genre
          </label>
          <select
            id="genre"
            className="w-full p-2 border border-gray-300 rounded-md"
            value={formData.genre}
            onChange={(e) => setFormData({ ...formData, genre: e.target.value })}
            required
          >
            <option value="">Select a genre</option>
            <option value="Fiction">Fiction</option>
            <option value="Non-Fiction">Non-Fiction</option>
            <option value="Mystery">Mystery</option>
            <option value="Science Fiction">Science Fiction</option>
            <option value="Fantasy">Fantasy</option>
            <option value="Romance">Romance</option>
            <option value="Thriller">Thriller</option>
            <option value="Biography">Biography</option>
            <option value="History">History</option>
            <option value="Children">Children</option>
            <option value="Self-Help">Self-Help</option>
            <option value="Business">Business</option>
            <option value="Other">Other</option>
          </select>
        </div>

        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="availableCount">
            Number of Copies Available
          </label>
          <input
            type="number"
            id="availableCount"
            min="0"
            className="w-full p-2 border border-gray-300 rounded-md"
            value={formData.availableCount}
            onChange={(e) => setFormData({ ...formData, availableCount: Number(e.target.value) })}
            required
          />
        </div>

        <button
          type="submit"
          className="w-full p-2 bg-green-500 text-white rounded-md hover:bg-green-600"
          disabled={loading}
        >
          {loading ? 'Adding Book...' : 'Add Book'}
        </button>
      </form>
    </div>
  );
};

export default AddBook;
