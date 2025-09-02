import React, { useState, useEffect } from 'react';
import axios from '../axios';
import { useParams, useNavigate } from 'react-router-dom';
import Header from '../components/Header';
import Footer from '../components/Footer';
import BorrowedBooks from '../components/BorrowedBooks';
import AddBook from '../components/AddBook';
import '../styles/AdminPanel.css';

// ...existing code...

const AdminPanel = ({ user: propUser }) => {
  const [formData, setFormData] = useState({
    title: '',
    author: '',
    imageUrl: '',
  genre: '',
  availableCount: 10,
  });
  const [isEdit, setIsEdit] = useState(false);
  const [error, setError] = useState('');
  const [user, setUser] = useState(propUser || null);
  const [activeTab, setActiveTab] = useState('addBook'); // 'addBook', 'editBook', or 'borrowed'
  const navigate = useNavigate();
  const { id } = useParams();

  useEffect(() => {
    // Update local user when prop changes
    setUser(propUser || null);

    // Ensure we have an authenticated admin user before showing admin UI.
    // If propUser is not provided, try to fetch /auth/me using token from localStorage.
    const ensureAdminAndLoad = async () => {
      let currentUser = propUser;

      if (!currentUser) {
        const token = localStorage.getItem('token');
        if (!token) {
          navigate('/login');
          return;
        }

        try {
          const res = await axios.get('/auth/me');
          currentUser = res.data?.user || res.data;
          setUser(currentUser || null);
        } catch (err) {
          console.error('Failed to verify current user:', err);
          navigate('/login');
          return;
        }
      }

      if (!currentUser || currentUser.role !== 'admin') {
        navigate('/');
        return;
      }

      if (id) {
        // If there's an ID in the URL, it means we are editing a book
        setIsEdit(true);
        setActiveTab('editBook');
        try {
          const response = await axios.get(`/books/${id}`);
          setFormData({
            title: response.data.title || '',
            author: response.data.author || '',
            imageUrl: response.data.imageUrl || '',
            genre: response.data.genre || '',
            availableCount: response.data.availableCount ?? response.data.countavailable ?? 10,
          });
        } catch (error) {
          console.error('Failed to load book for editing:', error);
        }
      } else {
        setIsEdit(false);
        setFormData({ title: '', author: '', imageUrl: '', genre: '', availableCount: 10 });
      }
    };

    ensureAdminAndLoad();
  }, [id, navigate, propUser]);

  // Clear messages when switching tabs
  useEffect(() => {
    setError('');
    setSuccess('');
  }, [activeTab]);

  // Fetch books for management
  const [books, setBooks] = useState([]);
  const [success, setSuccess] = useState('');
  const fetchBooks = async () => {
    try {
      const res = await axios.get('/books');
      setBooks(res.data || []);
    } catch (err) {
      console.error('Failed to load books for admin:', err);
    }
  };

  useEffect(() => {
    // fetch always when admin panel mounts or when switching to manageBooks
    fetchBooks();
  }, []);

  useEffect(() => {
    // When switched to borrowed tab, ensure BorrowedBooks fetches current data by re-mounting
    // Force a small state ripple by toggling activeTab briefly if needed (no-op here)
  }, [activeTab]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      // Validate required fields
      const payload = {
        title: String(formData.title || '').trim(),
        author: String(formData.author || '').trim(),
        imageUrl: String(formData.imageUrl || '').trim(),
        genre: String(formData.genre || '').trim(),
        availableCount: Number(formData.availableCount ?? 10),
      };

      if (!payload.title || !payload.author || !payload.imageUrl || !payload.genre) {
        setError('Please fill in all required fields');
        return;
      }

      // keep legacy field in sync
      payload.countavailable = payload.availableCount;

      if (isEdit && id) {
        const res = await axios.put(`/books/${id}`, payload);
        await fetchBooks();
        setActiveTab('manageBooks');
        setSuccess('Book updated successfully');
        navigate('/admin');
      } else {
        const res = await axios.post('/books', payload);
        await fetchBooks();
        setActiveTab('manageBooks');
        setSuccess('Book created successfully');
        navigate('/admin');
      }
    } catch (err) {
      setError('Error while saving book: ' + (err.response?.data?.message || err.message));
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      <Header user={user} />
      <div className="flex-grow p-8 max-w-6xl mx-auto w-full">
        <h2 className="text-3xl font-bold mb-6">Admin Dashboard</h2>
        
        {/* Full-width segmented tab navigation */}
        <div className="admin-tabs mb-6">
          <button
            className={`admin-tab ${activeTab === 'addBook' ? 'active' : ''}`}
            onClick={() => { setActiveTab('addBook'); setIsEdit(false); navigate('/admin'); }}
          >
            Add New Book
          </button>

          <button
            className={`admin-tab ${activeTab === 'manageBooks' ? 'active' : ''}`}
            onClick={() => { setActiveTab('manageBooks'); navigate('/admin'); }}
          >
            Manage Books
          </button>

          {isEdit && (
            <button
              className={`admin-tab ${activeTab === 'editBook' ? 'active' : ''}`}
              onClick={() => { setActiveTab('editBook'); navigate(`/admin/${id}`); }}
            >
              Edit Book
            </button>
          )}

          <button
            className={`admin-tab ${activeTab === 'borrowed' ? 'active' : ''}`}
            onClick={() => { setActiveTab('borrowed'); navigate('/admin'); }}
          >
            Borrowed Books
          </button>
        </div>
        
        {/* Tab Content */}
        <div className="admin-tab-content">
          {activeTab === 'addBook' && (
            <AddBook onBookAdded={() => setError('')} />
          )}
        
  {/* (tabs above control the active section) */}

          {activeTab === 'manageBooks' && (
            <div className="manage-books bg-white p-6 rounded-lg shadow-md">
            <h3 className="text-xl font-bold mb-4">Manage Books</h3>
            <div className="mb-4">
              <button
                onClick={() => setActiveTab('addBook')}
                className="p-2 bg-green-500 text-white rounded-md mr-2"
              >
                Add New Book
              </button>
              <button onClick={fetchBooks} className="p-2 bg-gray-200 rounded-md">Refresh</button>
            </div>

            {books.length === 0 ? (
              <p className="text-gray-500">No books in the library.</p>
            ) : (
              <div className="admin-books-table overflow-x-auto">
                <table className="min-w-full border">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="p-2 text-left">Cover</th>
                      <th className="p-2 text-left">Title</th>
                      <th className="p-2 text-left">Author</th>
                      <th className="p-2 text-left">Genre</th>
                      <th className="p-2 text-left">Available</th>
                      <th className="p-2 text-left">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {books.map(b => (
                      <tr key={b._id} className="border-t">
                        <td className="p-2"><img src={b.imageUrl || 'https://via.placeholder.com/80x100'} alt={b.title} className="w-16 h-20 object-cover" /></td>
                        <td className="p-2 align-top">{b.title}</td>
                        <td className="p-2 align-top">{b.author}</td>
                        <td className="p-2 align-top">{b.genre || '—'}</td>
                        <td className="p-2 align-top">{b.availableCount ?? 0}</td>
                        <td className="p-2 align-top actions">
                          <button
                            onClick={() => { setActiveTab('editBook'); setError(''); setSuccess(''); navigate(`/admin/${b._id}`); }}
                            className="p-1 px-2 mr-2 bg-blue-500 text-white rounded hover:bg-blue-600"
                          >
                            Edit
                          </button>
                          <button
                            onClick={async () => {
                              if (!window.confirm('Delete this book permanently?')) return;
                              try {
                                await axios.delete(`/books/${b._id}`);
                                await fetchBooks();
                              } catch (err) {
                                console.error('Failed to delete book:', err);
                                alert('Failed to delete book');
                              }
                            }}
                            className="p-1 px-2 bg-red-500 text-white rounded hover:bg-red-600"
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            </div>
          )}
        
          {activeTab === 'editBook' && isEdit && (
            <div className="bg-white p-6 rounded-lg shadow-md edit-book-panel">
            <h3 className="text-xl font-bold mb-4">Edit Book</h3>
              <form onSubmit={handleSubmit} className="edit-book-form">
              <div className="mb-4 form-column">
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
              
              <div className="mb-4 form-column">
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
              
              <div className="mb-4 form-column">
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
              
              <div className="mb-4 form-column">
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
                  value={formData.availableCount || 10}
                  onChange={(e) => setFormData({ ...formData, availableCount: Number(e.target.value) })}
                />
              </div>
              
              <div className="form-actions flex gap-4">
                <button 
                  type="submit" 
                  className="flex-1 p-2 bg-green-500 text-white rounded-md hover:bg-green-600"
                >
                  Update Book
                </button>
                <button 
                  type="button" 
                  onClick={() => navigate('/admin')}
                  className="flex-1 p-2 bg-gray-500 text-white rounded-md hover:bg-gray-600"
                >
                  Cancel
                </button>
              </div>
              {error && <p className="text-red-500 mt-4">{error}</p>}
            </form>
          </div>
        )}
        
        {activeTab === 'borrowed' && (
          <BorrowedBooks />
        )}
      </div>
    </div>
      <Footer />
    </div>
  );
};

export default AdminPanel;
