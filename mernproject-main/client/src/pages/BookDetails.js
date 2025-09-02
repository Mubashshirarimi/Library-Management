import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from '../axios';
import Header from '../components/Header';
import Footer from '../components/Footer';
import LoadingPage from '../components/LoadingPage';
import '../styles/BookDetails.css';

const BookDetails = ({ user, setUser }) => {
  const { id } = useParams();
  const [book, setBook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [borrowing, setBorrowing] = useState(false);
  const [borrowSuccess, setBorrowSuccess] = useState('');
  const [borrowError, setBorrowError] = useState('');
  const [reviews, setReviews] = useState([]);
  const [newRating, setNewRating] = useState(5);
  const [newComment, setNewComment] = useState('');
  const [postingReview, setPostingReview] = useState(false);
  const [reviewError, setReviewError] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
  const response = await axios.get(`/books/${id}`);
        setBook(response.data);
        // fetch reviews separately
        try {
          const r = await axios.get(`/reviews/book/${id}`);
          setReviews(r.data);
        } catch (rvErr) {
          console.warn('Failed to load reviews', rvErr?.response?.data || rvErr.message);
        }
      } catch (err) {
        setError(err.response?.data?.message || err.message || 'Failed to load book');
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [id]);

  if (loading) return <LoadingPage message="Loading book" />;
  if (error) return <div className="p-8 text-center text-red-500">{error}</div>;
  if (!book) return <div className="p-8 text-center">Book not found</div>;

  return (
    <div className="flex flex-col min-h-screen">
  <Header user={user} setUser={setUser} />
      <div className="flex-grow p-8 max-w-4xl mx-auto w-full">
        <Link to="/catalog" className="text-blue-500 hover:text-blue-700 flex items-center mb-4">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-1" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M9.707 14.707a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 1.414L7.414 9H15a1 1 0 110 2H7.414l2.293 2.293a1 1 0 010 1.414z" clipRule="evenodd" />
          </svg>
          Back to Catalog
        </Link>
        <div className="bg-white p-6 rounded-lg shadow-lg">
          <div className="md:flex">
            <img src={book.imageUrl || 'https://via.placeholder.com/300'} alt={book.title} className="md:w-1/3 object-cover rounded mb-4 md:mb-0 md:mr-6" />
            <div>
              <h1 className="text-3xl font-bold">{book.title}</h1>
              <h2 className="text-xl text-gray-700 mb-2">by {book.author}</h2>
              {book.genre && <p className="text-blue-500 mb-4">Genre: {book.genre}</p>}
              <div className="mt-4">
                <h3 className="text-xl font-semibold mb-2">Description</h3>
                <p className="text-gray-700">{book.description || 'No description available.'}</p>
              </div>
              {/* reviews moved below the main card for layout */}

              {/* Borrow status */}
              <div className="mt-6 p-3 rounded-md bg-gray-50">
                <h3 className="font-semibold mb-1">Availability Status</h3>
                {((book.availableCount ?? book.countavailable) > 0) ? (
                  <div className="text-green-600">{(book.availableCount ?? book.countavailable)} copies available</div>
                ) : (
                  <div className="text-red-600">Currently not available</div>
                )}
              </div>
              
              {/* Borrow button (hidden for admins) */}
              {user && (book.availableCount ?? book.countavailable) > 0 && user.role !== 'admin' && (
                <div className="mt-4">
                  <button
                    onClick={async () => {
                      if (!user) {
                        setBorrowError('You must be logged in to borrow books');
                        return;
                      }
                      
                      try {
                        setBorrowing(true);
                        setBorrowError('');
                        setBorrowSuccess('');
                        
                        console.log('Attempting to borrow book with ID:', book._id);
                        
                        const response = await axios.post('/borrows/borrow', {
                          bookId: book._id
                        });
                        
                        console.log('Borrow response:', response.data);
                        
                        setBorrowSuccess(`Book borrowed successfully! Due date: ${new Date(response.data.dueDate).toLocaleDateString()}`);
                        // refresh book details from server to get updated counts
                        try {
                          const bRes = await axios.get(`/books/${book._id}`);
                          setBook(bRes.data);
                        } catch (e) {
                          console.warn('Failed to refresh book after borrow', e?.message || e);
                        }
                      } catch (err) {
                        console.error('Borrow error:', err);
                        setBorrowError(err.response?.data?.message || err.message || 'Failed to borrow book');
                      } finally {
                        setBorrowing(false);
                      }
                    }}
                    className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400"
                    disabled={borrowing}
                  >
                    {borrowing ? 'Processing...' : 'Borrow This Book'}
                  </button>
                  
                  {borrowSuccess && (
                    <div className="mt-2 p-2 bg-green-100 text-green-700 rounded">
                      {borrowSuccess}
                    </div>
                  )}
                  
                  {borrowError && (
                    <div className="mt-2 p-2 bg-red-100 text-red-700 rounded">
                      {borrowError}
                    </div>
                  )}
                </div>
              )}
              
              {!user && (
                <div className="mt-4 p-2 bg-blue-100 text-blue-800 rounded">
                  <Link to="/login" className="font-medium underline">Log in</Link> to borrow this book.
                </div>
              )}

              {user && user.role === 'admin' && (
                <div className="mt-4 p-2 bg-yellow-100 text-yellow-800 rounded">
                  Admins cannot borrow books here. Use the Admin Dashboard to manage borrows.
                </div>
              )}
            </div>
          </div>
        </div>
        {/* Reviews card placed below the main book card */}
        <div className="reviews-wrapper max-w-4xl mx-auto mt-6">
          <div className="reviews-card bg-white p-4 rounded-lg shadow-sm">
            <h3 className="reviews-heading">Reviews</h3>
            {reviews.length === 0 && <div className="text-gray-600">No reviews yet. Be the first to review.</div>}
            <div className="reviews-list mt-3">
              {reviews.map(r => (
                <div key={r._id} className="review-card">
                  <div className="review-header">
                    <strong className="review-author">{r.reviewerName || r.user?.name || 'Anonymous'}</strong>
                    <span className="review-date">{new Date(r.createdAt).toLocaleDateString()}</span>
                  </div>
                  <div className="review-rating">Rating: <span className="rating-value">{r.rating}</span>/5</div>
                  {r.comment && <div className="review-comment">{r.comment}</div>}
                </div>
              ))}
            </div>

            <div className="review-form mt-4">
              {user ? (
                <div className="review-post-card">
                  <h4 className="mb-2">Leave a review</h4>
                  <div className="flex items-center gap-3 mb-2">
                    <label className="text-sm">Rating</label>
                    <select value={newRating} onChange={e => setNewRating(Number(e.target.value))} className="border rounded px-2 py-1">
                      {[5,4,3,2,1].map(n => <option key={n} value={n}>{n}</option>)}
                    </select>
                  </div>
                  <textarea value={newComment} onChange={e => setNewComment(e.target.value)} className="w-full border rounded p-2 mb-2" placeholder="Write a short review (optional)"></textarea>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={async () => {
                        try {
                          setPostingReview(true);
                          setReviewError('');
                          const res = await axios.post(`/reviews/book/${id}`, { rating: newRating, comment: newComment });
                          setReviews(prev => [res.data, ...prev]);
                          setNewComment('');
                          setNewRating(5);
                        } catch (err) {
                          console.error('Review post error', err);
                          setReviewError(err.response?.data?.message || err.message || 'Failed to post review');
                        } finally {
                          setPostingReview(false);
                        }
                      }}
                      className="btn-submit"
                      disabled={postingReview}
                    >
                      {postingReview ? 'Posting...' : 'Submit Review'}
                    </button>
                    {reviewError && <div className="text-red-600">{reviewError}</div>}
                  </div>
                </div>
              ) : (
                <div className="text-sm text-gray-600">Please <Link to="/login" className="underline">log in</Link> to leave a review.</div>
              )}
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default BookDetails;
