import React, { useState, useEffect } from 'react';
import axios from '../axios';

const BorrowedBooks = () => {
  const [borrows, setBorrows] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchBorrows = async () => {
      try {
        const borrowsResponse = await axios.get('/borrows');
        const statsResponse = await axios.get('/borrows/stats');
        setBorrows(borrowsResponse.data);
        setStats(statsResponse.data);
        setLoading(false);
      } catch (err) {
        setError('Error fetching borrow information: ' + (err.response?.data?.message || err.message));
        setLoading(false);
      }
    };

    fetchBorrows();
  }, []);

  const handleReturn = async (borrowId) => {
    try {
      await axios.post('/borrows/return', { borrowId });
      // Refresh borrows list
      const response = await axios.get('/borrows');
      setBorrows(response.data);
      // Refresh stats
      const statsResponse = await axios.get('/borrows/stats');
      setStats(statsResponse.data);
    } catch (err) {
      setError('Error returning book: ' + (err.response?.data?.message || err.message));
    }
  };

  const calculateDaysOverdue = (dueDate) => {
    const now = new Date();
    const due = new Date(dueDate);
    if (now <= due) return 0;
    
    const diffTime = Math.abs(now - due);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  if (loading) return <div className="text-center py-8">Loading borrowed books...</div>;
  if (error) return <div className="text-red-500 text-center py-8">{error}</div>;

  return (
    <div className="w-full">
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="bg-blue-100 p-4 rounded-md">
            <h4 className="text-lg font-bold">Total Borrows</h4>
            <p className="text-2xl">{stats.totalBorrows}</p>
          </div>
          <div className="bg-yellow-100 p-4 rounded-md">
            <h4 className="text-lg font-bold">Active Borrows</h4>
            <p className="text-2xl">{stats.activeBorrows}</p>
          </div>
          <div className="bg-green-100 p-4 rounded-md">
            <h4 className="text-lg font-bold">Total Fees</h4>
            <p className="text-2xl">{stats.totalFees} tk</p>
          </div>
          <div className="bg-purple-100 p-4 rounded-md">
            <h4 className="text-lg font-bold">Return Rate</h4>
            <p className="text-2xl">
              {stats.totalBorrows > 0
                ? `${Math.round(((stats.totalBorrows - stats.activeBorrows) / stats.totalBorrows) * 100)}%`
                : '0%'}
            </p>
          </div>
        </div>
      )}

      <h3 className="text-2xl font-bold mb-4">All Borrowed Books</h3>
      
      {borrows.length === 0 ? (
        <p className="text-gray-500">No books have been borrowed.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white border border-gray-300">
            <thead className="bg-gray-100">
              <tr>
                <th className="py-2 px-4 border-b text-left">Book</th>
                <th className="py-2 px-4 border-b text-left">User</th>
                <th className="py-2 px-4 border-b text-left">Borrow Date</th>
                <th className="py-2 px-4 border-b text-left">Due Date</th>
                <th className="py-2 px-4 border-b text-left">Status</th>
                <th className="py-2 px-4 border-b text-left">Fine</th>
                <th className="py-2 px-4 border-b text-left">Actions</th>
              </tr>
            </thead>
            <tbody>
              {borrows.map((borrow) => (
                <tr key={borrow._id} className={borrow.returnDate ? 'bg-green-50' : 'bg-white'}>
                  <td className="py-2 px-4 border-b">
                    {borrow.bookId ? (
                      <div className="flex items-center">
                        <img 
                          src={borrow.bookId.imageUrl} 
                          alt={borrow.bookId.title} 
                          className="w-10 h-12 object-cover mr-2" 
                        />
                        <div>
                          <p className="font-semibold">{borrow.bookId.title}</p>
                          <p className="text-sm text-gray-600">{borrow.bookId.author}</p>
                        </div>
                      </div>
                    ) : (
                      'Book not available'
                    )}
                  </td>
                  <td className="py-2 px-4 border-b">
                    {borrow.userId ? (
                      <div>
                        <p>{borrow.userId.name}</p>
                        <p className="text-sm text-gray-600">{borrow.userId.email}</p>
                      </div>
                    ) : (
                      'User not available'
                    )}
                  </td>
                  <td className="py-2 px-4 border-b">
                    {new Date(borrow.borrowedDate).toLocaleDateString()}
                  </td>
                  <td className="py-2 px-4 border-b">
                    {new Date(borrow.dueDate).toLocaleDateString()}
                  </td>
                  <td className="py-2 px-4 border-b">
                    {borrow.returnDate ? (
                      <span className="text-green-600">Returned</span>
                    ) : (
                      <span className={
                        new Date() > new Date(borrow.dueDate) 
                          ? 'text-red-600' 
                          : 'text-yellow-600'
                      }>
                        {new Date() > new Date(borrow.dueDate) 
                          ? `Overdue (${calculateDaysOverdue(borrow.dueDate)} days)` 
                          : 'Borrowed'}
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-4 border-b">
                    {borrow.returnDate ? (
                      <span>{borrow.fine} tk</span>
                    ) : (
                      new Date() > new Date(borrow.dueDate) ? (
                        <span className="text-red-600">
                          {calculateDaysOverdue(borrow.dueDate) * 10} tk (estimated)
                        </span>
                      ) : (
                        '0 tk'
                      )
                    )}
                  </td>
                  <td className="py-2 px-4 border-b">
                    {!borrow.returnDate && (
                      <button
                        onClick={() => handleReturn(borrow._id)}
                        className="px-3 py-1 bg-blue-500 text-white rounded hover:bg-blue-600"
                      >
                        Mark Returned
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      
      {stats && stats.topBooks && stats.topBooks.length > 0 && (
        <div className="mt-8">
          <h3 className="text-xl font-bold mb-4">Most Borrowed Books</h3>
          <ul className="bg-white rounded-lg p-4 border">
            {stats.topBooks.map((item, index) => (
              <li key={item.book._id} className="mb-2 pb-2 border-b last:border-b-0 flex justify-between">
                <div>
                  <span className="font-semibold mr-2">#{index + 1}</span>
                  <span>{item.book.title}</span> 
                  <span className="text-gray-600 ml-2">by {item.book.author}</span>
                </div>
                <span className="text-blue-600 font-semibold">{item.borrowCount} borrows</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default BorrowedBooks;
