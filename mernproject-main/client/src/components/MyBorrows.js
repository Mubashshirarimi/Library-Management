import React, { useState, useEffect } from 'react';
import axios from '../axios';
import { Link } from 'react-router-dom';
import LoadingPage from './LoadingPage';

const MyBorrows = () => {
  const [borrows, setBorrows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [feesSummary, setFeesSummary] = useState(null);
  const [returnSuccess, setReturnSuccess] = useState('');

  useEffect(() => {
    const fetchBorrows = async () => {
      try {
        const [borrowsResponse, feesResponse] = await Promise.all([
          axios.get('/borrows/user'),
          axios.get('/borrows/fees')
        ]);
        
        setBorrows(borrowsResponse.data);
        setFeesSummary(feesResponse.data);
        setLoading(false);
      } catch (err) {
        setError('Error fetching your borrowed books: ' + (err.response?.data?.message || err.message));
        setLoading(false);
      }
    };

    fetchBorrows();
  }, []);

  const handleReturn = async (borrowId) => {
    try {
      const response = await axios.post('/borrows/return', { borrowId });
      setReturnSuccess(response.data.message + (response.data.fine ? ` ${response.data.fine}` : ''));
      
      // Refresh data
      const [borrowsResponse, feesResponse] = await Promise.all([
        axios.get('/borrows/user'),
        axios.get('/borrows/fees')
      ]);
      
      setBorrows(borrowsResponse.data);
      setFeesSummary(feesResponse.data);
      
      // Clear success message after 5 seconds
      setTimeout(() => {
        setReturnSuccess('');
      }, 5000);
    } catch (err) {
      setError('Error returning book: ' + (err.response?.data?.message || err.message));
    }
  };

  if (loading) return <LoadingPage message="Loading your borrowed books" />;

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-2xl font-bold mb-6">My Borrowed Books</h2>
      
      {returnSuccess && (
        <div className="mb-4 bg-green-100 text-green-800 p-3 rounded-md">
          {returnSuccess}
        </div>
      )}
      
      {error && (
        <div className="mb-4 bg-red-100 text-red-800 p-3 rounded-md">
          {error}
        </div>
      )}
      
      {feesSummary && (
        <div className="mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-blue-50 p-4 rounded-md">
            <h4 className="text-sm text-gray-500">Total Paid Fines</h4>
            <p className="text-xl font-bold">{feesSummary.totalPaidFines} tk</p>
          </div>
          <div className={`${feesSummary.currentLateFees > 0 ? 'bg-red-50' : 'bg-yellow-50'} p-4 rounded-md`}>
            <h4 className="text-sm text-gray-500">Current Late Fees</h4>
            <p className="text-xl font-bold">{feesSummary.currentLateFees} tk</p>
          </div>
          <div className="bg-purple-50 p-4 rounded-md">
            <h4 className="text-sm text-gray-500">Total Fines</h4>
            <p className="text-xl font-bold">{feesSummary.totalFines} tk</p>
          </div>
        </div>
      )}
      
      {borrows.length === 0 ? (
        <div className="text-center py-8">
          <p className="text-gray-500 mb-4">You haven't borrowed any books yet.</p>
          <Link to="/catalog" className="text-blue-500 underline">
            Browse the catalog to find books
          </Link>
        </div>
      ) : (
        <div className="space-y-6">
          <h3 className="text-lg font-semibold">Current Borrows</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Book</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Borrowed Date</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Due Date</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {borrows.map((borrow) => (
                  <tr key={borrow._id}>
                    <td className="px-4 py-4 whitespace-nowrap">
                      {borrow.bookId ? (
                        <div className="flex items-center">
                          <div className="h-14 w-10 flex-shrink-0">
                            <img 
                              src={borrow.bookId.imageUrl} 
                              alt={borrow.bookId.title} 
                              className="h-full w-full object-cover" 
                            />
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">
                              {borrow.bookId.title}
                            </div>
                            <div className="text-sm text-gray-500">
                              {borrow.bookId.author}
                            </div>
                          </div>
                        </div>
                      ) : (
                        'Book unavailable'
                      )}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(borrow.borrowedDate).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(borrow.dueDate).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap">
                      {borrow.returnDate ? (
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                          Returned
                        </span>
                      ) : new Date() > new Date(borrow.dueDate) ? (
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                          Overdue
                        </span>
                      ) : (
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">
                          Borrowed
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-sm font-medium">
                      {!borrow.returnDate && (
                        <button
                          onClick={() => handleReturn(borrow._id)}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          Return Book
                        </button>
                      )}
                      {borrow.returnDate && borrow.fine > 0 && (
                        <span className="text-red-600">
                          Fine paid: {borrow.fine} tk
                        </span>
                      )}
                      {borrow.returnDate && borrow.fine === 0 && (
                        <span className="text-green-600">
                          Returned on time
                        </span>
                      )}
                      {!borrow.returnDate && new Date() > new Date(borrow.dueDate) && (
                        <div className="text-red-600 text-xs mt-1">
                          Current fine: {borrow.currentFine} tk
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default MyBorrows;
