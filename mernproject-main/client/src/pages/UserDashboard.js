import React, { useEffect, useState } from 'react';
import axios from '../axios';
import Header from '../components/Header';
import Footer from '../components/Footer';
import LoadingPage from '../components/LoadingPage';

const UserDashboard = ({ user }) => {
  const [borrows, setBorrows] = useState([]);
  const [fees, setFees] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const [bRes, fRes] = await Promise.all([
          axios.get('/borrows/user'),
          axios.get('/borrows/fees')
        ]);
        setBorrows(bRes.data);
        setFees(fRes.data);
      } catch (err) {
        setError(err.response?.data?.message || err.message || 'Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  if (loading) return <LoadingPage message="Loading your dashboard" />;
  if (error) return <div className="p-8 text-center text-red-500">{error}</div>;

  return (
    <div className="flex flex-col min-h-screen">
      <Header user={user} />
      <div className="flex-grow p-8 max-w-6xl mx-auto w-full">
        <h2 className="text-3xl font-bold mb-6">My Dashboard</h2>

        {fees && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="p-4 bg-gray-100 rounded">
              <h4 className="font-semibold">Total Paid Fines</h4>
              <p className="text-xl">{fees.totalPaidFines} tk</p>
            </div>
            <div className="p-4 bg-gray-100 rounded">
              <h4 className="font-semibold">Current Late Fees</h4>
              <p className="text-xl">{fees.currentLateFees} tk</p>
            </div>
            <div className="p-4 bg-gray-100 rounded">
              <h4 className="font-semibold">Total Fines</h4>
              <p className="text-xl">{fees.totalFines} tk</p>
            </div>
          </div>
        )}

        <h3 className="text-2xl font-bold mb-4">My Borrowed Books</h3>
        {borrows.length === 0 ? (
          <p className="text-gray-500">You have no borrowed books.</p>
        ) : (
          <div className="bg-white rounded shadow p-4">
            <table className="min-w-full">
              <thead>
                <tr>
                  <th className="text-left p-2">Book</th>
                  <th className="text-left p-2">Borrowed</th>
                  <th className="text-left p-2">Due</th>
                  <th className="text-left p-2">Status</th>
                  <th className="text-left p-2">Fine</th>
                </tr>
              </thead>
              <tbody>
                {borrows.map(b => (
                  <tr key={b._id} className="border-t">
                    <td className="p-2">
                      {b.bookId ? (
                        <div>
                          <div className="font-semibold">{b.bookId.title}</div>
                          <div className="text-sm text-gray-600">{b.bookId.author}</div>
                        </div>
                      ) : 'Book not available' }
                    </td>
                    <td className="p-2">{new Date(b.borrowedDate).toLocaleDateString()}</td>
                    <td className="p-2">{new Date(b.dueDate).toLocaleDateString()}</td>
                    <td className="p-2">{b.returnDate ? 'Returned' : 'Borrowed'}</td>
                    <td className="p-2">{b.returnDate ? `${b.fine} tk` : (b.currentFine ? `${b.currentFine} tk` : '0 tk')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <Footer />
    </div>
  );
};

export default UserDashboard;
