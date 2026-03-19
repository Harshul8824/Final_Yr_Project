import React, { useState, useEffect } from 'react';
import { PieChart, Pie, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, Cell, ResponsiveContainer } from 'recharts';
import { AlertCircle, FileSearch, Shield, CheckCircle, RefreshCw } from 'lucide-react';
import { analyticsService } from '../services/api';
import toast from 'react-hot-toast';

const Analytics = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboard = async () => {
    setLoading(true);
    try {
        const dashboardData = await analyticsService.getDashboard();
        setData(dashboardData);
    } catch (err) {
        toast.error('Failed to load analytics data.');
    } finally {
        setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12" style={{ minHeight: '60vh' }}>
        <div className="flex flex-col items-center">
          <div className="loading-spinner w-10 h-10 border-4 mb-4"></div>
          <p className="text-gray-500 font-medium">Loading Analytics...</p>
        </div>
      </div>
    );
  }

  if (!data || data.totalChecks === 0) {
    return (
      <div className="container mx-auto max-w-7xl p-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">Analytics Dashboard</h1>
        <div className="flex flex-col items-center justify-center p-16 card shadow-sm border border-gray-200 bg-gray-50">
          <AlertCircle className="w-16 h-16 text-gray-400 mb-4" />
          <h2 className="text-xl font-bold text-gray-700">No Data Yet</h2>
          <p className="text-gray-500 mt-2">Run some VPN detection checks to see your statistics here.</p>
        </div>
      </div>
    );
  }

  const PIE_COLORS = ['#ef4444', '#f59e0b', '#22c55e'];
  const pieData = [
    { name: 'High Risk', value: data.riskBreakdown.high },
    { name: 'Medium Risk', value: data.riskBreakdown.medium },
    { name: 'Low Risk', value: data.riskBreakdown.low },
  ];

  return (
    <div className="container mx-auto max-w-7xl p-4 md:p-6" style={{ minHeight: '85vh' }}>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-1">Analytics Dashboard</h1>
          <p className="text-gray-600 font-medium">Insights and summary of your scan history.</p>
        </div>
        <button 
           onClick={fetchDashboard} 
           className="btn-secondary flex items-center bg-white shadow-sm hover:bg-gray-50"
        >
          <RefreshCw className="w-4 h-4 mr-2 text-primary-600" />
          Refresh
        </button>
      </div>

      {/* Top Stats Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="card shadow-sm border border-gray-100 flex items-center p-6 bg-white overflow-hidden relative" style={{ borderRadius: '1rem' }}>
           <div className="absolute -right-4 -top-4 opacity-5 pointer-events-none">
              <FileSearch className="w-24 h-24" />
           </div>
           <div className="rounded-full bg-blue-100 p-3 mr-4">
              <FileSearch className="w-6 h-6 text-blue-600" />
           </div>
           <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">Total Checks</p>
              <h2 className="text-3xl font-bold text-gray-900 mt-1">{data.totalChecks}</h2>
           </div>
        </div>
        <div className="card shadow-sm border border-red-50 flex items-center p-6 bg-white relative overflow-hidden" style={{ borderRadius: '1rem' }}>
           <div className="rounded-full bg-red-100 p-3 mr-4">
              <AlertCircle className="w-6 h-6 text-red-600" />
           </div>
           <div>
              <p className="text-xs font-bold text-red-500 uppercase tracking-wider">VPN Detected</p>
              <h2 className="text-3xl font-bold text-gray-900 mt-1">{data.vpnDetected}</h2>
           </div>
        </div>
        <div className="card shadow-sm border border-green-50 flex items-center p-6 bg-white relative overflow-hidden" style={{ borderRadius: '1rem' }}>
           <div className="rounded-full bg-green-100 p-3 mr-4">
              <CheckCircle className="w-6 h-6 text-green-600" />
           </div>
           <div>
              <p className="text-xs font-bold text-green-500 uppercase tracking-wider">Clean IPs</p>
              <h2 className="text-3xl font-bold text-gray-900 mt-1">{data.cleanIPs}</h2>
           </div>
        </div>
        <div className="card shadow-sm border border-orange-50 flex items-center p-6 bg-white relative overflow-hidden" style={{ borderRadius: '1rem' }}>
           <div className="rounded-full bg-orange-100 p-3 mr-4">
              <Shield className="w-6 h-6 text-orange-600" />
           </div>
           <div>
              <p className="text-xs font-bold text-orange-500 uppercase tracking-wider">High Risk</p>
              <h2 className="text-3xl font-bold text-gray-900 mt-1">{data.riskBreakdown.high}</h2>
           </div>
        </div>
      </div>

      {/* Middle Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        <div className="lg:col-span-1 card shadow-xl border border-gray-100 bg-white" style={{ borderRadius: '1rem', padding: '1.5rem' }}>
           <h3 className="text-lg font-bold text-gray-800 mb-6">Risk Breakdown</h3>
           <div style={{ width: '100%', height: 300 }}>
             <ResponsiveContainer>
               <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                     formatter={(value) => [value, 'Scans']}
                     contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
               </PieChart>
             </ResponsiveContainer>
           </div>
        </div>

        <div className="lg:col-span-2 card shadow-xl border border-gray-100 bg-white" style={{ borderRadius: '1rem', padding: '1.5rem' }}>
           <h3 className="text-lg font-bold text-gray-800 mb-6">Checks Over Last 7 Days</h3>
           <div style={{ width: '100%', height: 300 }}>
             <ResponsiveContainer>
               <BarChart data={data.checksOverTime.slice().reverse()} margin={{ top: 5, right: 30, left: -20, bottom: 5 }}>
                 <XAxis dataKey="date" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
                 <YAxis tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
                 <Tooltip 
                     cursor={{ fill: '#f3f4f6' }}
                     contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                 />
                 <Bar dataKey="count" fill="#6366f1" radius={[6, 6, 0, 0]} maxBarSize={50} />
               </BarChart>
             </ResponsiveContainer>
           </div>
        </div>
      </div>

      {/* Bottom Row Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Recent Activity Table */}
        <div className="card shadow-xl border border-gray-100 bg-white overflow-hidden p-0" style={{ borderRadius: '1rem' }}>
           <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
             <h3 className="text-lg font-bold text-gray-800">Recent Scans</h3>
           </div>
           {data.recentActivity.length > 0 ? (
             <div className="overflow-x-auto">
               <table className="min-w-full divide-y divide-gray-100">
                 <thead className="bg-white">
                   <tr>
                     <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">IP Address</th>
                     <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Date</th>
                     <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Risk Level</th>
                   </tr>
                 </thead>
                 <tbody className="bg-white divide-y divide-gray-100">
                   {data.recentActivity.map((act, i) => (
                     <tr key={i} className="hover:bg-gray-50 transition-colors">
                        <td className="px-6 py-3 whitespace-nowrap text-sm font-mono text-gray-900">{act.ip}</td>
                        <td className="px-6 py-3 whitespace-nowrap text-sm text-gray-500">{new Date(act.checkedAt).toLocaleDateString()} {new Date(act.checkedAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                        <td className="px-6 py-3 whitespace-nowrap">
                           <span className={`px-2.5 py-0.5 inline-flex text-xs leading-5 font-semibold rounded-full border 
                            ${act.overallRisk === 'High' ? 'bg-red-100 text-red-800 border-red-200' : 
                              act.overallRisk === 'Medium' ? 'bg-yellow-100 text-yellow-800 border-yellow-200' : 
                              'bg-green-100 text-green-800 border-green-200'}`}>
                             {act.overallRisk}
                           </span>
                        </td>
                     </tr>
                   ))}
                 </tbody>
               </table>
             </div>
           ) : (
             <div className="p-6 text-center text-gray-500 text-sm">No recent scans.</div>
           )}
        </div>

        {/* Top Risky IPs Table */}
        <div className="card shadow-xl border border-gray-100 bg-white overflow-hidden p-0" style={{ borderRadius: '1rem' }}>
           <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
             <h3 className="text-lg font-bold text-gray-800">Top Risky IPs</h3>
           </div>
           {data.topRiskyIPs.length > 0 ? (
             <div className="overflow-x-auto">
               <table className="min-w-full divide-y divide-gray-100">
                 <thead className="bg-white">
                   <tr>
                     <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">IP Address</th>
                     <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Times Scanned</th>
                     <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Risk Level</th>
                   </tr>
                 </thead>
                 <tbody className="bg-white divide-y divide-gray-100">
                   {data.topRiskyIPs.map((ip, i) => (
                     <tr key={i} className="hover:bg-gray-50 transition-colors">
                        <td className="px-6 py-3 whitespace-nowrap text-sm font-mono font-bold text-red-600">{ip.ip}</td>
                        <td className="px-6 py-3 whitespace-nowrap text-sm font-medium text-gray-600">{ip.count}</td>
                        <td className="px-6 py-3 whitespace-nowrap">
                           <span className={`px-2.5 py-0.5 inline-flex text-xs leading-5 font-semibold rounded-full border 
                            ${ip.risk === 'High' ? 'bg-red-100 text-red-800 border-red-200' : 
                              ip.risk === 'Medium' ? 'bg-yellow-100 text-yellow-800 border-yellow-200' : 
                              'bg-green-100 text-green-800 border-green-200'}`}>
                             {ip.risk}
                           </span>
                        </td>
                     </tr>
                   ))}
                 </tbody>
               </table>
             </div>
           ) : (
             <div className="p-6 text-center text-gray-500 text-sm">No risky IPs found.</div>
           )}
        </div>

      </div>
    </div>
  );
};

export default Analytics;
