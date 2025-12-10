import React, { useState } from 'react';
import { format, parse } from 'date-fns';
import {
  Shield,
  Activity,
  Users,
  TrendingUp,
  RefreshCw,
} from 'lucide-react';

import { useAttackData } from './hooks/useAttackData';
import { StatsCard } from './components/StatsCard';
import { ChartCard } from './components/ChartCard';
import { DatePicker } from './components/DatePicker';
import { AttackTimelineChart } from './components/AttackTimelineChart';
import { AttackTypeChart } from './components/AttackTypeChart';
import { ProtocolDistribution } from './components/ProtocolDistribution';
import { AttackTable } from './components/AttackTable';
import { LoadingSpinner } from './components/LoadingSpinner';
import { ErrorMessage } from './components/ErrorMessage';

function App() {
  // เก็บวันที่เป็น ISO เพื่อให้ <input type="date" /> ใช้ได้จริง
  const todayISO = format(new Date(), 'yyyy-MM-dd');
  const [selectedDateISO, setSelectedDateISO] = useState<string>(todayISO);

  // แปลงเป็น dd-MM-yyyy เฉพาะตอนยิง API/Hook
  const selectedDateForApi = format(
    parse(selectedDateISO, 'yyyy-MM-dd', new Date()),
    'dd-MM-yyyy'
  );

  const { data, loading, error, lastUpdated, stats, refetch } =
    useAttackData(selectedDateForApi);

  if (loading && data.length === 0) return <LoadingSpinner />;

  // ถ้าต้องการ handle error ให้เปิดใช้สองบรรทัดนี้
  // if (error) return <ErrorMessage message={error} onRetry={refetch} />;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-lg border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
                <p className="text-gray-500">Real-time attack monitoring and analysis</p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <DatePicker
                selectedDate={selectedDateISO}      // <-- ใช้ ISO
                onDateChange={setSelectedDateISO}    // <-- รับค่า ISO กลับมา
                loading={loading}
              />
              <button
                onClick={refetch}
                disabled={loading}
                className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors duration-200 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatsCard
            title="Total Attacks"
            value={stats.totalAttacks.toLocaleString()}
            icon={Shield}
            color="red"
            subtitle="Detected incidents"
          />
          <StatsCard
            title="Unique Source IPs"
            value={stats.uniqueIPs}
            icon={Users}
            color="blue"
            subtitle="Different attackers"
          />
          <StatsCard
            title="Average Probability"
            value={`${(stats.avgProbability * 100).toFixed(1)}%`}
            icon={TrendingUp}
            color="yellow"
            subtitle="Threat confidence"
          />
          <StatsCard
            title="Most Common Attack"
            value={stats.mostCommonAttack}
            icon={Activity}
            color="green"
            subtitle="Primary threat type"
          />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          <ChartCard title="Attack Timeline">
            <AttackTimelineChart data={data} />
          </ChartCard>

          <ChartCard title="Attack Types Distribution">
            <AttackTypeChart data={data} />
          </ChartCard>

          <ChartCard title="Protocol Distribution" className="lg:col-span-2">
            <div className="max-w-md mx-auto">
              <ProtocolDistribution data={data} />
            </div>
          </ChartCard>
        </div>

        {/* Attack Details Table */}
        <AttackTable data={data} />
      </main>
    </div>
  );
}

export default App;
