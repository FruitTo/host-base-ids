import React, { useMemo } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import { format, parseISO } from 'date-fns';
import { AttackData } from '../types/attack';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale
);

interface AttackTimelineChartProps {
  data: AttackData[];
}

export const AttackTimelineChart: React.FC<AttackTimelineChartProps> = ({ data }) => {
  const chartData = useMemo(() => {
    // Group attacks by hour
    const hourlyAttacks = data.reduce((acc, attack) => {
      const hour = format(parseISO(attack.timestamp), 'yyyy-MM-dd HH:00');
      acc[hour] = (acc[hour] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const sortedHours = Object.keys(hourlyAttacks).sort();
    const labels = sortedHours.map(hour => format(parseISO(hour), 'HH:mm'));
    const values = sortedHours.map(hour => hourlyAttacks[hour]);

    return {
      labels,
      datasets: [
        {
          label: 'Attacks per Hour',
          data: values,
          borderColor: '#3B82F6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ],
    };
  }, [data]);

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      tooltip: {
        mode: 'index' as const,
        intersect: false,
      },
    },
    scales: {
      x: {
        display: true,
        title: {
          display: true,
          text: 'Time'
        }
      },
      y: {
        display: true,
        title: {
          display: true,
          text: 'Number of Attacks'
        },
        beginAtZero: true,
      },
    },
    interaction: {
      mode: 'nearest' as const,
      axis: 'x' as const,
      intersect: false,
    },
  };

  return (
    <div className="h-80">
      <Line data={chartData} options={options} />
    </div>
  );
};