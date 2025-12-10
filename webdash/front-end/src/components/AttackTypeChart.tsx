import React, { useMemo } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { AttackData } from '../types/attack';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

interface AttackTypeChartProps {
  data: AttackData[];
}

export const AttackTypeChart: React.FC<AttackTypeChartProps> = ({ data }) => {
  const chartData = useMemo(() => {
    const attackTypeCounts = data.reduce((acc, attack) => {
      acc[attack.attack_type] = (acc[attack.attack_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const labels = Object.keys(attackTypeCounts);
    const values = Object.values(attackTypeCounts);

    const colors = [
      '#EF4444', '#F97316', '#EAB308', '#22C55E', 
      '#3B82F6', '#8B5CF6', '#EC4899', '#06B6D4'
    ];

    return {
      labels,
      datasets: [
        {
          label: 'Attack Count',
          data: values,
          backgroundColor: colors.slice(0, labels.length),
          borderColor: colors.slice(0, labels.length),
          borderWidth: 1,
          borderRadius: 8,
        },
      ],
    };
  }, [data]);

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: 'white',
        bodyColor: 'white',
        borderColor: 'rgba(255, 255, 255, 0.2)',
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        title: {
          display: true,
          text: 'Attack Types'
        }
      },
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'Number of Attacks'
        }
      },
    },
  };

  return (
    <div className="h-80">
      <Bar data={chartData} options={options} />
    </div>
  );
};