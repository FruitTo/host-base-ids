import React, { useMemo } from 'react';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { AttackData } from '../types/attack';

ChartJS.register(ArcElement, Tooltip, Legend);

interface ProtocolDistributionProps {
  data: AttackData[];
}

export const ProtocolDistribution: React.FC<ProtocolDistributionProps> = ({ data }) => {
  const chartData = useMemo(() => {
    const protocolCounts = data.reduce((acc, attack) => {
      acc[attack.protocol] = (acc[attack.protocol] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const labels = Object.keys(protocolCounts);
    const values = Object.values(protocolCounts);

    const colors = [
      '#3B82F6', '#EF4444', '#10B981', '#F59E0B', 
      '#8B5CF6', '#EC4899', '#06B6D4', '#84CC16'
    ];

    return {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: colors.slice(0, labels.length),
          borderColor: '#ffffff',
          borderWidth: 2,
          hoverBorderWidth: 3,
        },
      ],
    };
  }, [data]);

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          padding: 20,
          usePointStyle: true,
        }
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: 'white',
        bodyColor: 'white',
        borderColor: 'rgba(255, 255, 255, 0.2)',
        borderWidth: 1,
      },
    },
    cutout: '60%',
  };

  return (
    <div className="h-80">
      <Doughnut data={chartData} options={options} />
    </div>
  );
};