import React from 'react';
import { DivideIcon as LucideIcon } from 'lucide-react';

interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color: 'blue' | 'red' | 'green' | 'yellow';
  trend?: {
    value: number;
    isPositive: boolean;
  };
}

const colorConfig = {
  blue: {
    bg: 'bg-blue-500',
    bgLight: 'bg-blue-50',
    text: 'text-blue-600',
    icon: 'text-blue-500'
  },
  red: {
    bg: 'bg-red-500',
    bgLight: 'bg-red-50',
    text: 'text-red-600',
    icon: 'text-red-500'
  },
  green: {
    bg: 'bg-green-500',
    bgLight: 'bg-green-50',
    text: 'text-green-600',
    icon: 'text-green-500'
  },
  yellow: {
    bg: 'bg-yellow-500',
    bgLight: 'bg-yellow-50',
    text: 'text-yellow-600',
    icon: 'text-yellow-500'
  }
};

export const StatsCard: React.FC<StatsCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color,
  trend
}) => {
  const colors = colorConfig[color];

  return (
    <div className="bg-white rounded-xl shadow-lg p-6 border border-gray-100 hover:shadow-xl transition-shadow duration-300">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="flex items-center mb-2">
            <div className={`p-2 rounded-lg ${colors.bgLight} mr-3`}>
              <Icon className={`h-6 w-6 ${colors.icon}`} />
            </div>
            <h3 className="text-sm font-medium text-gray-500 uppercase tracking-wider">
              {title}
            </h3>
          </div>
          <div className="flex items-baseline">
            <p className="text-3xl font-bold text-gray-900">{value}</p>
            {trend && (
              <span className={`ml-2 text-sm font-medium ${
                trend.isPositive ? 'text-green-600' : 'text-red-600'
              }`}>
                {trend.isPositive ? '+' : '-'}{Math.abs(trend.value)}%
              </span>
            )}
          </div>
          {subtitle && (
            <p className="text-sm text-gray-500 mt-1">{subtitle}</p>
          )}
        </div>
      </div>
    </div>
  );
};