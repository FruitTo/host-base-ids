import React from 'react';

interface ChartCardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
}

export const ChartCard: React.FC<ChartCardProps> = ({
  title,
  children,
  className = ''
}) => {
  return (
    <div className={`bg-white rounded-xl shadow-lg border border-gray-100 hover:shadow-xl transition-shadow duration-300 ${className}`}>
      <div className="p-6 border-b border-gray-100">
        <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
      </div>
      <div className="p-6">
        {children}
      </div>
    </div>
  );
};