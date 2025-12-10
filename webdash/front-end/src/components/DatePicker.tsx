import React from 'react';
import { Calendar } from 'lucide-react';

interface DatePickerProps {
  // ใช้ ISO เสมอ (YYYY-MM-DD)
  selectedDate: string;
  onDateChange: (isoDate: string) => void;
  loading?: boolean;
}

export const DatePicker: React.FC<DatePickerProps> = ({
  selectedDate,
  onDateChange,
  loading = false
}) => {
  const getTodayISO = (): string => {
    const d = new Date();
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  };

  // แสดงให้คนอ่านแบบ DD-MM-YYYY เฉย ๆ
  const toDisplay = (iso: string): string => {
    const [y, m, d] = iso.split('-');
    return `${d}-${m}-${y}`;
  };

  const inputValue = selectedDate || getTodayISO();

  const handleDateChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const iso = e.target.value; // input type="date" ให้ค่าเป็น YYYY-MM-DD อยู่แล้ว
    if (iso) onDateChange(iso);
  };

  return (
    <div className="flex items-center space-x-2">
      <div className="relative">
        <Calendar className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
        <input
          type="date"
          value={inputValue}
          onChange={handleDateChange}
          disabled={loading}
          className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white disabled:opacity-50 disabled:cursor-not-allowed"
        />
      </div>
      <div className="text-sm text-gray-500">
        Selected: {toDisplay(inputValue)}
      </div>
    </div>
  );
};