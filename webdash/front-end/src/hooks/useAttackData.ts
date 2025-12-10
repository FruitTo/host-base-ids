import { useState, useEffect, useCallback } from 'react';
import { AttackData, AttackStats } from '../types/attack';

const API_URL = 'http://localhost:3000/alert';
const REFRESH_INTERVAL = 30000; // 30 seconds

export const useAttackData = (selectedDate?: string) => {
  const [data, setData] = useState<AttackData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Build URL with date parameter if provided
      const url = new URL(API_URL);
      if (selectedDate) {
        url.searchParams.append('date', selectedDate);
      }

      const response = await fetch(url.toString());

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const attackData: AttackData[] = await response.json();

      // Validate data structure
      if (!Array.isArray(attackData)) {
        throw new Error('Invalid data format: expected array');
      }

      // ✅ รีเซ็ตเมื่อไม่พบข้อมูล
      if (attackData.length === 0) {
        setData([]);
        setLastUpdated(null);
        setError('No data found for this date');
      } else {
        setData(attackData);
        setLastUpdated(new Date());
      }
    } catch (err) {
      // ✅ รีเซ็ตเมื่อเกิด error
      setData([]);
      setLastUpdated(null);
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
      console.error('Failed to fetch attack data:', err);
    } finally {
      setLoading(false);
    }
  }, [selectedDate]);

  const getStats = useCallback((): AttackStats => {
    if (data.length === 0) {
      return {
        totalAttacks: 0,
        uniqueIPs: 0,
        avgProbability: 0,
        mostCommonAttack: 'N/A',
      };
    }

    const uniqueIPs = new Set(data.map((attack) => attack.src_ip)).size;
    const avgProbability =
      data.reduce((sum, attack) => sum + attack.prob, 0) / data.length;

    // Find most common attack type
    const attackTypeCounts = data.reduce((acc, attack) => {
      acc[attack.attack_type] = (acc[attack.attack_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const mostCommonAttack = Object.entries(attackTypeCounts).reduce(
      (a, b) => (a[1] > b[1] ? a : b),
      ['N/A', 0] as [string, number]
    )[0];

    return {
      totalAttacks: data.length,
      uniqueIPs,
      avgProbability,
      mostCommonAttack,
    };
  }, [data]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

  return {
    data,
    loading,
    error,
    lastUpdated,
    stats: getStats(),
    refetch: fetchData,
  };
};