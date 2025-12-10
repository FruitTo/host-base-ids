export type AttackData = {
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  attack_type: string;
  prob: number;
};

export interface ChartDataPoint {
  x: string;
  y: number;
}

export interface AttackStats {
  totalAttacks: number;
  uniqueIPs: number;
  avgProbability: number;
  mostCommonAttack: string;
}