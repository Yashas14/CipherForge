import { useState, useEffect } from 'react';
import { apiGet } from '../lib/api';

export function useHealth() {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const check = async () => {
      try {
        const data = await apiGet('/health');
        setHealth(data);
      } catch {
        setHealth(null);
      }
    };
    check();
    const id = setInterval(check, 10000);
    return () => clearInterval(id);
  }, []);

  return health;
}
