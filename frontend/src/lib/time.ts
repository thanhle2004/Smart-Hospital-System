const formatNumber = (value: number): string => {
  const normalized = Number.isInteger(value) ? String(value) : value.toFixed(1);
  return normalized.replace(/\.0$/, '');
};

export function formatMinutes(minutes: number): string {
  return `${formatNumber(minutes)} min`;
}

export function formatMinutesFromSeconds(minutes: number): string {
  return formatMinutes(minutes);
}