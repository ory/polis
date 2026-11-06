import packageInfo from '../package.json';
import { initializeMetrics } from '@boxyhq/metrics';

const g = global as any;

if (!g.metricsInit) {
  initializeMetrics({ name: packageInfo.name, version: packageInfo.version });
  g.metricsInit = true;
}
