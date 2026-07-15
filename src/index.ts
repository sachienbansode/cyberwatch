import { createApp } from './api';
import { startWorker } from './worker';
import { config } from './config';

const app = createApp();
app.listen(config.port, () => {
  console.log(`[api] AntShield VAPT service on :${config.port}  (active scans: ${config.activeScansEnabled ? 'ENABLED' : 'disabled'})`);
});
startWorker();
