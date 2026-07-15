import { Scanner, Profile } from '../types';
import { passiveScanner } from './passive';
import { secretsScanner } from './secrets';
import { zapBaselineScanner, zapActiveScanner, nucleiScanner, nmapScanner, testsslScanner } from './active';
import { authActiveScanner } from './authactive';

// Which scanners run for each profile.
export function scannersFor(profile: Profile): Scanner[] {
  switch (profile) {
    case 'passive':  return [passiveScanner, secretsScanner];
    case 'baseline': return [passiveScanner, secretsScanner, zapBaselineScanner, testsslScanner];
    case 'active':   return [passiveScanner, secretsScanner, authActiveScanner, nucleiScanner, nmapScanner, zapActiveScanner, testsslScanner];
    default:         return [passiveScanner];
  }
}
export const requiresAuthorization = (s: Scanner[]) => s.some(x => x.kind === 'active');
