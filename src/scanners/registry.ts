import { Scanner, Profile } from '../types';
import { passiveScanner } from './passive';
import { zapBaselineScanner, zapActiveScanner, nucleiScanner, nmapScanner, testsslScanner } from './active';
import { authActiveScanner } from './authactive';

// Which scanners run for each profile.
export function scannersFor(profile: Profile): Scanner[] {
  switch (profile) {
    case 'passive':  return [passiveScanner];
    case 'baseline': return [passiveScanner, zapBaselineScanner, testsslScanner];
    case 'active':   return [passiveScanner, authActiveScanner, nucleiScanner, nmapScanner, zapActiveScanner, testsslScanner];
    default:         return [passiveScanner];
  }
}
export const requiresAuthorization = (s: Scanner[]) => s.some(x => x.kind === 'active');
