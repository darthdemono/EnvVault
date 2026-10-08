import { describe, expect, it, beforeEach } from 'vitest';
import { loadRealIndexHtml } from './helpers';
import { hideWifiQr, qrSvg, showWifiQr } from '../src/ts/wifi-qr';

describe('Wi-Fi QR', () => {
  beforeEach(() => loadRealIndexHtml());

  it('draws an SVG locally and never puts the input text into it', () => {
    const uri = 'WIFI:T:WPA;S:Home;P:hunter2-passphrase;;';
    const svg = qrSvg(uri);
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).not.toContain('hunter2');
    expect(qrSvg('WIFI:T:WPA;S:Other;P:x;;')).not.toBe(svg);
  });

  it('an over-long payload throws instead of drawing a wrong code', () => {
    expect(() => qrSvg('x'.repeat(4000))).toThrow();
  });

  it('shows in a named modal dialog and empties the document when closed', () => {
    showWifiQr('WIFI:T:WPA;S:Home;P:secret;;', 'Home');
    const overlay = document.getElementById('wifi-qr-overlay')!;
    expect(overlay.classList.contains('open')).toBe(true);
    expect(overlay.getAttribute('role')).toBe('dialog');
    expect(overlay.getAttribute('aria-modal')).toBe('true');
    expect(document.querySelector('#wifi-qr-body svg')?.getAttribute('aria-label')).toContain(
      'Home',
    );
    hideWifiQr();
    expect(overlay.classList.contains('open')).toBe(false);
    expect(document.getElementById('wifi-qr-body')!.innerHTML).toBe('');
  });
});
