/**
 * The window sizes this app can actually be opened at.
 *
 * `tauri.conf.json` declares `minWidth: 860, minHeight: 600` and a default of
 * 1280×800, so 860×600 is not a hypothetical — it is a size the user can drag
 * the window to and the app promises to work at. Everything above it is a
 * display someone owns.
 *
 * `dpr` matters independently of size: a 3840×2160 panel at 150% scaling reports
 * 2560×1440 CSS pixels with dpr 1.5, and fractional scaling is where sub-pixel
 * rounding turns a 1px border into a clipped glyph.
 */
export interface Viewport {
  name: string;
  width: number;
  height: number;
  dpr: number;
  why: string;
}

export const VIEWPORTS: Viewport[] = [
  {
    name: 'min-window',
    width: 860,
    height: 600,
    dpr: 1,
    why: 'the declared minWidth/minHeight — the promise',
  },
  {
    name: 'narrow-tall',
    width: 900,
    height: 1200,
    dpr: 1,
    why: 'half a portrait monitor; sidebar + grid at their tightest',
  },
  {
    name: 'laptop-1366',
    width: 1366,
    height: 768,
    dpr: 1,
    why: 'still the most common laptop panel; short vertically',
  },
  {
    name: 'default-1280',
    width: 1280,
    height: 800,
    dpr: 1,
    why: 'the size the app opens at on first run',
  },
  { name: 'fhd', width: 1920, height: 1080, dpr: 1, why: 'the common desktop' },
  {
    name: 'fhd-scaled-125',
    width: 1536,
    height: 864,
    dpr: 1.25,
    why: 'FHD at 125% — fractional scaling, sub-pixel rounding',
  },
  {
    name: 'qhd',
    width: 2560,
    height: 1440,
    dpr: 1,
    why: 'wide layouts; catches grids that stop filling',
  },
  {
    name: '4k-scaled-150',
    width: 2560,
    height: 1440,
    dpr: 1.5,
    why: '4K at 150%, the usual 4K desktop setup',
  },
  {
    name: 'ultrawide',
    width: 3440,
    height: 1440,
    dpr: 1,
    why: '21:9 — where auto-fill grids and max-widths show up',
  },
];
