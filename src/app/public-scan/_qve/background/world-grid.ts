/**
 * Quantum Visualization Engine™ — dot-matrix world map (pure).
 *
 * The hero's backdrop needs a *real* world map, not an abstract blob: the
 * scanner assesses Internet-facing infrastructure, and a recognisable globe is
 * what makes that legible at a glance.
 *
 * Rather than shipping a raster or a heavyweight TopoJSON, landmasses are
 * described here as coarse lon/lat polygons and rasterised into an equirectangular
 * dot grid at module load. That keeps the whole map at a few hundred bytes of
 * source, renders as pure SVG (crisp at any DPI, no network request), and lets
 * the grid density adapt to the viewport.
 *
 * Precision is deliberately low — this is a backdrop, not a cartographic claim.
 */

type Ring = ReadonlyArray<readonly [number, number]>;

/** Coarse continental outlines, [longitude, latitude], degrees. */
const LANDMASSES: readonly Ring[] = [
  // North America
  [
    [-168, 65], [-152, 70], [-130, 70], [-110, 73], [-92, 74], [-80, 70], [-64, 60],
    [-55, 50], [-66, 45], [-70, 42], [-76, 35], [-81, 25], [-90, 29], [-97, 26],
    [-107, 23], [-114, 30], [-124, 40], [-124, 48], [-134, 57], [-150, 59],
  ],
  // Central America
  [[-95, 17], [-88, 21], [-83, 15], [-78, 9], [-84, 8], [-92, 14]],
  // South America
  [
    [-81, 6], [-75, 11], [-60, 11], [-50, 0], [-35, -6], [-38, -16], [-48, -25],
    [-58, -34], [-63, -41], [-70, -53], [-75, -46], [-71, -30], [-70, -18], [-78, -4],
  ],
  // Greenland
  [[-45, 60], [-22, 70], [-20, 82], [-50, 83], [-58, 76], [-55, 66]],
  // Europe
  [
    [-9, 37], [0, 44], [4, 43], [12, 45], [18, 40], [24, 36], [28, 41], [30, 46],
    [40, 46], [46, 55], [32, 61], [28, 70], [16, 69], [5, 60], [-4, 58], [-9, 50],
  ],
  // Africa
  [
    [-17, 15], [-10, 28], [0, 33], [11, 34], [21, 32], [32, 31], [35, 22], [38, 15],
    [43, 11], [51, 12], [43, 0], [40, -11], [35, -21], [32, -29], [25, -34],
    [18, -33], [14, -22], [12, -9], [9, 4], [-5, 5], [-12, 8],
  ],
  // Asia
  [
    [46, 55], [60, 70], [76, 75], [100, 77], [130, 73], [160, 69], [178, 67],
    [172, 60], [158, 57], [140, 50], [130, 43], [127, 35], [121, 30], [122, 23],
    [110, 20], [100, 9], [95, 16], [90, 22], [82, 9], [76, 20], [70, 25], [62, 25],
    [55, 28], [48, 30], [45, 40],
  ],
  // Maritime South-East Asia
  [[96, 5], [108, 2], [118, 5], [126, 2], [132, -3], [122, -9], [106, -7], [98, 1]],
  // Australia
  [
    [113, -22], [121, -18], [131, -12], [142, -11], [148, -20], [153, -28],
    [149, -38], [139, -38], [129, -32], [117, -34],
  ],
  // New Zealand
  [[166, -46], [172, -41], [176, -38], [174, -35], [170, -43]],
  // Japan
  [[130, 31], [136, 34], [141, 40], [145, 44], [141, 36], [134, 33]],
  // British Isles
  [[-10, 51], [-6, 55], [-3, 58], [1, 53], [-2, 50], [-6, 50]],
  // Madagascar
  [[43, -12], [50, -15], [48, -25], [44, -22]],
] as const;

/** Ray-casting point-in-polygon. */
function inRing(lon: number, lat: number, ring: Ring): boolean {
  let inside = false;
  for (let index = 0, previous = ring.length - 1; index < ring.length; previous = index, index += 1) {
    const [x1, y1] = ring[index];
    const [x2, y2] = ring[previous];
    if (lat > Math.min(y1, y2) && lat <= Math.max(y1, y2) && lon <= Math.max(x1, x2) && y1 !== y2) {
      const intersect = ((lat - y1) * (x2 - x1)) / (y2 - y1) + x1;
      if (x1 === x2 || lon <= intersect) inside = !inside;
    }
  }
  return inside;
}

export interface WorldDot {
  /** 0-1 within the map viewBox. */
  u: number;
  v: number;
  /** Distance-from-coast proxy, 0-1 — drives dot opacity for a soft edge. */
  weight: number;
}

/**
 * Rasterise the landmasses into a dot grid.
 *
 * @param columns  horizontal resolution (longitude samples)
 * @param rows     vertical resolution (latitude samples)
 */
export function buildWorldDots(columns = 96, rows = 40): WorldDot[] {
  const dots: WorldDot[] = [];
  const latTop = 80;
  const latBottom = -58;

  for (let row = 0; row < rows; row += 1) {
    const v = row / (rows - 1);
    const lat = latTop + (latBottom - latTop) * v;
    for (let column = 0; column < columns; column += 1) {
      const u = column / (columns - 1);
      const lon = -180 + u * 360;
      if (!LANDMASSES.some((ring) => inRing(lon, lat, ring))) continue;

      // Interior dots are brighter than coastal ones: sample the 4-neighbourhood
      // and use the hit ratio as a cheap interiority measure.
      const step = 360 / columns;
      const neighbours = [
        [lon + step, lat],
        [lon - step, lat],
        [lon, lat + step * 0.7],
        [lon, lat - step * 0.7],
      ].filter(([nLon, nLat]) => LANDMASSES.some((ring) => inRing(nLon, nLat, ring))).length;

      dots.push({ u, v, weight: 0.45 + (neighbours / 4) * 0.55 });
    }
  }

  return dots;
}
