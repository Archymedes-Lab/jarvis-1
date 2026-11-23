// ARGUS-INSTINCT world watch, drawn from /api/world.
//
// What in the scene carries meaning:
//   land          a dot per 0.75 degree cell of land (Natural Earth), with
//                 country outlines. It carries no data.
//   report dot    one per place that reports name. Red = newsroom article,
//                 amber = newsroom video, grey = GDELT machine-coded event.
//                 Larger = more reports there. A hollow ring is a report that
//                 names only a country: it sits at the country's label point,
//                 not at the place it happened.
//   pulse         a dot pulses only while its newest report is under three
//                 hours old; a zone's bracket pulses only while its reports in
//                 the last day clearly exceed the day before. Nothing else
//                 moves by itself. The globe turns only if Rotate is switched on.
//   focus         with a place or zone pinned, everything outside it dims.
//   zone          an outline around a cluster of located reports from several
//                 publishers. It is where reports cluster, not a front line.
//   teal marker   this device or a trusted zone, as ARGUS-INSTINCT knows it locally,
//                 and an arc to the nearest zone with the distance.
//
// The page talks to this origin only. Report links open in a new tab when the
// owner clicks one; nothing is fetched from a publisher by the page itself.
// All feed text is written with textContent, never parsed as markup.
//
// When the data is old or ARGUS-INSTINCT stops answering, the colour drains, pulses
// stop and the banner says so.
//
// The design was ranked with Jev (scripts/reviews/world_view_design.py). It
// put the hover card, place search and focus dimming first, and scored a
// day/night terminator and a constant turn as things the reports do not
// carry, so the first was removed and the second is off until asked for.
import * as THREE from '/static/vendor/three.module.min.js';

THREE.ColorManagement.enabled = false;

const R = 100;                       // globe radius in scene units
const FRESH_S = 3 * 3600;
const POLL_MS = 60000;
const HOME = { lon: 20, lat: 15, dist: 400 };
const COLORS = { news: 0xff5a4e, video: 0xffb648, event: 0x8fa3c8, zone: 0xff7a45, me: 0x39e6c8, hud: 0x5fd4ff };
const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
};

// -- state ---------------------------------------------------------------------
const layers = { news: true, video: true, zones: true, events: false };
const view = { lon: HOME.lon, lat: HOME.lat, dist: HOME.dist, flat: 0, eased: 0, flatTarget: 0, spin: false, idleAt: 0 };
let data = null;                     // last /api/world payload
let spots = [];                      // visible places, each with its reports
let zones = [];                      // visible zones
let asOf = null;                     // null = now, else epoch seconds
let hover = null, pinned = null;     // {type: 'spot'|'zone', ref}
let fly = null, playing = null;
let clockSkew = 0;                   // server time minus this clock

// -- projection, shared by shaders and by picking ------------------------------
const PROJECT = `
uniform float uFlat;
uniform vec4 uFocus;                 // lon, lat, radius in degrees, on
const float R = ${R.toFixed(1)};
vec3 onSphere(vec2 ll, float alt) {
  float lon = radians(ll.x), lat = radians(ll.y), r = R + alt;
  return vec3(r * cos(lat) * sin(lon), r * sin(lat), r * cos(lat) * cos(lon));
}
vec3 project(vec3 lla) {
  vec3 sheet = vec3(radians(lla.x) * R, radians(lla.y) * R, lla.z);
  return mix(onSphere(lla.xy, lla.z), sheet, uFlat);
}
// 0 inside the pinned place or zone, rising to 1 outside it.
float outsideFocus(vec2 ll) {
  vec3 a = normalize(onSphere(ll, 0.0)), b = normalize(onSphere(uFocus.xy, 0.0));
  float angle = degrees(acos(clamp(dot(a, b), -1.0, 1.0)));
  return uFocus.w * smoothstep(uFocus.z, uFocus.z * 2.2 + 2.0, angle);
}`;
const RAD = Math.PI / 180;
function project(lon, lat, alt, out) {
  const r = R + alt, cl = Math.cos(lat * RAD);
  const sx = r * cl * Math.sin(lon * RAD), sy = r * Math.sin(lat * RAD), sz = r * cl * Math.cos(lon * RAD);
  const f = view.eased;
  return out.set(sx + (lon * RAD * R - sx) * f, sy + (lat * RAD * R - sy) * f, sz + (alt - sz) * f);
}

const U = {
  uFlat: { value: 0 }, uTime: { value: 0 }, uPx: { value: 1 }, uLive: { value: 0 },
  uFocus: { value: new THREE.Vector4(0, 0, 1, 0) },
};

// -- renderer --------------------------------------------------------------------
const canvas = $('scene');
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false, powerPreference: 'high-performance' });
renderer.setClearColor(0x02050b, 1);
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(38, 1, 1, 4000);

function resize() {
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  renderer.setPixelRatio(ratio);
  renderer.setSize(window.innerWidth, window.innerHeight, false);
  camera.aspect = window.innerWidth / window.innerHeight;
  // Sit the globe in the space the panels leave: right of the lists, above the timeline.
  const wide = window.innerWidth > 900;
  camera.setViewOffset(window.innerWidth, window.innerHeight, wide ? -110 : 0, wide ? 34 : 0,
    window.innerWidth, window.innerHeight);
  camera.updateProjectionMatrix();
  U.uPx.value = ratio;
}
window.addEventListener('resize', resize);
resize();

function material(vertex, fragment, extra = {}, options = {}) {
  return new THREE.ShaderMaterial({
    uniforms: { ...U, ...extra }, vertexShader: PROJECT + vertex, fragmentShader: fragment,
    transparent: true, depthWrite: false, ...options,
  });
}
function geometry(lla, attributes = {}) {
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(lla), 3));
  for (const [name, [array, size]] of Object.entries(attributes)) {
    geo.setAttribute(name, new THREE.BufferAttribute(new Float32Array(array), size));
  }
  return geo;
}
function add(object) { object.frustumCulled = false; scene.add(object); return object; }
function replace(old, object) {
  if (old) { scene.remove(old); old.geometry.dispose(); }
  return object ? add(object) : null;
}

// The globe's body: dark glass with a lit rim. It also hides the far side.
const core = add(new THREE.Mesh(
  new THREE.SphereGeometry(R * 0.994, 96, 64),
  new THREE.ShaderMaterial({
    uniforms: U,
    vertexShader: `varying vec3 vN; varying vec3 vV;
      void main() { vec4 mv = modelViewMatrix * vec4(position, 1.0); vN = normalize(normalMatrix * normal);
        vV = normalize(-mv.xyz); gl_Position = projectionMatrix * mv; }`,
    fragmentShader: `varying vec3 vN; varying vec3 vV;
      void main() { float rim = pow(1.0 - max(dot(vN, vV), 0.0), 3.0);
        gl_FragColor = vec4(vec3(0.012, 0.03, 0.065) + vec3(0.10, 0.36, 0.52) * rim, 1.0); }`,
  })));
const halo = add(new THREE.Mesh(
  new THREE.SphereGeometry(R * 1.25, 64, 48),
  new THREE.ShaderMaterial({
    uniforms: U, side: THREE.BackSide, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    vertexShader: `varying vec3 vN; varying vec3 vV;
      void main() { vec4 mv = modelViewMatrix * vec4(position, 1.0); vN = normalize(normalMatrix * normal);
        vV = normalize(-mv.xyz); gl_Position = projectionMatrix * mv; }`,
    fragmentShader: `uniform float uFlat; varying vec3 vN; varying vec3 vV;
      void main() { float a = pow(max(dot(-vN, vV), 0.0), 3.0) * 0.7 * (1.0 - uFlat);
        gl_FragColor = vec4(0.22, 0.62, 0.95, a); }`,
  })));

const LINE_VERT = `attribute float aWrap; varying float vWrap; varying float vOut;
  void main() { vWrap = aWrap; vOut = outsideFocus(position.xy); gl_Position = projectionMatrix * modelViewMatrix * vec4(project(position), 1.0); }`;
const lineMaterial = (color, alpha) => material(LINE_VERT,
  `uniform vec3 uColor; uniform float uAlpha; uniform float uFlat; varying float vWrap; varying float vOut;
   void main() { gl_FragColor = vec4(uColor, uAlpha * (1.0 - 0.7 * vOut) * (1.0 - vWrap * step(0.02, uFlat))); }`,
  { uColor: { value: new THREE.Color(color) }, uAlpha: { value: alpha } });

// Segments from a lon/lat path. A step across the antimeridian is marked so
// the flat map does not draw it as a line across the whole sheet.
function segments(paths, alt) {
  const lla = [], wrap = [];
  for (const path of paths) {
    for (let i = 0; i + 1 < path.length; i++) {
      const a = path[i], b = path[i + 1], w = Math.abs(a[0] - b[0]) > 180 ? 1 : 0;
      lla.push(a[0], a[1], a[2] ?? alt, b[0], b[1], b[2] ?? alt);
      wrap.push(w, w);
    }
  }
  return geometry(lla, { aWrap: [wrap, 1] });
}

function graticule() {
  const paths = [];
  for (let lon = -180; lon <= 180; lon += 30) {
    const path = []; for (let lat = -84; lat <= 84; lat += 3) path.push([lon, lat]); paths.push(path);
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const path = []; for (let lon = -180; lon <= 180; lon += 3) path.push([lon, lat]); paths.push(path);
  }
  return add(new THREE.LineSegments(segments(paths, 0.05), lineMaterial(COLORS.hud, 0.07)));
}
graticule();

function buildWorld(world) {
  const paths = world.borders.map((flat) => {
    const path = []; for (let i = 0; i < flat.length; i += 2) path.push([flat[i], flat[i + 1]]); return path;
  });
  add(new THREE.LineSegments(segments(paths, 0.12), lineMaterial(COLORS.hud, 0.34)));

  const { w, h, bits } = world.mask;
  const raw = atob(bits), lla = [];
  for (let row = 0; row < h; row++) {
    const lat = 90 - (row + 0.5) * 180 / h;
    // Fewer columns toward the poles, so dots are evenly spaced on the sphere.
    const every = Math.max(1, Math.round(1 / Math.max(Math.cos(lat * RAD), 0.05)));
    for (let col = 0; col < w; col += every) {
      const index = row * w + col;
      if (raw.charCodeAt(index >> 3) & (1 << (index & 7))) lla.push(-180 + (col + 0.5) * 360 / w, lat, 0.1);
    }
  }
  add(new THREE.Points(geometry(lla), material(
    `uniform float uPx; varying float vOut;
     void main() { vec3 p = project(position); vec4 mv = modelViewMatrix * vec4(p, 1.0);
       vOut = outsideFocus(position.xy);
       gl_Position = projectionMatrix * mv; gl_PointSize = clamp(uPx * 520.0 / -mv.z, 1.4 * uPx, 3.4 * uPx); }`,
    `varying float vOut;
     void main() { float d = length(gl_PointCoord - 0.5); if (d > 0.5) discard;
       gl_FragColor = vec4(0.40, 0.72, 0.96, smoothstep(0.5, 0.25, d) * 0.85 * (1.0 - 0.7 * vOut)); }`)));
}

// Faint fixed stars for depth on the globe; they fade as the map unfolds.
(function stars() {
  const pos = [];
  let seed = 7;
  const rand = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  for (let i = 0; i < 900; i++) {
    const z = rand() * 2 - 1, a = rand() * 2 * Math.PI, r = Math.sqrt(1 - z * z);
    pos.push(1800 * r * Math.cos(a), 1800 * z, 1800 * r * Math.sin(a));
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(pos), 3));
  add(new THREE.Points(geo, new THREE.ShaderMaterial({
    uniforms: U, transparent: true, depthWrite: false,
    vertexShader: `uniform float uPx; void main() { gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); gl_PointSize = 1.6 * uPx; }`,
    fragmentShader: `uniform float uFlat; void main() { gl_FragColor = vec4(0.62, 0.74, 0.95, 0.5 * (1.0 - uFlat)); }`,
  })));
})();

// -- report dots -------------------------------------------------------------------
const DOT_VERT = `attribute vec3 aColor; attribute vec4 aInfo; uniform float uPx;
  varying vec3 vColor; varying vec4 vInfo; varying float vOut;
  void main() { vColor = aColor; vInfo = aInfo; vOut = outsideFocus(position.xy);
    gl_Position = projectionMatrix * modelViewMatrix * vec4(project(position), 1.0);
    gl_PointSize = aInfo.x * uPx * 3.0; }`;
// aInfo: x radius in px, y shape (0 disc, 1 ring, 2 diamond), z fresh (pulses), w emphasis.
const DOT_FRAG = `uniform float uTime; uniform float uLive; varying vec3 vColor; varying vec4 vInfo; varying float vOut;
  void main() {
    vec2 c = (gl_PointCoord - 0.5) * 6.0;        // the dot itself has radius 1
    float d = vInfo.y > 1.5 ? abs(c.x) + abs(c.y) : length(c);
    float body = vInfo.y > 0.5 && vInfo.y < 1.5
      ? smoothstep(1.0, 0.86, d) * smoothstep(0.52, 0.66, d)
      : smoothstep(1.0, 0.8, d);
    float glow = exp(-d * 1.3) * 0.6;
    float t = fract(uTime * 0.45);
    float wave = vInfo.z * uLive * (1.0 - t) * smoothstep(0.16, 0.0, abs(d - (1.0 + 1.9 * t)));
    float a = max(body, glow * (0.5 + vInfo.w)) + wave * 0.9;
    if (a < 0.01) discard;
    float heart = vInfo.y < 0.5 ? smoothstep(0.45, 0.0, d) * 0.55 : 0.0;
    gl_FragColor = vec4(mix(vColor, vec3(1.0), heart + vInfo.w * 0.2), a * (1.0 - 0.75 * vOut));
  }`;
const dotMaterial = material(DOT_VERT, DOT_FRAG);
const zoneLineMaterial = lineMaterial(COLORS.zone, 0.95), arcMaterial = lineMaterial(COLORS.me, 0.55);
const zoneFillMaterial = material(
  `void main() { gl_Position = projectionMatrix * modelViewMatrix * vec4(project(position), 1.0); }`,
  `void main() { gl_FragColor = vec4(1.0, 0.48, 0.27, 0.13); }`, {}, { side: THREE.DoubleSide });
let dots = null, zoneLines = null, zoneFill = null, anchorDots = null, arcs = null;

const RETICLE_FRAG = `uniform float uTime; uniform float uLive; varying vec3 vColor; varying vec4 vInfo; varying float vOut;
  void main() {
    vec2 c = (gl_PointCoord - 0.5) * 2.0; float d = length(c);
    float ring = smoothstep(0.05, 0.0, abs(d - 0.62));
    float tick = step(abs(min(abs(c.x), abs(c.y))), 0.035) * step(0.74, d) * step(d, 0.98);
    // vInfo.z marks a zone whose reporting is rising: only that one breathes.
    float breathe = 1.0 - 0.5 * vInfo.z * uLive * (0.5 + 0.5 * sin(uTime * 3.2));
    float a = max(ring, tick) * (0.55 + 0.45 * vInfo.w) * breathe * (1.0 - 0.75 * vOut);
    if (a < 0.01) discard;
    gl_FragColor = vec4(vColor, a);
  }`;
const reticleMaterial = material(DOT_VERT, RETICLE_FRAG, {}, { depthTest: false });
const beaconMaterial = material(DOT_VERT, RETICLE_FRAG);
let reticle = null, beacons = null;

function now() { return Date.now() / 1000 + clockSkew; }
function horizon() { return asOf == null ? now() : asOf; }

function shown(item) {
  if (item.precision === 'unmapped' || item.ts > horizon()) return false;
  if (item.kind === 'event') return layers.events || (layers.zones && item.corroborated === true);
  return layers[item.kind];
}

function rebuild() {
  const groups = new Map();
  for (const item of (data ? data.items : [])) {
    if (!shown(item)) continue;
    const key = `${item.lat.toFixed(1)},${item.lon.toFixed(1)},${item.precision === 'country' ? 'c' : 'p'}`;
    let spot = groups.get(key);
    if (!spot) groups.set(key, spot = { key, lat: item.lat, lon: item.lon, items: [], country: item.precision === 'country' });
    spot.items.push(item);
  }
  spots = [...groups.values()];
  const lla = [], color = [], info = [];
  const t = horizon();
  for (const spot of spots) {
    spot.items.sort((a, b) => b.ts - a.ts);
    const kinds = new Set(spot.items.map((i) => i.kind));
    spot.kind = kinds.has('news') ? 'news' : kinds.has('video') ? 'video' : 'event';
    spot.fresh = t - spot.items[0].ts < FRESH_S && asOf == null;
    spot.radius = (spot.kind === 'event' ? 3.2 : 5.5) + 2.6 * Math.log2(spot.items.length);
    spot.alt = 0.6;
    const c = new THREE.Color(COLORS[spot.kind]);
    lla.push(spot.lon, spot.lat, spot.alt);
    color.push(c.r, c.g, c.b);
    info.push(Math.min(spot.radius, 18), spot.country ? 1 : 0, spot.fresh ? 1 : 0, 0);
  }
  dots = replace(dots, spots.length
    ? new THREE.Points(geometry(lla, { aColor: [color, 3], aInfo: [info, 4] }), dotMaterial) : null);

  zones = (data && layers.zones && asOf == null) ? data.zones : [];
  const outline = [], fill = [];
  for (const zone of zones) {
    const ring = densify(zone.polygon);
    outline.push([...ring, ring[0]]);
    for (let i = 0; i < ring.length; i++) {
      const a = ring[i], b = ring[(i + 1) % ring.length];
      if (Math.abs(a[0] - b[0]) > 180 || Math.abs(a[0] - zone.lon) > 180 || Math.abs(b[0] - zone.lon) > 180) continue;
      fill.push(zone.lon, zone.lat, 0.3, a[0], a[1], 0.3, b[0], b[1], 0.3);
    }
  }
  zoneLines = replace(zoneLines, zones.length
    ? new THREE.LineSegments(segments(outline, 0.35), zoneLineMaterial) : null);
  zoneFill = replace(zoneFill, fill.length ? new THREE.Mesh(geometry(fill), zoneFillMaterial) : null);
  // A zone's outline is a few pixels wide from orbit, so each also gets a
  // bracket of fixed screen size, larger for more reports.
  const zc = new THREE.Color(COLORS.zone), bl = [], bc = [], bi = [];
  for (const zone of zones) {
    bl.push(zone.lon, zone.lat, 0.8); bc.push(zc.r, zc.g, zc.b);
    bi.push(Math.min(16 + 2.5 * Math.log2(zone.reports), 30), 0, rising(zone) ? 1 : 0, 0.7);
  }
  beacons = replace(beacons, zones.length
    ? new THREE.Points(geometry(bl, { aColor: [bc, 3], aInfo: [bi, 4] }), beaconMaterial) : null);

  buildAnchors();
  renderLists();
  renderTags();
  mark();
}

// Extra points along each edge so an outline follows the sphere.
function densify(polygon) {
  const out = [];
  for (let i = 0; i < polygon.length; i++) {
    const a = polygon[i], b = polygon[(i + 1) % polygon.length];
    let dlon = b[0] - a[0];
    if (dlon > 180) dlon -= 360; else if (dlon < -180) dlon += 360;
    const steps = Math.max(1, Math.ceil(Math.max(Math.abs(dlon), Math.abs(b[1] - a[1])) / 1.5));
    for (let s = 0; s < steps; s++) {
      let lon = a[0] + dlon * s / steps;
      if (lon > 180) lon -= 360; else if (lon < -180) lon += 360;
      out.push([lon, a[1] + (b[1] - a[1]) * s / steps]);
    }
  }
  return out;
}

function greatCircle(a, b, lift) {
  const va = new THREE.Vector3(), vb = new THREE.Vector3(), v = new THREE.Vector3();
  const unit = (p, out) => out.set(Math.cos(p.lat * RAD) * Math.sin(p.lon * RAD), Math.sin(p.lat * RAD),
    Math.cos(p.lat * RAD) * Math.cos(p.lon * RAD));
  unit(a, va); unit(b, vb);
  const angle = va.angleTo(vb), path = [];
  if (angle < 1e-4) return path;
  for (let i = 0; i <= 64; i++) {
    const t = i / 64, s = Math.sin(angle);
    v.copy(va).multiplyScalar(Math.sin((1 - t) * angle) / s).addScaledVector(vb, Math.sin(t * angle) / s);
    path.push([Math.atan2(v.x, v.z) / RAD, Math.asin(Math.max(-1, Math.min(1, v.y))) / RAD,
      0.5 + lift * Math.sin(Math.PI * t)]);
  }
  return path;
}

function buildAnchors() {
  const anchors = data ? data.anchors : [];
  const lla = [], color = [], info = [], paths = [];
  const c = new THREE.Color(COLORS.me);
  for (const anchor of anchors) {
    lla.push(anchor.lon, anchor.lat, 0.9);
    color.push(c.r, c.g, c.b);
    info.push(anchor.kind === 'device' ? 5.5 : 4, 2, 0, 0.6);
  }
  // One arc, from the device (or else the first trusted zone) to its nearest zone.
  const from = anchors.find((a) => a.kind === 'device') || anchors[0];
  const zone = from && from.nearest && asOf == null && layers.zones
    ? (data.zones.find((z) => z.id === from.nearest.zone)) : null;
  if (zone && !from.nearest.inside) paths.push(greatCircle(from, zone, Math.min(18, from.nearest.distance_km / 400)));
  anchorDots = replace(anchorDots, lla.length
    ? new THREE.Points(geometry(lla, { aColor: [color, 3], aInfo: [info, 4] }), dotMaterial) : null);
  arcs = replace(arcs, paths.length && paths[0].length
    ? new THREE.LineSegments(segments(paths, 0.5), arcMaterial) : null);
  arcs && (arcs.userData = { from, zone, mid: paths[0][32] });
}

function mark() {
  const lla = [], color = [], info = [];
  const push = (target, strong) => {
    if (!target) return;
    const p = target.type === 'spot' ? target.ref : { lon: target.ref.lon, lat: target.ref.lat, radius: 22 };
    const c = new THREE.Color(target.type === 'zone' ? COLORS.zone : COLORS.hud);
    lla.push(p.lon, p.lat, 1.0);
    color.push(c.r, c.g, c.b);
    info.push(Math.min(p.radius || 6, 18) * 1.25 + 5, 0, 0, strong ? 1 : 0);
  };
  push(pinned, true);
  if (hover && !(pinned && pinned.ref === hover.ref)) push(hover, false);
  reticle = replace(reticle, lla.length
    ? new THREE.Points(geometry(lla, { aColor: [color, 3], aInfo: [info, 4] }), reticleMaterial) : null);
}

// -- text ---------------------------------------------------------------------------
function ago(ts) {
  const s = Math.max(0, now() - ts);
  if (s < 90) return 'just now';
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
const PRECISION = {
  city: ['City', 'Placed at the city the report names.'],
  region: ['Region', 'Placed at the centre of the region the report names.'],
  country: ['Country-level', 'The report names only a country. The ring is at the country\'s label point, not where it happened.'],
};
function reportNode(item, compact) {
  const row = el('div', 'rep');
  const head = compact ? el('span') : el('a');
  head.textContent = (item.kind === 'video' ? '▶ ' : '') + item.title;
  if (!compact) { head.href = item.url; head.target = '_blank'; head.rel = 'noopener noreferrer'; }
  row.append(head);
  if (!compact && item.summary) row.append(el('p', null, item.kind === 'event' ? `Link text: ${item.summary}` : item.summary));
  const kind = item.kind === 'event' ? 'GDELT, from ' : item.kind === 'video' ? 'video, ' : '';
  row.append(el('small', null, `${kind}${item.source} · ${ago(item.ts)}`));
  return row;
}
function describeSpot(spot, compact) {
  const frag = document.createDocumentFragment();
  const first = spot.items[0];
  frag.append(el('div', 'title', first.country && first.country !== first.place ? `${first.place}, ${first.country}` : first.place));
  const badges = el('div');
  badges.append(el('span', spot.country ? 'badge warn' : 'badge', PRECISION[first.precision][0]));
  if (spot.items.some((i) => i.ambiguous)) badges.append(el('span', 'badge warn', 'Name is shared'));
  frag.append(badges);
  const publishers = new Set(spot.items.map((i) => i.source)).size;
  frag.append(el('div', 'meta', `${spot.items.length} report${spot.items.length > 1 ? 's' : ''} · `
    + `${publishers} publisher${publishers > 1 ? 's' : ''} · latest ${ago(first.ts)}`));
  for (const item of spot.items.slice(0, compact ? 3 : 40)) frag.append(reportNode(item, compact));
  if (!compact) {
    frag.append(el('div', 'caveat', PRECISION[first.precision][1]));
    if (spot.items.some((i) => i.ambiguous)) {
      frag.append(el('div', 'caveat', 'More than one place has this name and the report does not name the country; the largest was used.'));
    }
    if (spot.items.some((i) => i.kind === 'event')) {
      frag.append(el('div', 'caveat', 'GDELT events are coded by machine from articles, including places an article only mentions. Treat their positions as unverified.'));
    }
  } else if (spot.items.length > 3) {
    frag.append(el('div', 'hint', `+${spot.items.length - 3} more · click to pin`));
  } else {
    frag.append(el('div', 'hint', 'click to pin'));
  }
  return frag;
}
// Feeds carry about a day of items, so a day-on-day comparison means something
// only once ARGUS-INSTINCT has itself collected for the whole two-day window.
function rising(zone) { return data.trend_ready && zone.last_24h > zone.prior_24h * 1.5 + 1; }
function trend(zone) {
  if (!data.trend_ready) return 'trend after two days of collecting';
  if (rising(zone)) return 'reporting is rising';
  if (zone.prior_24h > zone.last_24h * 1.5 + 1) return 'reporting is easing';
  return 'reporting is steady';
}
function describeZone(zone, compact) {
  const frag = document.createDocumentFragment();
  frag.append(el('div', 'title', zone.name));
  const badges = el('div');
  badges.append(el('span', 'badge', 'Report cluster'));
  frag.append(badges);
  frag.append(el('div', 'meta', `${zone.reports} located reports (${zone.newsroom} newsroom, `
    + `${zone.reports - zone.newsroom} machine-coded) from ${zone.sources} publishers in 48 h · `
    + `about ${zone.radius_km} km across its widest half · latest ${ago(zone.last_ts)}`));
  frag.append(el('div', 'meta', `Last 24 h: ${zone.last_24h} · the 24 h before: ${zone.prior_24h} · ${trend(zone)}`));
  if (!compact) {
    // Reports per six hours over the zone's two days, oldest on the left.
    const chart = el('div', 'hist'), top = Math.max(1, ...zone.history);
    for (const n of zone.history) { const bar = el('i'); bar.style.height = `${Math.max(4, 100 * n / top)}%`; bar.title = `${n} reports`; chart.append(bar); }
    frag.append(chart, el('div', 'histaxis', '48 h ago · reports per 6 h · now'));
    if (!data.trend_ready) frag.append(el('div', 'caveat', 'ARGUS-INSTINCT has collected for less than two days. Older bars hold only what the feeds still carried, so they undercount.'));
  }
  frag.append(el('div', 'meta', `Places named: ${zone.places.join(', ')}`));
  if (!compact) {
    const byId = new Map(data.items.map((i) => [i.id, i]));
    for (const id of zone.items) { const item = byId.get(id); if (item) frag.append(reportNode(item, false)); }
    frag.append(el('div', 'caveat', data.rules.note));
    frag.append(el('div', 'caveat', `Rule: ${data.rules.zone}. Machine-coded events count only near a newsroom report.`));
  } else {
    frag.append(el('div', 'hint', 'click to pin'));
  }
  return frag;
}
function describe(target, compact) {
  return target.type === 'spot' ? describeSpot(target.ref, compact) : describeZone(target.ref, compact);
}

function renderLists() {
  const zl = $('zlist'), ll = $('llist');
  zl.replaceChildren(); ll.replaceChildren();
  if (!data) return;
  const all = data.zones;
  if (!all.length) zl.append(el('div', 'empty', data.generated_at ? 'No cluster of reports meets the zone rule right now.' : 'No reports collected yet.'));
  const top = Math.max(1, ...all.map((z) => z.reports));
  for (const zone of all) {
    const row = el('button', 'zrow');
    const head = el('b'); head.append(zone.name, el('span', 'num', String(zone.reports)));
    const bar = el('div', 'zbar'); const fill = el('i'); fill.style.width = `${100 * zone.reports / top}%`; bar.append(fill);
    row.append(head, el('small', null, `${zone.sources} publishers · ${trend(zone)}`), bar);
    row.addEventListener('click', () => { pin({ type: 'zone', ref: zone }); go(zone.lon, zone.lat, 210); });
    zl.append(row);
  }
  const latest = data.items.filter((i) => i.kind !== 'event').slice(0, 14);
  for (const item of latest) {
    const row = el('button', 'lrow');
    const dot = el('span', `dot ${item.kind}`);
    row.append(dot, item.title, el('small', null,
      `${item.source} · ${ago(item.ts)} · ${item.precision === 'unmapped' ? 'place not established' : item.place}`));
    row.addEventListener('click', () => {
      if (item.precision === 'unmapped') return;
      const spot = spots.find((s) => s.items.includes(item));
      if (spot) pin({ type: 'spot', ref: spot });
      go(item.lon, item.lat, 210);
    });
    ll.append(row);
  }
  const near = $('near'); near.replaceChildren();
  const anchor = data.anchors.find((a) => a.kind === 'device') || data.anchors[0];
  if (!anchor) near.append('No device position or trusted zone is set, so no distance is shown. Set one in GeoSecurity.');
  else if (!anchor.nearest) near.append(`${anchor.name}: no zone to measure to.`);
  else if (anchor.nearest.inside) { near.append(`${anchor.name} is `, el('b', null, 'inside'), ` the ${anchor.nearest.name} report cluster.`); }
  else { near.append(`Nearest zone to ${anchor.name}: `, el('b', 'num', `${anchor.nearest.distance_km.toLocaleString()} km`), ` · ${anchor.nearest.name}`); }
}

const tags = $('tags');
let tagNodes = [];
function renderTags() {
  tags.replaceChildren(); tagNodes = [];
  for (const zone of zones.slice(0, 10)) {
    const node = el('div', 'tag', zone.name);
    tags.append(node); tagNodes.push({ node, lon: zone.lon, lat: zone.lat, alt: 1 });
  }
  const named = [];
  for (const anchor of (data ? data.anchors : [])) {
    // A trusted zone the device is sitting in shares the device's tag.
    const twin = named.find((a) => Math.abs(a.lat - anchor.lat) < 0.05 && Math.abs(a.lon - anchor.lon) < 0.05);
    if (twin) { twin.node.textContent += ` · ${anchor.name}`; continue; }
    const node = el('div', 'tag me', anchor.name);
    named.push({ lat: anchor.lat, lon: anchor.lon, node });
    tags.append(node); tagNodes.push({ node, lon: anchor.lon, lat: anchor.lat, alt: 1 });
  }
  if (arcs && arcs.userData.mid) {
    const m = arcs.userData.mid;
    const node = el('div', 'tag arc num', `${arcs.userData.from.nearest.distance_km.toLocaleString()} km`);
    tags.append(node); tagNodes.push({ node, lon: m[0], lat: m[1], alt: m[2] });
  }
}

// -- picking --------------------------------------------------------------------------
const tmp = new THREE.Vector3(), tmp2 = new THREE.Vector3();
function screen(lon, lat, alt) {
  project(lon, lat, alt, tmp);
  // On the globe, a point past the horizon is hidden by the body.
  if (view.eased < 0.5 && tmp.dot(camera.position) < R * R) return null;
  tmp2.copy(tmp).project(camera);
  if (tmp2.z > 1) return null;
  return [(tmp2.x + 1) / 2 * window.innerWidth, (1 - tmp2.y) / 2 * window.innerHeight];
}
function pick(x, y) {
  let best = null, bestD = 16;
  for (const spot of spots) {
    const p = screen(spot.lon, spot.lat, spot.alt);
    if (!p) continue;
    const d = Math.hypot(p[0] - x, p[1] - y) - Math.min(spot.radius, 18) * 0.6;
    if (d < bestD) { bestD = d; best = { type: 'spot', ref: spot }; }
  }
  if (best) return best;
  for (const zone of zones) {
    if (!screen(zone.lon, zone.lat, 0)) continue;
    const ring = zone.polygon.map((p) => { const q = screen(p[0], p[1], 0); return q && [q[0], q[1]]; });
    let inside = false;
    for (let i = 0, j = ring.length - 1; i < ring.length && !ring.some((p) => !p); j = i++) {
      if ((ring[i][1] > y) !== (ring[j][1] > y)
        && x < (ring[j][0] - ring[i][0]) * (y - ring[i][1]) / (ring[j][1] - ring[i][1]) + ring[i][0]) inside = !inside;
    }
    const centre = screen(zone.lon, zone.lat, 0);
    if (inside || Math.hypot(centre[0] - x, centre[1] - y) < 20) return { type: 'zone', ref: zone };
  }
  return null;
}

const tip = $('tip');
function showTip(target, x, y) {
  if (!target) { tip.style.display = 'none'; return; }
  tip.replaceChildren(describe(target, true));
  tip.style.display = 'block';
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = `${Math.min(window.innerWidth - w - 12, x + 18)}px`;
  tip.style.top = `${Math.max(12, Math.min(window.innerHeight - h - 12, y - h / 2))}px`;
}
function pin(target) {
  pinned = target;
  const panel = $('detail');
  if (!target) { panel.classList.remove('open'); mark(); focus(); return; }
  $('dbody').replaceChildren(describe(target, false));
  panel.classList.add('open');
  mark(); focus();
}
// With something pinned, everything outside it dims.
function focus() {
  const f = U.uFocus.value;
  if (!pinned) { f.w = 0; return; }
  const ref = pinned.ref;
  f.set(ref.lon, ref.lat, pinned.type === 'zone' ? ref.radius_km / 111 + 1.5 : 3, 1);
}

// Search runs over the reports already here: nothing is looked up elsewhere.
function search(text) {
  const q = text.trim().toLowerCase(), out = $('found');
  if (!q || !data) { out.textContent = ''; return; }
  const zone = zones.find((z) => z.name.toLowerCase().includes(q) || z.places.some((p) => p.toLowerCase().includes(q)));
  const hits = spots.filter((s) => s.items.some((i) => `${i.place} ${i.country}`.toLowerCase().includes(q)))
    .sort((a, b) => b.items.length - a.items.length);
  const byTitle = hits.length ? [] : spots.filter((s) => s.items.some((i) => i.title.toLowerCase().includes(q)));
  const spot = hits[0] || byTitle[0];
  if (zone && !(spot && spot.items.some((i) => i.place.toLowerCase() === q))) {
    pin({ type: 'zone', ref: zone }); go(zone.lon, zone.lat, 190); out.textContent = `zone: ${zone.name}`;
  } else if (spot) {
    pin({ type: 'spot', ref: spot }); go(spot.lon, spot.lat, 190);
    out.textContent = `${spot.items.length} report${spot.items.length > 1 ? 's' : ''} at ${spot.items[0].place}`
      + (hits.length > 1 ? ` · ${hits.length - 1} more place${hits.length > 2 ? 's' : ''} match` : '');
  } else out.textContent = 'No collected report names that place.';
}
$('find').addEventListener('keydown', (e) => { if (e.key === 'Enter') search(e.target.value); });
$('close').addEventListener('click', () => pin(null));

// -- camera ---------------------------------------------------------------------------
function go(lon, lat, dist) {
  let dlon = lon - view.lon;
  if (view.flat < 0.5) { if (dlon > 180) dlon -= 360; else if (dlon < -180) dlon += 360; }
  fly = { t0: performance.now(), from: { ...view }, dlon, lat, dist: dist ?? view.dist };
  view.idleAt = performance.now();
}
function placeCamera() {
  const f = view.eased, lat = Math.max(-84, Math.min(84, view.lat));
  const cl = Math.cos(lat * RAD), d = view.dist;
  const sx = d * cl * Math.sin(view.lon * RAD), sy = d * Math.sin(lat * RAD), sz = d * cl * Math.cos(view.lon * RAD);
  const fx = view.lon * RAD * R, fy = lat * RAD * R, fz = (d - R) * 1.5 + 60;
  camera.position.set(sx + (fx - sx) * f, sy + (fy - sy) * f, sz + (fz - sz) * f);
  camera.up.set(0, 1, 0);
  camera.lookAt(fx * f, fy * f, 0);
  camera.updateMatrixWorld();
}

let drag = null;
canvas.addEventListener('pointerdown', (e) => {
  drag = { x: e.clientX, y: e.clientY, moved: 0 };
  canvas.setPointerCapture(e.pointerId); canvas.classList.add('dragging'); fly = null;
});
canvas.addEventListener('pointermove', (e) => {
  view.idleAt = performance.now();
  if (drag) {
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    drag.moved += Math.abs(dx) + Math.abs(dy); drag.x = e.clientX; drag.y = e.clientY;
    const k = (view.dist - R * (1 - view.eased * 0.4)) / window.innerHeight * 0.42;
    view.lon -= dx * k; view.lat = Math.max(-84, Math.min(84, view.lat + dy * k));
    if (view.flat < 0.5) view.lon = ((view.lon + 540) % 360) - 180;
    else view.lon = Math.max(-180, Math.min(180, view.lon));
    showTip(null);
    return;
  }
  const target = pick(e.clientX, e.clientY);
  if ((target && target.ref) !== (hover && hover.ref)) { hover = target; mark(); }
  canvas.classList.toggle('aim', !!target);
  showTip(target, e.clientX, e.clientY);
});
canvas.addEventListener('pointerup', (e) => {
  canvas.classList.remove('dragging');
  if (drag && drag.moved < 5) pin(pick(e.clientX, e.clientY));
  drag = null;
});
canvas.addEventListener('pointerleave', () => { hover = null; mark(); showTip(null); });
canvas.addEventListener('wheel', (e) => {
  e.preventDefault(); fly = null; view.idleAt = performance.now();
  view.dist = Math.max(R * 1.18, Math.min(620, view.dist * Math.exp(e.deltaY * 0.0012)));
}, { passive: false });

// -- controls ---------------------------------------------------------------------------
function toggle(id, get, set) {
  const button = $(id);
  const sync = () => button.setAttribute('aria-pressed', String(get()));
  button.addEventListener('click', () => { set(!get()); sync(); });
  sync();
}
for (const name of ['news', 'video', 'zones', 'events']) {
  toggle(`l-${name}`, () => layers[name], (v) => { layers[name] = v; rebuild(); });
}
toggle('flat', () => view.flatTarget === 1, (v) => {
  view.flatTarget = v ? 1 : 0;
  if (v) view.lon = Math.max(-180, Math.min(180, view.lon));
});
toggle('spin', () => view.spin, (v) => { view.spin = v; });
$('home').addEventListener('click', () => { const h = start(); go(h.lon, h.lat, h.dist); });
window.addEventListener('keydown', (e) => {
  if (e.target instanceof HTMLInputElement) return;
  if (e.key === 'Escape') pin(null);
  if (e.key === 'f' || e.key === 'F') $('flat').click();
});
function start() {
  const anchor = data && (data.anchors.find((a) => a.kind === 'device') || data.anchors[0]);
  return anchor ? { lon: anchor.lon, lat: Math.max(-50, Math.min(50, anchor.lat)), dist: HOME.dist } : HOME;
}

// -- timeline ---------------------------------------------------------------------------
const scrub = $('scrub');
const STEPS = Number(scrub.max), STEP_S = 900;
function renderBars() {
  const bars = $('bars'); bars.replaceChildren();
  if (!data) return;
  const hours = Math.round(data.window_s / 3600), counts = new Array(hours).fill(0), t = now();
  for (const item of data.items) {
    if (item.kind === 'event') continue;
    const h = hours - 1 - Math.floor((t - item.ts) / 3600);
    if (h >= 0 && h < hours) counts[h]++;
  }
  const top = Math.max(1, ...counts), limit = asOf == null ? hours : hours - (t - asOf) / 3600;
  counts.forEach((n, h) => {
    const bar = el('i'); bar.style.height = `${Math.max(3, 100 * n / top)}%`;
    if (n && h < limit) bar.className = 'on';
    bars.append(bar);
  });
}
function setAsOf(step) {
  asOf = step >= STEPS ? null : now() - (STEPS - step) * STEP_S;
  if (asOf == null) { $('asofb').textContent = 'Now'; $('asofs').textContent = 'all reports of the last 72 h'; }
  else {
    const hours = (STEPS - step) * STEP_S / 3600;
    $('asofb').textContent = `${hours % 1 ? hours.toFixed(2) : hours} h ago`;
    $('asofs').textContent = `${new Date(asOf * 1000).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })} · zones hidden`;
  }
  if (pinned && pinned.type === 'zone' && asOf != null) pin(null);
  renderBars(); rebuild();
}
scrub.addEventListener('input', () => { stopPlay(); setAsOf(Number(scrub.value)); });
function stopPlay() { if (playing) { playing = null; $('play').textContent = '▶'; } }
$('play').addEventListener('click', () => {
  if (playing) { stopPlay(); return; }
  playing = { t0: performance.now(), last: -1 }; $('play').textContent = '■';
});

// -- data ---------------------------------------------------------------------------------
function banner(text) { const b = $('banner'); b.textContent = text || ''; b.style.display = text ? 'block' : 'none'; }
function status(state, text) { document.body.dataset.link = state; $('linktext').textContent = text; U.uLive.value = state === 'live' && !calm ? 1 : 0; }

function apply(payload, first) {
  if (payload.generated_at != null && payload.age_s != null) clockSkew = payload.generated_at + payload.age_s - Date.now() / 1000;
  data = payload;
  $('nzones').textContent = payload.zones.length;
  $('nplaced').textContent = payload.counts.mapped;
  $('nreports').textContent = payload.counts.reports;
  const failed = payload.sources.filter((s) => s.error);
  const src = $('sources');
  src.textContent = payload.sources.length
    ? `${payload.sources.length - failed.length} of ${payload.sources.length} sources reached · ${payload.counts.unmapped} reports could not be placed`
    : '';
  src.title = failed.length ? `Unreachable: ${failed.map((s) => s.name).join(', ')}` : 'All sources answered on the last run.';
  if (payload.generated_at == null) {
    status('stale', 'no data'); banner('No reports collected yet. The world job runs every 15 minutes; run it now with: jarvis geo world --refresh');
  } else if (payload.stale) {
    status('stale', `stale · ${ago(payload.generated_at)}`); banner(`Reports are old: last collected ${ago(payload.generated_at)}. The map shows what was known then.`);
  } else {
    status('live', `updated ${ago(payload.generated_at)}`); banner('');
  }
  // Keep a pin across refreshes when its place or zone is still there.
  const keep = pinned && (pinned.type === 'spot' ? pinned.ref.key : pinned.ref.id);
  const kind = pinned && pinned.type;
  hover = null;
  renderBars(); rebuild();
  if (keep) {
    const ref = kind === 'spot' ? spots.find((s) => s.key === keep) : zones.find((z) => z.id === keep);
    pin(ref ? { type: kind, ref } : null);
  }
  if (first) {
    const h = start(); view.lon = h.lon; view.lat = h.lat; view.dist = h.dist;
    // Deep links: #map opens unfolded, #zone=2 opens on the second zone.
    const hash = location.hash.slice(1).split('&');
    if (hash.includes('map')) { $('flat').click(); view.flat = 1; }
    const want = hash.find((part) => part.startsWith('zone='));
    const zone = want && zones[Number(want.slice(5)) - 1];
    if (zone) { pin({ type: 'zone', ref: zone }); view.lon = zone.lon; view.lat = zone.lat; view.dist = 150; }
  }
}

let loaded = false;
async function poll() {
  try {
    const res = await fetch('/api/world', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    apply(await res.json(), !loaded);
    loaded = true;
  } catch (err) {
    status('down', 'not answering'); banner('ARGUS-INSTINCT is not answering. The map shows the last reports it sent.');
  }
}
async function boot() {
  try {
    const res = await fetch('/static/vendor/world-50m.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    buildWorld(await res.json());
  } catch (err) {
    banner('The map outlines could not be loaded; reports are still listed.');
  }
  await poll();
  setInterval(poll, POLL_MS);
}

// -- frame ------------------------------------------------------------------------------------
function frame(t) {
  requestAnimationFrame(frame);
  if (document.hidden) return;
  U.uTime.value = t / 1000;
  if (view.flat !== view.flatTarget) {
    const step = calm ? 1 : 0.035;
    view.flat = view.flatTarget > view.flat ? Math.min(1, view.flat + step) : Math.max(0, view.flat - step);
  }
  // Ease the unfold so it starts and ends gently.
  const eased = view.eased = U.uFlat.value = view.flat * view.flat * (3 - 2 * view.flat);
  core.scale.setScalar(Math.max(0.001, 1 - eased)); halo.visible = eased < 0.98;
  if (fly) {
    const k = Math.min(1, (t - fly.t0) / (calm ? 1 : 900)), e = k * k * (3 - 2 * k);
    view.lon = fly.from.lon + fly.dlon * e; view.lat = fly.from.lat + (fly.lat - fly.from.lat) * e;
    view.dist = fly.from.dist + (fly.dist - fly.from.dist) * e;
    if (k >= 1) { fly = null; if (view.flat < 0.5) view.lon = ((view.lon + 540) % 360) - 180; }
  } else if (view.spin && !drag && !hover && !pinned && view.flatTarget === 0 && t - view.idleAt > 4000) {
    view.lon = ((view.lon + 0.02 + 540) % 360) - 180;
  }
  if (playing) {
    const step = Math.floor((t - playing.t0) / 24000 * STEPS);
    if (step !== playing.last) { playing.last = step; scrub.value = String(Math.min(STEPS, step)); setAsOf(Math.min(STEPS, step)); }
    if (step >= STEPS) stopPlay();
  }
  placeCamera();
  for (const tag of tagNodes) {
    const p = screen(tag.lon, tag.lat, tag.alt);
    tag.node.style.display = p ? 'block' : 'none';
    if (p) { tag.node.style.left = `${p[0]}px`; tag.node.style.top = `${p[1]}px`; }
  }
  renderer.render(scene, camera);
}
placeCamera();
requestAnimationFrame(frame);
boot();
