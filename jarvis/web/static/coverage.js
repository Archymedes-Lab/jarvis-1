// ARGUS-INSTINCT defense coverage, drawn from /api/coverage and kept live by a stream.
//
// What in the scene carries meaning:
//   glass shell   every ATT&CK technique, one pane per tactic it belongs to.
//                 Each tactic is a wedge, in attack order; inside a wedge the
//                 proven panes fill from the top, so the lit share of a wedge
//                 is that tactic's coverage. Panes have equal area.
//   pane label    the technique's ATT&CK id, etched on the pane once it is large
//                 enough on screen to read.
//   pane style    lit glass = validated (a probe made the real detector fire),
//                 clear glass with a coloured rim = claimed (mapped, unproven),
//                 a faint etched outline = blind, red hatching = regressed.
//   neurons       the collectors. The arc around one is the time since its
//                 last run against its interval; in the uptime reading an outer
//                 ring is its 24 h uptime. Red motes = open critical or high findings. A neuron
//                 sits under the techniques it feeds, joined to each by an
//                 axon; collectors that feed none ring the core.
//   firing        a collector really ran: its stored timestamp advanced. The
//                 signal leaves the neuron along every axon, lights the panes
//                 it feeds on arrival, and reports to the core. A signal from
//                 the core to a neuron is the scheduler starting that job.
//   core          this machine. Its colour is the share of collectors that are
//                 current. A ring closing onto it is the native sensor
//                 committing a pass of events; a wider ring is a larger pass.
//
// Motion means something happened. Nothing in the scene moves by itself except
// the camera's slow turn (which the Rotate button stops): no drifting panes, no
// flicker between neurons, no spinning ornaments. This was decided with a
// Jev-guided review (scripts/reviews/coverage_view_design.py), which judged
// constant ambient motion both the least attractive and the most likely thing
// to be read as activity. What remains as pure appearance is static: the
// stars, the glass shading, the bloom, and the panes flying into place once on
// first load.
//
// When the view stops hearing from ARGUS-INSTINCT every motion stops, the colour
// drains out of the scene and the banner says so: a monitor that has died
// cannot be left looking busy.
//
// Two readings of the same scene, cross-faded on a timer or pinned:
//   coverage      what is proven, as above.
//   uptime        is it watching right now. A pane is a gauge: its fill is the
//                 share of the last 24 h in which at least one collector that
//                 feeds it had fresh evidence. Blind panes have no collector,
//                 so they stay empty: nothing can be up there.
import * as THREE from '/static/vendor/three.module.min.js';

THREE.ColorManagement.enabled = false;      // colours are authored for the display, as written

const LEVELS = ['validated', 'regressed', 'claimed', 'blind'];
const LEVEL_TEXT = {
  validated: ['Validated', 'a probe made the real detector fire for at least one way of doing it'],
  claimed: ['Claimed', 'a collector is mapped, nothing proves it'],
  blind: ['Blind', 'no collector looks for it'],
  regressed: ['Regressed', 'a detector that should fire did not'],
};
const STYLE = { blind: 0, claimed: 1, validated: 2, regressed: 3 };
const STATE = { current: 0, stale: 1, failing: 2, missing: 3 };
const R = 6, ROWS = 8, ZMAX = 0.62, GAP = 0.9, NODE_R = 3.6, INFRA_R = 2.2;
const MAX_NODES = 64;          // size of the shaders' per-collector arrays
const SIGNAL_S = 1.05;         // seconds a signal takes to travel one axon
const FULL_REFRESH_MS = 60000; // the whole summary (uptime figures) is re-read this often
const SILENCE_MS = 15000;      // three of the stream's five-second heartbeats
const RETRY_MS = 4000;         // how soon a failed first read of the summary is tried again
const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = (id) => document.getElementById(id);
// brand:begin -- identical in every page; tests/test_ui_brand.py keeps the copies equal.
// The product is ARGUS-INSTINCT. Server text can still say JARVIS (finding titles keep their
// identity for acknowledgements and history), so it is re-branded at display time.
// Real Windows objects keep their spelling so they can be found in Task Scheduler
// and Services; lowercase commands (jarvis ..., jarvis.service) are never touched.
// Idempotent: a name already followed by -1 is left alone, so text that went
// through the rule twice, or a build that renames JARVIS to ARGUS, never reads ARGUS-INSTINCT-1.
const BRAND = "ARGUS-INSTINCT";
const BRAND_KEEP = /^ (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)/;
const brand = (s) => String(s ?? "").replace(/\bJARVIS\b(?!-(?:1|INSTINCT)\b)/g,
  (m, i, all) => (BRAND_KEEP.test(all.slice(i + m.length)) ? m : BRAND));
// brand:end
const esc = (s) => brand(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const pretty = (t) => t.replace(/-/g, ' ');
const hex3 = (h) => [((h >> 16) & 255) / 255, ((h >> 8) & 255) / 255, (h & 255) / 255];

// ── themes ─────────────────────────────────────────────────────────────────
const THEMES = {
  dark: {
    light: 0, clear: 0x03050a, bloom: 0.62,
    level: { validated: 0x33e6d4, claimed: 0xffb648, blind: 0x6c80ad, regressed: 0xff4d63 },
    ok: [0.80, 0.90, 1.0], warn: [1.0, 0.72, 0.30], bad: [1.0, 0.33, 0.42],
    axon: [0.30, 0.50, 0.95], star: [0.62, 0.72, 0.92], coreCool: [0.45, 0.80, 1.0],
  },
  light: {
    light: 1, clear: 0xedf1f7, bloom: 0.0,
    level: { validated: 0x0a9d92, claimed: 0xcf8508, blind: 0x93a1bb, regressed: 0xdd3148 },
    ok: [0.16, 0.30, 0.62], warn: [0.80, 0.50, 0.03], bad: [0.86, 0.19, 0.28],
    axon: [0.30, 0.42, 0.66], star: [0.52, 0.60, 0.74], coreCool: [0.14, 0.42, 0.78],
  },
};
let themeSetting = 'auto';
try { themeSetting = localStorage.getItem('jarvis-coverage-theme') || 'auto'; } catch (e) { /* storage may be blocked */ }
{ const t = new URLSearchParams(location.hash.slice(1)).get('theme'); if (t in THEMES || t === 'auto') themeSetting = t; }
const prefersLight = matchMedia('(prefers-color-scheme: light)');
const themeName = () => (themeSetting === 'auto' ? (prefersLight.matches ? 'light' : 'dark') : themeSetting);
let theme = THEMES[themeName()];

// ── renderer, camera, orbit ────────────────────────────────────────────────
const canvas = $('scene');
const renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: 'high-performance' });
renderer.outputColorSpace = THREE.LinearSRGBColorSpace;
renderer.autoClear = false;
let dpr = Math.min(devicePixelRatio || 1, 1.75);
const HDR = renderer.extensions.has('EXT_color_buffer_float') || renderer.extensions.has('EXT_color_buffer_half_float');
const scene = new THREE.Scene();        // everything inside the shell, and the far side of it
const front = new THREE.Scene();        // the near panes, drawn as glass over the first
const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 400);
const HOME = { theta: -0.75, el: 0.2, dist: 18.5 };
for (const [k, v] of new URLSearchParams(location.hash.slice(1))) if (k in HOME && isFinite(+v)) HOME[k] = +v;
const view = { ...HOME }, goal = { ...HOME };
let spin = !calm, lastTouch = 0, drag = null, vel = 0;

const U = {     // uniforms shared by every material
  uTime: { value: 0 }, uMix: { value: 0 }, uLight: { value: theme.light }, uScale: { value: 1 },
  uMotion: { value: calm ? 0 : 1 }, uRes: { value: new THREE.Vector2(1, 1) },
  uFire: { value: new Float32Array(MAX_NODES).fill(-100) },
  uStart: { value: new Float32Array(MAX_NODES).fill(-100) },
  uRun: { value: new Float32Array(MAX_NODES) },
  uOk: { value: new THREE.Vector3() }, uWarn: { value: new THREE.Vector3() }, uBad: { value: new THREE.Vector3() },
};

function target(w, h, mips) {
  const t = new THREE.WebGLRenderTarget(Math.max(2, w), Math.max(2, h), {
    type: HDR ? THREE.HalfFloatType : THREE.UnsignedByteType, depthBuffer: false,
    minFilter: mips ? THREE.LinearMipmapLinearFilter : THREE.LinearFilter, magFilter: THREE.LinearFilter,
    generateMipmaps: !!mips });
  return t;
}
let rtScene, rtMain, rtBloom = [];
function resize() {
  const w = Math.round(innerWidth * dpr), h = Math.round(innerHeight * dpr);
  renderer.setPixelRatio(1);
  renderer.setSize(w, h, false);
  canvas.style.width = `${innerWidth}px`; canvas.style.height = `${innerHeight}px`;
  camera.aspect = innerWidth / innerHeight;
  camera.updateProjectionMatrix();
  for (const t of [rtScene, rtMain, ...rtBloom]) if (t) t.dispose();
  rtScene = target(w, h, true); rtMain = target(w, h, false);
  rtBloom = [2, 4, 8, 16].map((k) => target(Math.round(w / k), Math.round(h / k), false));
  U.uRes.value.set(w, h);
}
addEventListener('resize', resize);
resize();

canvas.addEventListener('pointerdown', (e) => {
  drag = { x: e.clientX, y: e.clientY, moved: 0 };
  canvas.setPointerCapture(e.pointerId);
  canvas.classList.add('dragging');
});
canvas.addEventListener('pointermove', (e) => {
  if (drag) {
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    drag.x = e.clientX; drag.y = e.clientY; drag.moved += Math.abs(dx) + Math.abs(dy);
    goal.theta += dx * 0.006; vel = dx * 0.006;
    goal.el = Math.max(-1.2, Math.min(1.2, goal.el + dy * 0.005));
    lastTouch = performance.now();
    hideTip();
  } else hover(e.clientX, e.clientY);
});
canvas.addEventListener('pointerup', (e) => {
  canvas.classList.remove('dragging');
  if (drag && drag.moved < 5) { select(pick(e.clientX, e.clientY)); vel = 0; }
  drag = null;
});
canvas.addEventListener('pointerleave', hideTip);
canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  goal.dist = Math.max(9, Math.min(34, goal.dist * Math.exp(e.deltaY * 0.001)));
  lastTouch = performance.now();
}, { passive: false });

// ── shader pieces ──────────────────────────────────────────────────────────
const GLSL_ENV = `
  // The room the glass reflects: a sky gradient, one key light, one soft strip.
  vec3 envMap(vec3 d, float light){
    float h = d.y * .5 + .5;
    vec3 dark = mix(vec3(.010, .018, .045), vec3(.09, .19, .42), smoothstep(0., 1., h));
    dark += vec3(.60, .82, 1.) * pow(max(dot(d, normalize(vec3(.42, .78, .46))), 0.), 26.) * 1.8;
    dark += vec3(.20, .95, .85) * pow(max(dot(d, normalize(vec3(-.72, .12, -.6))), 0.), 7.) * .22;
    dark += vec3(.75, .85, 1.) * smoothstep(.05, 0., abs(d.y - .32 + .08 * sin(d.x * 3.))) * .30;
    vec3 lite = mix(vec3(.70, .77, .88), vec3(1.), smoothstep(-.3, .8, d.y));
    lite += vec3(1.) * pow(max(dot(d, normalize(vec3(.42, .78, .46))), 0.), 32.) * 1.2;
    return mix(dark, lite, light);
  }`;
const GLSL_UP = `
  uniform vec3 uOk; uniform vec3 uWarn; uniform vec3 uBad;
  vec3 upColor(float f){ return f >= .98 ? uOk : f >= .8 ? uWarn : uBad; }`;
const blendFor = () => (theme.light ? THREE.NormalBlending : THREE.AdditiveBlending);
const themed = [];      // materials whose blending follows the theme
function mat(opts, follow = true) {
  const m = new THREE.ShaderMaterial({ transparent: true, depthWrite: false, depthTest: false, ...opts,
    uniforms: { ...U, ...(opts.uniforms || {}) } });
  if (follow) { m.blending = blendFor(); themed.push(m); }
  return m;
}

// ── sky and stars ──────────────────────────────────────────────────────────
const fsGeo = new THREE.PlaneGeometry(2, 2);
const sky = new THREE.Mesh(fsGeo, mat({
  vertexShader: `varying vec2 vUv; void main(){ vUv = uv; gl_Position = vec4(position.xy, 0., 1.); }`,
  fragmentShader: `
    uniform float uLight; uniform float uTime; uniform vec2 uRes; varying vec2 vUv;
    float hash(vec2 p){ return fract(sin(dot(p, vec2(41.3, 289.1))) * 43758.5); }
    float noise(vec2 p){ vec2 i = floor(p), f = fract(p); f = f*f*(3.-2.*f);
      return mix(mix(hash(i), hash(i+vec2(1,0)), f.x), mix(hash(i+vec2(0,1)), hash(i+vec2(1,1)), f.x), f.y); }
    void main(){
      vec2 p = (vUv - .5) * vec2(uRes.x / uRes.y, 1.);
      float r = length(p);
      float neb = noise(p * 2.2 + uTime * .010) * .6 + noise(p * 5.1 - uTime * .014) * .4;
      vec3 dark = mix(vec3(.030, .055, .125), vec3(.006, .010, .022), smoothstep(.0, .95, r));
      dark += vec3(.05, .12, .22) * neb * neb * (1. - smoothstep(.2, 1.1, r)) * .55;
      dark += vec3(.10, .03, .16) * pow(noise(p * 1.6 + 7.), 3.) * .35;
      vec3 lite = mix(vec3(.985, .990, 1.), vec3(.865, .895, .945), smoothstep(.05, 1.05, r));
      lite -= vec3(.030, .022, .010) * neb * (1. - smoothstep(.3, 1.1, r));
      gl_FragColor = vec4(mix(dark, lite, uLight), 1.);
    }`,
}, false));
sky.material.blending = THREE.NoBlending;
sky.frustumCulled = false; sky.renderOrder = -100;
scene.add(sky);

function points(positions, extra, vertexShader, fragmentShader) {
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
  for (const [name, arr, n] of extra) g.setAttribute(name, new THREE.Float32BufferAttribute(arr, n));
  const p = new THREE.Points(g, mat({ vertexShader, fragmentShader }));
  p.frustumCulled = false;
  return p;
}
const GLOW_FRAG = `
  uniform float uLight; varying vec3 vColor; varying float vA;
  void main(){ float r = length(gl_PointCoord - .5) * 2.;
    float a = (exp(-r * r * 5.) + smoothstep(.34, .0, r) * mix(.0, .5, uLight)) * vA * step(r, 1.);
    gl_FragColor = vec4(vColor, a); }`;
{
  const p = [], seed = [];
  let s = 7;
  const rnd = () => (s = (s * 16807) % 2147483647) / 2147483647;
  for (let i = 0; i < 1400; i++) {
    const u = rnd() * 2 - 1, a = rnd() * Math.PI * 2, d = 60 + rnd() * 90, k = Math.sqrt(1 - u * u);
    p.push(d * k * Math.cos(a), d * u, d * k * Math.sin(a)); seed.push(rnd());
  }
  const stars = points(p, [['aSeed', seed, 1]], `
    attribute float aSeed; uniform float uTime, uScale, uMotion, uLight; uniform vec3 uStar;
    varying vec3 vColor; varying float vA;
    void main(){ vec4 mv = modelViewMatrix * vec4(position, 1.); gl_Position = projectionMatrix * mv;
      float tw = .55 + .45 * aSeed;
      gl_PointSize = (.22 + aSeed * .34) * uScale / -mv.z;
      vColor = uStar; vA = tw * mix(.75, .30, uLight); }`, GLOW_FRAG);
  stars.material.uniforms.uStar = { value: new THREE.Vector3() };
  scene.add(stars);
  scene.userData.stars = stars;
}

// ── the core: this machine ─────────────────────────────────────────────────
const core = new THREE.Group();
const coreU = { uHealth: { value: 1 }, uHit: { value: -100 }, uCool: { value: new THREE.Vector3() } };
const orb = new THREE.Mesh(new THREE.IcosahedronGeometry(0.66, 5), mat({
  uniforms: coreU,
  vertexShader: `
    uniform float uTime, uMotion, uHit; varying vec3 vN; varying vec3 vV; varying vec3 vO;
    void main(){
      float hit = exp(-max(uTime - uHit, 0.) * 2.2) * step(uHit, uTime);
      vec3 p = position * (1. + hit * .07);
      vec4 mv = modelViewMatrix * vec4(p, 1.);
      vN = normalize(normalMatrix * normal); vV = normalize(-mv.xyz); vO = position;
      gl_Position = projectionMatrix * mv;
    }`,
  fragmentShader: `
    uniform float uTime, uLight, uHealth, uHit, uMotion; uniform vec3 uCool, uWarn, uBad;
    varying vec3 vN; varying vec3 vV; varying vec3 vO;
    ${GLSL_ENV}
    void main(){
      vec3 N = normalize(vN); float ndv = max(dot(N, vV), 0.);
      float F = pow(1. - ndv, 3.);
      float hit = exp(-max(uTime - uHit, 0.) * 2.2) * step(uHit, uTime);
      vec3 mood = uHealth > .97 ? uCool : uHealth > .8 ? uWarn : uBad;
      float plasma = .5 + .5 * sin(vO.x * 9.) * sin(vO.y * 8.) * sin(vO.z * 7.);
      vec3 inner = mix(mood * (.30 + .50 * plasma * ndv + hit * 1.3), mix(vec3(1.), mood, .45 + .25 * plasma) + hit * .2, uLight);
      vec3 col = inner + envMap(reflect(-vV, N), uLight) * (F * .9 + .05) * mix(1., .5, uLight) + mood * F * mix(1.1, .0, uLight);
      col = mix(col, mix(col, mood, F * .8), uLight);
      float a = mix(.90, .78, uLight);
      gl_FragColor = vec4(col, a);
    }`,
}, false));
orb.material.blending = THREE.NormalBlending;
const lineMat = (opacity) => mat({
  uniforms: { uOpacity: { value: opacity }, ...coreU },
  vertexShader: `void main(){ gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.); }`,
  fragmentShader: `uniform float uOpacity, uLight, uHealth; uniform vec3 uCool, uWarn, uBad;
    void main(){ vec3 mood = uHealth > .97 ? uCool : uHealth > .8 ? uWarn : uBad;
      gl_FragColor = vec4(mix(mood * 1.2 + .1, mood, uLight), uOpacity * mix(.8, 1., uLight)); }`,
});
const cage = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.92, 1)), lineMat(0.5));
cage.rotation.set(0.4, 0.6, 0);
core.add(orb, cage);
scene.add(core);

// The native sensor committing a pass of events: one ring closing onto the core.
// It is drawn when a new pass is reported and at no other time.
const intake = (() => {
  const pts = [];
  for (let k = 0; k <= 128; k++) { const a = (k / 128) * Math.PI * 2; pts.push(Math.cos(a), 0, Math.sin(a)); }
  const g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
  const m = new THREE.Line(g, mat({
    uniforms: { uAt: { value: -100 }, uSize: { value: 0 }, ...coreU },
    vertexShader: `uniform float uTime, uAt, uSize; varying float vA;
      void main(){ float t = clamp((uTime - uAt) / 1.1, 0., 1.);
        float rad = mix(1.4 + uSize * 1.5, .70, t * t);
        vA = step(uAt, uTime) * step(uTime - uAt, 1.1) * sin(t * 3.1416) * (.5 + .5 * uSize);
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position * rad, 1.); }`,
    fragmentShader: `uniform vec3 uCool; uniform float uLight; varying float vA;
      void main(){ gl_FragColor = vec4(mix(uCool * 1.4, uCool, uLight), vA); }`,
  }));
  m.rotation.set(0.5, 0, 0.25); m.frustumCulled = false;
  scene.add(m);
  return m;
})();

// ── data-driven objects ────────────────────────────────────────────────────
let data = null, world = null, focus = null, pinned = null, signature = '', introDone = false;
const clock = new THREE.Clock();
// The one clock every animation reads. It advances only while the view is live
// (see frame()), so births, firings and shader time can never disagree.
let sceneTime = 0;

const TILE_VERT = `
  attribute vec3 aColor; attribute float aStyle; attribute vec2 aSize; attribute float aHi; attribute float aPulse;
  attribute float aUp; attribute float aBorn; attribute float aSeed; attribute float aCell;
  uniform float uTime, uMotion;
  varying float vCell;
  varying vec2 vP; varying vec2 vHalf; varying vec3 vColor; varying float vStyle; varying float vFace;
  varying float vHi; varying float vPulse; varying float vUp; varying float vSeed;
  varying vec3 vN; varying vec3 vT; varying vec3 vB; varying vec3 vView; varying vec3 vWorld;
  void main(){
    float born = clamp((uTime - aBorn) / .9, 0., 1.), e = 1. - pow(1. - born, 3.);
    float bump = exp(-max(uTime - aPulse, 0.) * 2.4) * step(aPulse, uTime);
    vCell = aCell;
    vP = position.xy * aSize; vHalf = aSize * .5; vColor = aColor; vStyle = aStyle; vHi = aHi; vPulse = aPulse; vUp = aUp; vSeed = aSeed;
    mat3 basis = mat3(instanceMatrix);
    vec3 nrm = normalize(basis * vec3(0., 0., 1.));
    vec4 world = instanceMatrix * vec4(position.xy * aSize * e, 0., 1.);
    float lift = smoothstep(1.2, 1.5, aHi) * .16 + bump * .10;
    world.xyz += nrm * (lift - (1. - e) * 2.4);
    vec4 mv = modelViewMatrix * world;
    vN = normalize(normalMatrix * nrm); vT = normalize(normalMatrix * (basis * vec3(1., 0., 0.)));
    vB = normalize(normalMatrix * (basis * vec3(0., 1., 0.)));
    vView = -mv.xyz; vFace = dot(vN, normalize(vView)); vWorld = world.xyz;
    gl_Position = projectionMatrix * mv;
  }`;
const TILE_FRAG = `
  uniform float uTime, uMix, uLight, uFront, uMotion; uniform vec2 uRes; uniform sampler2D uScene;
  uniform sampler2D uAtlas; uniform vec2 uGrid; varying float vCell;
  varying vec2 vP; varying vec2 vHalf; varying vec3 vColor; varying float vStyle; varying float vFace;
  varying float vHi; varying float vPulse; varying float vUp; varying float vSeed;
  varying vec3 vN; varying vec3 vT; varying vec3 vB; varying vec3 vView; varying vec3 vWorld;
  ${GLSL_ENV} ${GLSL_UP}
  float box(vec2 p, vec2 b, float r){ vec2 q = abs(p) - b + r; return length(max(q, 0.)) + min(max(q.x, q.y), 0.) - r; }
  void main(){
    if (uFront > .5 ? vFace <= 0. : vFace > 0.) discard;
    vec2 b = vHalf * .80; float rad = min(b.x, b.y) * .30;
    float d = box(vP, b, rad);
    float w = fwidth(d) + .003;
    float mask = smoothstep(w, -w, d);
    if (mask < .004) discard;
    float dim = smoothstep(.2, 1., vHi);

    // what the pane shows: its proof level, or in the uptime reading a gauge
    float style = vStyle; vec3 tint = vColor;
    float fed = step(0., vUp);
    float level = (b.y - vP.y) / (2. * b.y);
    float filled = mix(1., smoothstep(vUp + .02, vUp - .02, level) * fed, uMix);
    tint = mix(tint, mix(vColor, upColor(vUp), fed), uMix);
    float solid = step(1.5, style);                    // validated or regressed
    solid = mix(solid, fed, uMix);
    float rimK = style < .5 ? .30 : style < 1.5 ? 1.15 : 1.35;
    rimK = mix(rimK, mix(.30, 1.2, fed), uMix);

    float rim = smoothstep(.032 + w, .0, abs(d + .010));
    float pulse = exp(-max(uTime - vPulse, 0.) * 1.7) * step(vPulse, uTime);
    float ripple = smoothstep(.07, .0, abs(length(vP) / max(b.x, b.y) - (uTime - vPulse) * 1.5)) * step(vPulse, uTime) * step(uTime - vPulse, 1.2);
    float hatch = step(2.5, style) * (1. - uMix) * step(.5, fract((vP.x + vP.y) * 6.));

    if (uFront < .5) {          // the far side of the shell, seen through the middle
      float a = (solid * filled * .22 + rim * rimK * .55 + hatch * .25 + pulse * .5) * mask * dim * mix(.55, .50, uLight);
      gl_FragColor = vec4(tint * (1. + pulse), a);
      return;
    }

    // a bevelled pane: the normal leans outward near the edge
    float e = .003;
    vec2 g = vec2(box(vP + vec2(e, 0.), b, rad) - box(vP - vec2(e, 0.), b, rad),
                  box(vP + vec2(0., e), b, rad) - box(vP - vec2(0., e), b, rad)) / (2. * e);
    float bev = clamp(1. + d / (min(b.x, b.y) * .42), 0., 1.);
    vec3 N = normalize(vN + (vT * g.x + vB * g.y) * bev * bev * .9);
    vec3 V = normalize(vView);
    float ndv = max(dot(N, V), 0.);
    float F = pow(1. - ndv, 4.);

    // refraction of everything behind the pane, split a little by colour, and frosted when lit
    vec2 suv = gl_FragCoord.xy / uRes;
    vec2 off = N.xy * (.030 + .055 * bev) * (.6 + .4 * solid);
    float frost = solid * filled * 2.6 + (1. - solid) * .5 + bev * 1.2;
    vec3 refr = vec3(textureLod(uScene, suv + off * 1.10, frost).r,
                     textureLod(uScene, suv + off, frost).g,
                     textureLod(uScene, suv + off * .90, frost).b);

    float body = solid * filled;
    float inner = exp(-dot(vP / b, vP / b) * 1.1);
    vec3 col = refr * mix(vec3(1.), mix(tint, tint * 1.25 + .12, uLight), body * mix(.62, .58, uLight));
    col += tint * body * (.12 + inner * .14) * (1. - uLight);       // lit from within
    col = mix(col, col * (1. - .5 * hatch) + tint * hatch * .5, step(2.5, style));
    // rim: added light on dark, ink on light
    col = mix(col + tint * rim * rimK * .95, mix(col, tint, clamp(rim * rimK * .9, 0., 1.)), uLight);
    vec3 refl = envMap(reflect(-V, N), uLight);
    col += refl * (F * .85 + .035) * mix(.35 + .65 * max(body, .45 * step(.5, style)), .55, uLight);
    col += mix(vec3(.8, .9, 1.), vec3(1.), uLight) * pow(bev, 3.) * max(N.y, 0.) * mix(.10, .22, uLight);   // top bevel catches light
    col += tint * (pulse * .9 + ripple * 1.1) * mix(1., .55, uLight);
    // the technique id, etched: only once the pane is wide enough on screen to read it
    float wide = 2. * b.x / max(fwidth(vP.x), 1e-5);
    float readable = smoothstep(52., 78., wide);
    if (readable > 0.) {
      vec2 q = vec2(vP.x / (b.x * 1.62), vP.y / (b.x * 1.62 * .30)) + .5;       // +y runs down the pane on screen
      if (q.x > 0. && q.x < 1. && q.y > 0. && q.y < 1.) {
        float cx = mod(vCell, uGrid.x), cy = floor(vCell / uGrid.x);
        // seen from outside the shell the pane's own x axis runs right to left
        float ink = texture2D(uAtlas, vec2((cx + 1. - q.x) / uGrid.x, 1. - (cy + q.y) / uGrid.y)).r;
        vec3 etched = mix(mix(tint, vec3(1.), .55) * 1.25, tint * .38, uLight);
        col = mix(col, etched, ink * readable * mix(.50, .92, step(.5, style)));
      }
    }
    gl_FragColor = vec4(col, mask * mix(.20, 1., dim));
  }`;

const tileMaterial = (isFront) => {
  // Each has its own scene texture slot: the far panes are drawn *into* that
  // texture, so theirs must stay empty or the GPU refuses the draw.
  const m = mat({ uniforms: { uFront: { value: isFront ? 1 : 0 }, uScene: { value: null }, uAtlas: { value: null },
    uGrid: { value: new THREE.Vector2(1, 1) } }, side: THREE.DoubleSide,
    vertexShader: TILE_VERT, fragmentShader: TILE_FRAG }, !isFront);
  if (isFront) m.blending = THREE.NormalBlending;
  return m;
};
const tileBack = tileMaterial(false), tileFront = tileMaterial(true);

const SIGNAL_GLSL = `
  uniform float uTime; uniform float uFire[${MAX_NODES}]; uniform float uStart[${MAX_NODES}]; uniform float uRun[${MAX_NODES}];
  const float SPEED = ${(1 / SIGNAL_S).toFixed(4)};`;
// axons: kind 0 neuron -> pane, 1 neuron -> core (aT runs from the neuron)
const axonMaterial = mat({
  uniforms: { uAxon: { value: new THREE.Vector3() } },
  vertexShader: `
    attribute float aT; attribute float aJob; attribute float aKind; attribute vec3 aColor; attribute float aHi;
    uniform vec3 uAxon; uniform float uLight; ${SIGNAL_GLSL}
    varying vec3 vColor; varying float vA;
    float packet(float since, float at){
      float p = since * SPEED - at;
      float head = exp(-p * p * 60.);
      float tail = exp(-max(p, 0.) * 7.) * step(0., p) * .55;
      return (head + tail) * step(0., since) * step(since, ${(SIGNAL_S * 2.2).toFixed(2)});
    }
    void main(){
      int j = int(aJob + .5);
      float sig = packet(uTime - uFire[j], aT);
      float charge = 0.;
      if (aKind > .5 && aKind < 1.5) {
        sig = max(sig, packet(uTime - uStart[j], 1. - aT));            // the scheduler starting the job
        charge = uRun[j] * (.5 + .5 * sin(aT * 26. + uTime * 7.)) * .5;
      }
      // Quiet until used: an axon is barely there until its neuron fires, runs or is pointed at.
      float base = aKind > .5 ? .05 : .07;
      float hi = aHi > 1.5 ? 6. : aHi;
      vColor = mix(mix(uAxon, aColor, aKind < .5 ? .75 : .15), mix(vec3(1.), aColor, .35 + .65 * uLight), clamp(sig, 0., 1.));
      vA = (base * hi + sig * 1.3 + charge) * mix(1., 1.3, uLight);
      gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.);
    }`,
  fragmentShader: `varying vec3 vColor; varying float vA; void main(){ gl_FragColor = vec4(vColor, min(vA, 1.6)); }`,
});
// the signal itself: a bright bead with a short trail, moved along the axon's curve on the GPU
const beadMaterial = mat({
  vertexShader: `
    attribute vec3 aP1; attribute vec3 aP2; attribute float aJob; attribute float aKind; attribute float aLag; attribute vec3 aColor;
    uniform float uScale, uLight; ${SIGNAL_GLSL}
    varying vec3 vColor; varying float vA;
    void main(){
      int j = int(aJob + .5);
      float since = aKind > 1.5 ? uTime - uStart[j] : uTime - uFire[j];
      float t = since * SPEED - aLag;
      float on = step(0., t) * step(t, 1.);
      float s = aKind > 1.5 ? 1. - t : t;                              // a start signal runs core -> neuron
      vec3 p = mix(mix(position, aP1, s), mix(aP1, aP2, s), s);
      vec4 mv = modelViewMatrix * vec4(p, 1.);
      gl_Position = on > .5 ? projectionMatrix * mv : vec4(2., 2., 2., 1.);
      gl_PointSize = (.46 - aLag * 3.2) * mix(1., .62, uLight) * uScale / -mv.z * on;
      vColor = mix(vec3(1.), aColor, .45 + .45 * uLight) * mix(1.25, 1., uLight);
      vA = on * (1. - aLag * 7.) * sin(clamp(t, 0., 1.) * 3.1416);
    }`,
  fragmentShader: GLOW_FRAG,
});
const nodeMaterial = mat({
  vertexShader: `
    attribute float aState; attribute float aProg; attribute float aHi; attribute float aUp; attribute float aJob;
    uniform float uScale; ${SIGNAL_GLSL}
    varying float vState; varying float vProg; varying float vFlash; varying float vRun; varying float vHi; varying float vUp; varying float vGo;
    void main(){
      int j = int(aJob + .5);
      vState = aState; vProg = aProg; vRun = uRun[j]; vHi = aHi; vUp = aUp;
      vFlash = exp(-max(uTime - uFire[j], 0.) * 1.5) * step(uFire[j], uTime);
      vGo = uTime - uFire[j];
      vec4 mv = modelViewMatrix * vec4(position, 1.);
      gl_Position = projectionMatrix * mv;
      gl_PointSize = (.62 + vFlash * .26 + vRun * .06) * uScale / -mv.z;
    }`,
  fragmentShader: `
    uniform float uTime, uMix, uLight, uMotion; ${GLSL_UP}
    varying float vState; varying float vProg; varying float vFlash; varying float vRun; varying float vHi; varying float vUp; varying float vGo;
    void main(){
      vec2 p = (gl_PointCoord - .5) * 2.; p.y = -p.y;
      float r = length(p);
      vec3 col = vState < .5 ? uOk : vState < 1.5 ? uWarn : uBad;
      col = mix(col, vUp < 0. ? col : upColor(vUp), uMix);
      float w = fwidth(r) + .01;
      // soma: a nucleus inside a membrane; missing collectors are an empty membrane
      float nucleus = smoothstep(.13 + w, .13 - w, r) * (.85 + .15 * vRun * sin(uTime * 12.));
      float membrane = smoothstep(.045, .0, abs(r - .24)) * (.55 + .45 * vRun);
      float cyto = smoothstep(.24, .05, r) * .28;
      float body = vState > 2.5 ? membrane : nucleus + membrane + cyto;
      float ang = fract(atan(p.x, p.y) / 6.2831853 + (vRun > .5 ? uTime * .9 : 0.));
      float ring = smoothstep(.06, .0, abs(r - .52));
      float arc = ring * (ang < (vRun > .5 ? .3 : vProg) ? .85 : .10) * (1. - .75 * uMix);
      float shock = smoothstep(.07, .0, abs(r - clamp(vGo * 1.3, 0., 1.))) * step(0., vGo) * step(vGo, .75) * (1. - vGo / .75);
      float halo = exp(-r * r * 7.) * (.08 + vFlash * .6 + vRun * .16) * mix(1., .55, uLight);
      float up = 0.;                                           // outer gauge: share of the last 24 h with fresh evidence
      if (vUp >= 0.) {
        float g = smoothstep(.05, .0, abs(r - .84));
        float turn = fract(atan(p.x, p.y) / 6.2831853);
        up = g * (turn < vUp ? .16 + 1.0 * uMix : .04 + .18 * uMix);
      }
      float a = (body * .9 + arc * .9 + halo + up + shock * 1.2) * vHi * step(r, 1.);
      gl_FragColor = vec4(col * mix(1. + vFlash * .5, 1., uLight), a);
    }`,
});
const motes = points(new Float32Array(MAX_NODES * 5 * 3), [], `
  uniform float uScale, uLight; uniform vec3 uBad; varying vec3 vColor; varying float vA;
  void main(){ vec4 mv = modelViewMatrix * vec4(position, 1.); gl_Position = projectionMatrix * mv;
    gl_PointSize = .30 * uScale / -mv.z; vColor = uBad * mix(1.2, 1., uLight); vA = .9; }`, GLOW_FRAG);
motes.visible = false;
scene.add(motes);
const guideMaterial = mat({
  vertexShader: `void main(){ gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.); }`,
  fragmentShader: `uniform float uLight; void main(){ gl_FragColor = vec4(mix(vec3(.5, .62, .85), vec3(.42, .50, .66), uLight), mix(.16, .30, uLight)); }`,
});

function basis(angle, z) {
  // Longitude runs clockwise seen from above, so wedges read left to right from outside.
  const lon = -angle, c = Math.sqrt(1 - z * z);
  const n = new THREE.Vector3(c * Math.cos(lon), z, c * Math.sin(lon));
  const east = new THREE.Vector3(-Math.sin(lon), 0, Math.cos(lon));
  const north = new THREE.Vector3().crossVectors(n, east);
  return { n, east, north, c };
}
const hash = (i) => { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); };

function build(d) {
  const before = world ? Object.fromEntries(Object.entries(world.byTid).map(([tid, ps]) => [tid, ps[0].tech.level])) : null;
  if (world) {
    for (const g of [scene, front]) g.remove(...world.groups);
    world.groups.forEach((g) => g.traverse((o) => o.geometry && o.geometry !== fsGeo && o.geometry.dispose()));
  }
  const group = new THREE.Group(), glass = new THREE.Group();
  const now = sceneTime;
  const tactics = Object.keys(d.tactics);
  const rank = (t) => LEVELS.indexOf(t.level);
  const wedges = tactics.map((name) => {
    const list = d.techniques.filter((t) => t.tactics.includes(name))
      .sort((a, b) => rank(a) - rank(b) || a.tid.localeCompare(b.tid));
    return { name, list, cols: Math.max(1, Math.ceil(list.length / ROWS)) };
  });
  const unit = (Math.PI * 2) / (wedges.reduce((s, w) => s + w.cols, 0) + wedges.length * GAP);
  const dz = (2 * ZMAX) / ROWS;

  const places = [], byTid = {}, seps = [];
  let lon = 0;
  wedges.forEach((w, wi) => {
    w.lon0 = lon + unit * GAP / 2;
    w.center = w.lon0 + (w.cols * unit) / 2;
    seps.push(lon);
    w.list.forEach((tech, i) => {
      const row = Math.floor(i / w.cols), col = i % w.cols;      // fill from the top, row by row
      const b = basis(w.lon0 + (col + 0.5) * unit, ZMAX - (row + 0.5) * dz);
      const place = { tech, tactic: w.name, n: b.n, pos: b.n.clone().multiplyScalar(R), index: places.length,
                      size: [unit * R * b.c * 0.96, (dz * R / b.c) * 0.96], b, born: wi * 0.07 + row * 0.05 + col * 0.02 };
      places.push(place);
      (byTid[tech.tid] = byTid[tech.tid] || []).push(place);
    });
    lon = w.lon0 + w.cols * unit + unit * GAP / 2;
  });

  // panes: one geometry, drawn twice (far side inside the scene, near side as glass over it)
  const n = places.length, geo = new THREE.PlaneGeometry(1, 1);
  const col = new Float32Array(n * 3), style = new Float32Array(n), size = new Float32Array(n * 2);
  const hi = new Float32Array(n).fill(1), pulse = new Float32Array(n).fill(-100), upt = new Float32Array(n).fill(-1);
  const born = new Float32Array(n), seed = new Float32Array(n), cell = new Float32Array(n);
  // every technique id drawn once into one texture; a pane reads its own cell
  const ids = [...new Set(places.map((p) => p.tech.tid))], COLS = 16, CW = 192, CH = 58;
  const sheet = document.createElement('canvas');
  sheet.width = COLS * CW; sheet.height = Math.max(1, Math.ceil(ids.length / COLS)) * CH;
  const pen = sheet.getContext('2d');
  pen.fillStyle = '#000'; pen.fillRect(0, 0, sheet.width, sheet.height);
  pen.fillStyle = '#fff'; pen.textAlign = 'center'; pen.textBaseline = 'middle';
  pen.font = '600 40px ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif';
  ids.forEach((tid, i) => pen.fillText(tid, (i % COLS + 0.5) * CW, (Math.floor(i / COLS) + 0.5) * CH + 2));
  const atlas = new THREE.CanvasTexture(sheet);
  atlas.colorSpace = THREE.NoColorSpace; atlas.minFilter = THREE.LinearMipmapLinearFilter; atlas.generateMipmaps = true;
  atlas.anisotropy = renderer.capabilities.getMaxAnisotropy();
  if (tileFront.uniforms.uAtlas.value) tileFront.uniforms.uAtlas.value.dispose();
  tileFront.uniforms.uAtlas.value = atlas;
  tileFront.uniforms.uGrid.value.set(COLS, sheet.height / CH);
  const cellOf = Object.fromEntries(ids.map((tid, i) => [tid, i]));
  const tilesB = new THREE.InstancedMesh(geo, tileBack, n), tilesF = new THREE.InstancedMesh(geo, tileFront, n);
  const m = new THREE.Matrix4();
  for (const p of places) {
    m.makeBasis(p.b.east, p.b.north, p.n).setPosition(p.pos);
    tilesB.setMatrixAt(p.index, m); tilesF.setMatrixAt(p.index, m);
    style[p.index] = STYLE[p.tech.level];
    size.set(p.size, p.index * 2);
    seed[p.index] = hash(p.index + 1);
    cell[p.index] = cellOf[p.tech.tid];
    born[p.index] = introDone || calm ? -100 : now + 0.2 + p.born;
    // a pane whose level changed since the last map flashes once
    if (before && before[p.tech.tid] && before[p.tech.tid] !== p.tech.level) pulse[p.index] = now;
  }
  tilesF.instanceMatrix = tilesB.instanceMatrix;
  const ia = (arr, k) => new THREE.InstancedBufferAttribute(arr, k);
  for (const [name, arr, k] of [['aColor', col, 3], ['aStyle', style, 1], ['aSize', size, 2], ['aHi', hi, 1],
    ['aPulse', pulse, 1], ['aUp', upt, 1], ['aBorn', born, 1], ['aSeed', seed, 1], ['aCell', cell, 1]]) geo.setAttribute(name, ia(arr, k));
  tilesB.frustumCulled = tilesF.frustumCulled = false;
  group.add(tilesB); glass.add(tilesF);
  introDone = true;

  // wedge separators and the two rims of the shell
  const guide = [];
  const arc = (f, steps) => { for (let i = 0; i < steps; i++) { guide.push(...f(i / steps), ...f((i + 1) / steps)); } };
  for (const s of seps) arc((t) => basis(s, -ZMAX - 0.03 + t * (2 * ZMAX + 0.06)).n.multiplyScalar(R).toArray(), 14);
  for (const z of [ZMAX + 0.03, -ZMAX - 0.03]) arc((t) => basis(t * Math.PI * 2, z).n.multiplyScalar(R).toArray(), 160);
  const gg = new THREE.BufferGeometry();
  gg.setAttribute('position', new THREE.Float32BufferAttribute(guide, 3));
  group.add(new THREE.LineSegments(gg, guideMaterial));

  // neurons: under the techniques they feed, or around the core
  const nodes = d.collectors.map((c, index) => ({ c, index, places: [] }));
  const byJob = Object.fromEntries(nodes.map((x) => [x.c.job, x]));
  for (const p of places) for (const job of p.tech.sources) if (byJob[job]) byJob[job].places.push(p);
  const feeders = nodes.filter((x) => x.places.length), infra = nodes.filter((x) => !x.places.length);
  for (const x of feeders) {
    const v = new THREE.Vector3();
    x.places.forEach((p) => v.add(p.n));
    if (v.lengthSq() < 1e-4) v.set(Math.cos(x.index), 0.2, Math.sin(x.index));
    x.pos = v.normalize().multiplyScalar(NODE_R);
  }
  for (let it = 0; it < 60; it++) {                // keep neurons apart on their sphere
    for (const a of feeders) for (const b of feeders) {
      if (a === b) continue;
      const delta = a.pos.clone().sub(b.pos), dist = delta.length();
      if (dist < 0.95) a.pos.add(delta.multiplyScalar((0.95 - dist) / (dist + 1e-3) * 0.3)).setLength(NODE_R);
    }
  }
  const areaOrder = [...new Set(infra.map((x) => x.c.area))];
  infra.sort((a, b) => areaOrder.indexOf(a.c.area) - areaOrder.indexOf(b.c.area));
  infra.forEach((x, i) => {
    // two tilted rings, alternating, so neighbours are not drawn on top of each other
    const a = (i / infra.length) * Math.PI * 2, outer = i % 2, rad = INFRA_R + outer * 0.62, tilt = outer ? -0.34 : 0.42;
    x.pos = new THREE.Vector3(Math.cos(a) * rad, Math.sin(a) * rad * tilt, Math.sin(a) * rad * 0.92);
  });

  const ng = new THREE.BufferGeometry();
  ng.setAttribute('position', new THREE.Float32BufferAttribute(nodes.flatMap((x) => x.pos.toArray()), 3));
  for (const name of ['aState', 'aProg']) ng.setAttribute(name, new THREE.Float32BufferAttribute(new Float32Array(nodes.length), 1));
  ng.setAttribute('aJob', new THREE.Float32BufferAttribute(nodes.map((x) => Math.min(x.index, MAX_NODES - 1)), 1));
  ng.setAttribute('aHi', new THREE.Float32BufferAttribute(new Float32Array(nodes.length).fill(1), 1));
  ng.setAttribute('aUp', new THREE.Float32BufferAttribute(new Float32Array(nodes.length).fill(-1), 1));
  const pointsMesh = new THREE.Points(ng, nodeMaterial);
  pointsMesh.frustumCulled = false;

  // axons (curved) and the beads that travel them
  const SEG = 18, TRAIL = 4;
  const ap = [], at = [], aj = [], ak = [], ac = [], beams = [];
  const b0 = [], b1 = [], b2 = [], bj = [], bk = [], bl = [], bc = [];
  const tmp = new THREE.Vector3(), c3 = [0, 0, 0];
  const curve = (p0, p1, p2, t) => tmp.copy(p0).lerp(p1, t).lerp(new THREE.Vector3().copy(p1).lerp(p2, t), t);
  const addAxon = (node, to, colour, place, kind, bend) => {
    const first = ap.length / 3, job = Math.min(node.index, MAX_NODES - 1);
    const mid = node.pos.clone().add(to).multiplyScalar(0.5);
    const side = new THREE.Vector3(hash(first + 1) - 0.5, hash(first + 2) - 0.5, hash(first + 3) - 0.5).cross(mid.lengthSq() > 1e-3 ? mid : node.pos).normalize();
    const ctrl = mid.clone().multiplyScalar(kind === 0 ? 1.10 : 0.9).addScaledVector(side, bend * (0.5 + hash(first + 4)));
    for (let i = 0; i < SEG; i++) for (const t of [i / SEG, (i + 1) / SEG]) {
      ap.push(...curve(node.pos, ctrl, to, t).toArray()); at.push(t); aj.push(job); ak.push(kind); ac.push(...colour);
    }
    for (let k = 0; k < TRAIL; k++) {
      b0.push(...node.pos.toArray()); b1.push(...ctrl.toArray()); b2.push(...to.toArray());
      bj.push(job); bk.push(kind); bl.push(k * 0.035); bc.push(...colour);
    }
    if (kind === 1) for (let k = 0; k < TRAIL; k++) {              // the start signal, core -> neuron
      b0.push(...node.pos.toArray()); b1.push(...ctrl.toArray()); b2.push(...to.toArray());
      bj.push(job); bk.push(2); bl.push(k * 0.035); bc.push(...colour);
    }
    beams.push({ node, place, first, count: SEG * 2 });
  };
  const origin = new THREE.Vector3();
  for (const x of nodes) {
    addAxon(x, origin, c3, null, 1, 0.55);
    for (const p of x.places) addAxon(x, p.pos, c3, p, 0, 0.75);
  }
  const bg = new THREE.BufferGeometry();
  bg.setAttribute('position', new THREE.Float32BufferAttribute(ap, 3));
  bg.setAttribute('aT', new THREE.Float32BufferAttribute(at, 1));
  bg.setAttribute('aJob', new THREE.Float32BufferAttribute(aj, 1));
  bg.setAttribute('aKind', new THREE.Float32BufferAttribute(ak, 1));
  bg.setAttribute('aColor', new THREE.Float32BufferAttribute(ac, 3));
  bg.setAttribute('aHi', new THREE.Float32BufferAttribute(new Float32Array(at.length).fill(1), 1));
  const lines = new THREE.LineSegments(bg, axonMaterial);
  lines.frustumCulled = false;
  const dg = new THREE.BufferGeometry();
  dg.setAttribute('position', new THREE.Float32BufferAttribute(b0, 3));
  dg.setAttribute('aP1', new THREE.Float32BufferAttribute(b1, 3));
  dg.setAttribute('aP2', new THREE.Float32BufferAttribute(b2, 3));
  dg.setAttribute('aJob', new THREE.Float32BufferAttribute(bj, 1));
  dg.setAttribute('aKind', new THREE.Float32BufferAttribute(bk, 1));
  dg.setAttribute('aLag', new THREE.Float32BufferAttribute(bl, 1));
  dg.setAttribute('aColor', new THREE.Float32BufferAttribute(bc, 3));
  const beads = new THREE.Points(dg, beadMaterial);
  beads.frustumCulled = false;
  group.add(lines, pointsMesh, beads);

  scene.add(group); front.add(glass);
  world = { groups: [group, glass], wedges, places, byTid, tiles: tilesB, geo, nodes, byJob, points: pointsMesh,
            lines, beams, beads, motes, sparks: [] };
  paint();
  spark();
  buildTags();
  applyFocus();
}

// Colours that depend on the theme, written into the buffers that carry them.
function paint() {
  if (!world) return;
  const c = world.geo.attributes.aColor;
  for (const p of world.places) c.array.set(hex3(theme.level[p.tech.level]), p.index * 3);
  c.needsUpdate = true;
  const lc = world.lines.geometry.attributes.aColor, dc = world.beads.geometry.attributes.aColor;
  for (const b of world.beams) {
    const colour = b.place ? hex3(theme.level[b.place.tech.level]) : theme.axon;
    for (let i = 0; i < b.count; i++) lc.array.set(colour, (b.first + i) * 3);
  }
  lc.needsUpdate = true;
  let k = 0;
  for (const b of world.beams) {
    const colour = b.place ? hex3(theme.level[b.place.tech.level]) : theme.ok;
    const count = b.place ? 4 : 8;
    for (let i = 0; i < count; i++) dc.array.set(colour, (k + i) * 3);
    k += count;
  }
  dc.needsUpdate = true;
}

// Red motes around a neuron: its open critical and high findings (exact counts are in the tooltip).
function spark() {
  const sparks = [];
  for (const n of world.nodes) {
    const open = n.serious ?? (n.c.findings.critical + n.c.findings.high);
    const count = open ? Math.min(5, Math.ceil(Math.log2(open + 1))) : 0;
    const up = n.pos.clone().normalize();
    const u = new THREE.Vector3().crossVectors(up, new THREE.Vector3(0.3, 1, 0.2)).normalize();
    const v = new THREE.Vector3().crossVectors(up, u);
    for (let i = 0; i < count; i++) sparks.push({ n, u, v, phase: (i / count) * Math.PI * 2 + n.index });
  }
  world.sparks = sparks;
  world.motes.geometry.setDrawRange(0, sparks.length);
  world.motes.visible = sparks.length > 0;
}

// ── live state ─────────────────────────────────────────────────────────────
function sync(d) {
  const g = world.points.geometry;
  for (const n of world.nodes) {
    const now = d.collectors.find((x) => x.job === n.c.job) || n.c;
    n.c = now;
    g.attributes.aState.array[n.index] = STATE[now.state] ?? 3;
    g.attributes.aUp.array[n.index] = now.uptime ? now.uptime.pct24 : -1;
  }
  g.attributes.aState.needsUpdate = g.attributes.aUp.needsUpdate = true;
  const tu = world.geo.attributes.aUp, by = Object.fromEntries(d.techniques.map((x) => [x.tid, x.uptime]));
  for (const p of world.places) tu.array[p.index] = by[p.tech.tid] == null ? -1 : by[p.tech.tid];
  tu.needsUpdate = true;
  health();
}

function health() {
  const cs = data.collectors;
  coreU.uHealth.value = cs.length ? cs.filter((c) => c.state === 'current').length / cs.length : 0;
}

const fired = [];      // recent firings, newest first, for the feed
function fire(n) {
  const t = sceneTime;
  if (n.index < MAX_NODES) U.uFire.value[n.index] = t;
  const pulse = world.geo.attributes.aPulse;
  for (const p of n.places) pulse.array[p.index] = t + SIGNAL_S;      // when the signal arrives
  pulse.needsUpdate = true;
  coreU.uHit.value = t + SIGNAL_S;
  fired.unshift({ job: n.c.job, at: Date.now() });
  fired.length = Math.min(fired.length, 12);
}

// One compact state from the stream (or the poll that stands in for it).
let live = null, levelsSeen = null, running = new Set(), ingestSeen = null;
function applyLive(s) {
  if (!s.ok) throw new Error(s.error || 'state unavailable');
  live = s;
  if (!world || !data) return;
  let counts = false;
  const g = world.points.geometry;
  for (const n of world.nodes) {
    const c = s.c[n.c.job];
    if (!c) continue;
    const [ts, state, serious] = c;
    if (ts && n.c.ts && ts > n.c.ts) fire(n);
    n.c.ts = ts || n.c.ts; n.c.state = state;
    g.attributes.aState.array[n.index] = STATE[state] ?? 3;
    if (n.serious !== serious) { n.serious = serious; counts = true; }
    const is = s.running.includes(n.c.job), was = running.has(n.c.job);
    if (is && !was && n.index < MAX_NODES) U.uStart.value[n.index] = sceneTime;
    n.c.running = is;
  }
  g.attributes.aState.needsUpdate = true;
  running = new Set(s.running);
  data.running = s.running;
  if (counts) spark();
  health();
  // A pass the page has not seen before: the ring closes once, wider for a larger pass.
  if (s.ingest && s.ingest.at !== ingestSeen) {
    if (ingestSeen !== null && s.ingest.events > 0) {
      intake.material.uniforms.uAt.value = sceneTime;
      intake.material.uniforms.uSize.value = Math.min(1, Math.log10(1 + s.ingest.events) / 4);
    }
    ingestSeen = s.ingest.at;
  }
  $('ingest').textContent = s.ingest ? `${s.ingest.events.toLocaleString()} events committed by the sensor's last pass` : '';
  // A pane changed level, or the map was measured again: read the whole summary.
  if (levelsSeen !== null && (s.levels !== levelsSeen || s.map_at !== data.map_at)) full();
  levelsSeen = s.levels;
  feed();
}

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago`
    : `${Math.round(s / 86400)} d ago`;
}
const every = (s) => (s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h`);
const cssv = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// Numbers ease to their new value instead of jumping.
const shownValue = new Map();
function count(el, value, suffix = '') {
  const from = shownValue.get(el) ?? value, start = performance.now();
  shownValue.set(el, value);
  if (calm || from === value) { el.textContent = `${value}${suffix}`; return; }
  const step = (t) => {
    const k = Math.min(1, (t - start) / 700), e = 1 - Math.pow(1 - k, 3);
    el.textContent = `${Math.round(from + (value - from) * e)}${suffix}`;
    if (k < 1 && shownValue.get(el) === value) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function hud() {
  const t = data.totals, total = t.total || 0;
  if (total) count($('pct'), Math.round((100 * t.validated) / total), '%'); else $('pct').textContent = '–';
  $('sub').textContent = `${t.validated || 0} of ${total} ATT&CK techniques for Windows and Linux`;
  const shown = LEVELS.filter((l) => l !== 'regressed' || t.regressed);
  $('bar').innerHTML = shown.filter((l) => t[l]).map((l) =>
    `<i style="flex:${t[l]};background:var(--${l});opacity:${l === 'blind' ? 0.55 : 1}"></i>`).join('');
  $('legend').innerHTML = shown.map((l) =>
    `<span class="glyph ${l}"></span><span class="l">${LEVEL_TEXT[l][0]}<small>${LEVEL_TEXT[l][1]}</small></span>` +
    `<span class="n num">${t[l] || 0}</span>`).join('');
  // The score is the last one that observed every scored collector; say when.
  $('score').textContent = data.score ? `${data.score.score}%` : '–';
  $('scoreage').textContent = data.score && data.score.at ? `verified ${ago(data.score.at)}` : '';
  $('mapage').textContent = data.map_at ? `map measured ${ago(data.map_at)}` : 'map not measured yet';
  $('tlist').innerHTML = Object.entries(data.tactics).map(([name, s]) =>
    `<button class="tactic${focus && focus.tactic === name ? ' on' : ''}" data-tactic="${esc(name)}">` +
    `<span class="name">${esc(pretty(name))}</span><span class="count num">${s.validated} / ${s.total}</span>` +
    `<span class="tbar">${shown.filter((l) => s[l]).map((l) =>
      `<i style="flex:${s[l]};background:var(--${l});opacity:${l === 'blind' ? 0.5 : 1}"></i>`).join('')}</span></button>`).join('');
  uptimePanel();
  feed();
}

const upColor = (f) => (f >= 0.98 ? cssv('--node') : f >= 0.8 ? cssv('--claimed') : cssv('--regressed'));
const pctText = (f) => `${(100 * f).toFixed(f >= 0.9995 ? 0 : 1)}%`;
function strip(buckets) {
  return `<span class="strip">${buckets.map((f, k) => {
    const n = buckets.length - 1 - k, when = `${n}-${n + 1} h ago`;
    return f == null ? `<i class="unk" title="${when}: no history yet"></i>`
      : `<i style="background:${upColor(f)}" title="${when}: ${pctText(f)} fresh"></i>`;
  }).join('')}</span>`;
}

function uptimePanel() {
  const u = data.uptime;
  $('upct').textContent = u ? pctText(u.pct24) : '–';
  $('ustrip').innerHTML = u ? strip(u.buckets) : '';
  const worst = data.collectors.filter((c) => c.uptime).sort((a, b) => a.uptime.pct24 - b.uptime.pct24).slice(0, 3);
  $('uworst').innerHTML = worst.map((c) =>
    `<li><span>${esc(c.label)}</span>${strip(c.uptime.buckets)}<b class="num">${pctText(c.uptime.pct24)}</b></li>`).join('');
  $('unote').textContent = !u ? 'No collector receipts are stored yet.'
    : u.partial_history ? `${u.partial_history} began reporting within the window; time before their first run is not counted. In this reading a neuron's outer ring is its own 24 h uptime.`
      : "In this reading a neuron's outer ring is its own 24 h uptime.";
}

function feed() {
  if (!data) return;
  const cs = data.collectors, n = (s) => cs.filter((c) => c.state === s).length;
  const bad = n('stale') + n('failing') + n('missing');
  $('health').innerHTML = `<span><b class="num">${n('current')}</b> of ${cs.length} current</span>` +
    (bad ? `<span><b class="num">${bad}</b> not reporting</span>` : '') +
    (data.running.length ? `<span class="run">running <b>${esc(data.running.join(', '))}</b></span>` : '');
  const recent = cs.filter((c) => c.ts).sort((a, b) => b.ts - a.ts).slice(0, 7);
  const just = new Set(fired.filter((f) => Date.now() - f.at < 2500).map((f) => f.job));
  $('runs').innerHTML = recent.map((c) =>
    `<li class="${just.has(c.job) ? 'fired' : ''}"><i class="dot ${esc(c.state)}"></i><span>${esc(c.label)}</span><time class="num">${ago(c.ts)}</time></li>`).join('');
}

// ── focus, picking, tooltip, detail ────────────────────────────────────────
function applyFocus() {
  if (!world) return;
  const f = pinned || focus;
  const tileHi = world.geo.attributes.aHi, nodeHi = world.points.geometry.attributes.aHi;
  const beamHi = world.lines.geometry.attributes.aHi;
  const tileOn = (p) => !f || (f.tid ? p.tech.tid === f.tid : f.job ? p.tech.sources.includes(f.job) : p.tactic === f.tactic);
  const nodeOn = (n) => !f || (f.job ? n.c.job === f.job : f.tid ? n.places.some((p) => p.tech.tid === f.tid)
    : n.places.some((p) => p.tactic === f.tactic));
  for (const p of world.places) tileHi.array[p.index] = tileOn(p) ? (f ? 1.5 : 1) : 0.22;
  for (const n of world.nodes) nodeHi.array[n.index] = nodeOn(n) ? 1 : 0.25;
  for (const b of world.beams) {
    const on = !f ? 1 : (nodeOn(b.node) && (!b.place || tileOn(b.place))) ? 2 : 0.25;
    beamHi.array.fill(on, b.first, b.first + b.count);
  }
  tileHi.needsUpdate = nodeHi.needsUpdate = beamHi.needsUpdate = true;
}

const v3 = new THREE.Vector3();
function screen(pos) {
  v3.copy(pos).project(camera);
  return v3.z < 1 ? [(v3.x * 0.5 + 0.5) * innerWidth, (-v3.y * 0.5 + 0.5) * innerHeight] : null;
}
function pick(x, y) {
  if (!world) return null;
  let best = null, bestD = 22 * 22;
  for (const n of world.nodes) {
    const s = screen(n.pos); if (!s) continue;
    const dd = (s[0] - x) ** 2 + (s[1] - y) ** 2;
    if (dd < bestD) { bestD = dd; best = { job: n.c.job }; }
  }
  if (best) return best;
  bestD = 20 * 20;
  for (const p of world.places) {
    if (v3.copy(camera.position).sub(p.pos).dot(p.n) <= 0) continue;    // only the near side
    const s = screen(p.pos); if (!s) continue;
    const dd = (s[0] - x) ** 2 + (s[1] - y) ** 2;
    if (dd < bestD) { bestD = dd; best = { tid: p.tech.tid }; }
  }
  return best;
}
function describe(f) {
  if (f.job) {
    const n = world.byJob[f.job], c = n.c, fd = c.findings;
    const open = ['critical', 'high', 'medium', 'low'].filter((s) => fd[s]).map((s) => `${fd[s]} ${s}`).join(', ');
    return { kind: `Collector · ${c.state}${c.running ? ' · running now' : ''}`, title: c.label,
      text: `Last ran ${ago(c.ts)}, scheduled every ${every(c.interval)}. ` +
        `${open ? `Open findings: ${open}.` : 'No open findings.'} ` +
        (c.uptime ? `Up ${pctText(c.uptime.pct24)} of the last 24 h` +
          `${c.uptime.pct7d != null ? `, ${pctText(c.uptime.pct7d)} of 7 days` : ''}; longest silence ` +
          `${every(Math.max(c.uptime.longest_gap_s, 1))}. ` : 'No run receipts stored yet. ') +
        (c.techniques.length ? `Feeds ${c.techniques.length} technique${c.techniques.length > 1 ? 's' : ''}.`
          : 'Supports the monitor itself; mapped to no technique.'),
      strip: c.uptime ? c.uptime : null,
      chips: [c.job, c.area, ...c.techniques] };
  }
  const t = world.byTid[f.tid][0].tech;
  return { kind: `${t.tid} · ${LEVEL_TEXT[t.level][0]}`, title: t.name,
    text: (t.level === 'blind' ? 'No collector looks for this technique.' : t.evidence) +
      // Said here and nowhere larger: a count of procedures is not a measure of completeness.
      (t.level === 'validated' && t.ways ? ` Proven ${t.ways === 1 ? 'one way' : `${t.ways} separate ways`}.` : '') +
      (t.uptime != null ? ` At least one of its collectors had fresh evidence ${pctText(t.uptime)} of the last 24 h.` : ''),
    chips: [...t.tactics.map(pretty), ...t.sources] };
}
function hover(x, y) {
  const f = pick(x, y);
  const same = JSON.stringify(f) === JSON.stringify(focus);
  if (!f) { if (focus && !focus.tactic) { focus = null; applyFocus(); } return hideTip(); }
  if (!same) { focus = f; applyFocus(); }
  const d = describe(f), tip = $('tip');
  tip.innerHTML = `<div class="k">${esc(d.kind)}</div><div class="t">${esc(d.title)}</div><div class="d">${esc(d.text)}</div>`;
  tip.style.display = 'block';
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = `${Math.min(innerWidth - w - 12, x + 16)}px`;
  tip.style.top = `${Math.max(12, Math.min(innerHeight - h - 12, y - h - 12))}px`;
}
function hideTip() { $('tip').style.display = 'none'; }
function select(f) {
  pinned = f;
  if (!f) { $('detail').style.display = 'none'; return applyFocus(); }
  const d = describe(f);
  $('dbody').innerHTML = `<div class="k">${esc(d.kind)}</div><h3>${esc(d.title)}</h3><p>${esc(d.text)}</p>` +
    `<div class="chips">${d.chips.map((c) => `<span class="chip">${esc(c)}</span>`).join('')}</div>` +
    (d.strip ? `${strip(d.strip.buckets)}<div class="axis"><span>24 h ago</span><span>now</span></div>` : '');
  $('detail').style.display = 'block';
  applyFocus();
}
$('close').onclick = () => select(null);
$('tlist').addEventListener('click', (e) => {
  const b = e.target.closest('.tactic'); if (!b) return;
  const w = world.wedges.find((x) => x.name === b.dataset.tactic);
  const off = focus && focus.tactic === w.name;
  focus = off ? null : { tactic: w.name };
  pinned = null; $('detail').style.display = 'none';
  if (!off) {
    const turns = Math.round((view.theta + w.center) / (Math.PI * 2));
    goal.theta = -w.center + turns * Math.PI * 2; goal.el = 0.12; lastTouch = performance.now() + 6000;
  }
  applyFocus(); hud();
});
$('spin').onclick = (e) => { spin = !spin; e.target.setAttribute('aria-pressed', spin); };
$('spin').setAttribute('aria-pressed', spin);
$('reset').onclick = () => { Object.assign(goal, HOME, { theta: view.theta }); focus = pinned = null;
  $('detail').style.display = 'none'; applyFocus(); hud(); };
$('showtable').onclick = () => {
  const rows = [...data.techniques].sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level) || a.tid.localeCompare(b.tid));
  $('tbody').innerHTML = '<table><thead><tr><th>Technique</th><th>Name</th><th>Level</th><th>Tactics</th><th>Collectors</th></tr></thead><tbody>' +
    rows.map((t) => `<tr><td class="num">${esc(t.tid)}</td><td>${esc(t.name)}</td><td>${LEVEL_TEXT[t.level][0]}</td>` +
      `<td>${esc(t.tactics.map(pretty).join(', '))}</td><td>${esc(t.sources.join(', ') || '—')}</td></tr>`).join('') + '</tbody></table>' +
    '<table><thead><tr><th>Collector</th><th>State</th><th>Last run</th><th>Up, 24 h</th><th>Up, 7 d</th><th>Longest silence, 24 h</th></tr></thead><tbody>' +
    [...data.collectors].sort((a, b) => (a.uptime ? a.uptime.pct24 : -1) - (b.uptime ? b.uptime.pct24 : -1)).map((c) =>
      `<tr><td>${esc(c.label)}</td><td>${esc(c.state)}</td><td>${ago(c.ts)}</td>` +
      `<td class="num">${c.uptime ? pctText(c.uptime.pct24) : '—'}</td>` +
      `<td class="num">${c.uptime && c.uptime.pct7d != null ? pctText(c.uptime.pct7d) : '—'}</td>` +
      `<td class="num">${c.uptime ? every(Math.max(c.uptime.longest_gap_s, 1)) : '—'}</td></tr>`).join('') + '</tbody></table>';
  $('table').style.display = 'block';
};
$('tclose').onclick = () => { $('table').style.display = 'none'; };
addEventListener('keydown', (e) => { if (e.key === 'Escape') { $('table').style.display = 'none'; select(null); } });

function buildTags() {
  $('tags').innerHTML = world.wedges.map((w, i) => {
    const s = data.tactics[w.name];
    return `<div class="tag" data-i="${i}">${esc(pretty(w.name))}<b class="num">${s.validated}/${s.total}</b></div>`;
  }).join('');
  world.tags = [...$('tags').children];
  world.wedges.forEach((w, i) => { w.tagPos = basis(w.center, ZMAX + (i % 2 ? 0.2 : 0.11)).n.multiplyScalar(R * 1.02); });
}

// ── theme ──────────────────────────────────────────────────────────────────
const THEME_LABEL = { auto: 'Theme: auto', light: 'Theme: light', dark: 'Theme: dark' };
function applyTheme() {
  const name = themeName();
  theme = THEMES[name];
  document.documentElement.dataset.theme = name;
  U.uLight.value = theme.light;
  U.uOk.value.set(...theme.ok); U.uWarn.value.set(...theme.warn); U.uBad.value.set(...theme.bad);
  coreU.uCool.value.set(...theme.coreCool);
  axonMaterial.uniforms.uAxon.value.set(...theme.axon);
  scene.userData.stars.material.uniforms.uStar.value.set(...theme.star);
  for (const m of themed) { m.blending = blendFor(); m.needsUpdate = true; }
  $('theme').textContent = THEME_LABEL[themeSetting];
  paint();
  if (data) hud();
}
$('theme').onclick = () => {
  themeSetting = { auto: 'light', light: 'dark', dark: 'auto' }[themeSetting];
  try { localStorage.setItem('jarvis-coverage-theme', themeSetting); } catch (e) { /* storage may be blocked */ }
  applyTheme();
};
prefersLight.addEventListener('change', applyTheme);

// ── the feed: one full read, then a stream of what changed ─────────────────
let fullBusy = false, lastFull = 0, lastHeard = 0, source = null, pollTimer = null;
let dead = false;
function offline(message) {
  // Never quiet: a view that cannot reach ARGUS-INSTINCT says so and stops implying liveness.
  $('banner').textContent = `ARGUS-INSTINCT is not answering (${message}). This view is not live.`;
  $('banner').style.display = 'block';
  setLink('down');
  dead = true;
  document.body.dataset.dead = '1';       // the panels grey out too: their numbers are the last known, not now
  // The clock stops with the view; panes still arriving would be left unseen.
  if (world) { const born = world.geo.attributes.aBorn; born.array.fill(-100); born.needsUpdate = true; }
}
function setLink(state) {
  const text = { stream: 'live', poll: 'live · polling', down: 'not live' }[state];
  $('link').dataset.state = state; $('linktext').textContent = text;
}
async function full() {
  if (fullBusy) return;
  fullBusy = true;
  try {
    const res = await fetch('/api/coverage', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const d = await res.json();
    const sig = JSON.stringify(d.techniques.map((t) => [t.tid, t.level, t.sources])) + d.collectors.map((c) => c.job).join();
    const first = !world || sig !== signature;
    // What the stream said since this read began is newer than the read.
    if (data && live) for (const c of d.collectors) { const l = live.c[c.job]; if (l) { c.ts = Math.max(c.ts || 0, l[0]) || c.ts; c.state = l[1]; } }
    data = d;
    if (first) { signature = sig; build(d); }
    sync(d);
    if (live) { for (const n of world.nodes) n.c.running = live.running.includes(n.c.job); data.running = live.running; }
    hud();
    $('banner').style.display = 'none';
    if (live) alive(source && !pollTimer ? 'stream' : 'poll');
    if (!d.techniques.length) { $('banner').textContent = 'The coverage map has not been measured yet.'; $('banner').style.display = 'block'; }
  } catch (err) { offline(err.message); } finally { fullBusy = false; lastFull = performance.now(); }
}
function heard(s, how) {
  try { applyLive(s); alive(how); }
  catch (err) { offline(err.message); }
}
function alive(how) {
  lastHeard = performance.now();
  if (!data) return;          // the live state alone is not a picture: stay "not live" until the summary loads
  dead = false; setLink(how);
  delete document.body.dataset.dead;
  if ($('banner').textContent.startsWith('ARGUS-INSTINCT is not')) $('banner').style.display = 'none';
}
function poll() {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/api/coverage/live', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      heard(await res.json(), 'poll');
    } catch (err) { offline(err.message); }
  }, 1000);
}
// #feed=poll keeps to plain requests: capture tools that wait for the network
// to go quiet never finish while a stream is open.
const POLL_ONLY = new URLSearchParams(location.hash.slice(1)).get('feed') === 'poll';
function listen() {
  if (POLL_ONLY || !('EventSource' in window)) return poll();
  source = new EventSource('/api/coverage/stream');
  source.addEventListener('pulse', (e) => {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    heard(JSON.parse(e.data), 'stream');
  });
  // Sent every few seconds while nothing changes: quiet and dead are different things.
  source.addEventListener('beat', () => { if (live) alive('stream'); });
  // The browser reconnects by itself; until it does, poll, so a refused or
  // dropped stream (every slot taken, daemon restarting) still shows live state.
  source.onerror = () => poll();
}
full().then(listen);
setInterval(() => {
  feed();
  // A summary that failed to load is asked for again every few seconds, not once a minute.
  if (performance.now() - lastFull > (data ? FULL_REFRESH_MS : RETRY_MS)) full();
  // Three missed heartbeats: not live, whatever the socket says.
  if (lastHeard && performance.now() - lastHeard > SILENCE_MS) offline(`nothing heard for ${SILENCE_MS / 1000} s`);
  $('linkage').textContent = live ? `state ${ago(live.at)}` : '';
}, 1000);

// ── post-processing: glass over the scene, then bloom ──────────────────────
const fsCam = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
const FS_VERT = `varying vec2 vUv; void main(){ vUv = uv; gl_Position = vec4(position.xy, 0., 1.); }`;
const pass = (fragmentShader, uniforms) => {
  const m = new THREE.ShaderMaterial({ vertexShader: FS_VERT, fragmentShader, uniforms, depthTest: false, depthWrite: false });
  const s = new THREE.Scene(); const q = new THREE.Mesh(fsGeo, m); q.frustumCulled = false; s.add(q);
  return { m, s };
};
const copyPass = pass(`uniform sampler2D tMap; varying vec2 vUv; void main(){ gl_FragColor = vec4(texture2D(tMap, vUv).rgb, 1.); }`,
  { tMap: { value: null } });
const downPass = pass(`
  uniform sampler2D tMap; uniform vec2 uTexel; uniform float uKnee; varying vec2 vUv;
  vec3 bright(vec3 c){ float l = max(c.r, max(c.g, c.b)); return c * smoothstep(uKnee, uKnee + .55, l); }
  void main(){
    vec3 s = texture2D(tMap, vUv).rgb * 4.;
    s += texture2D(tMap, vUv + uTexel * vec2(-1., -1.)).rgb + texture2D(tMap, vUv + uTexel * vec2(1., -1.)).rgb;
    s += texture2D(tMap, vUv + uTexel * vec2(-1., 1.)).rgb + texture2D(tMap, vUv + uTexel * vec2(1., 1.)).rgb;
    s /= 8.;
    gl_FragColor = vec4(uKnee > 0. ? bright(s) : s, 1.);
  }`, { tMap: { value: null }, uTexel: { value: new THREE.Vector2() }, uKnee: { value: 0 } });
const upPass = pass(`
  uniform sampler2D tMap; uniform vec2 uTexel; varying vec2 vUv;
  void main(){
    vec3 s = texture2D(tMap, vUv + uTexel * vec2(-2., 0.)).rgb + texture2D(tMap, vUv + uTexel * vec2(2., 0.)).rgb;
    s += texture2D(tMap, vUv + uTexel * vec2(0., -2.)).rgb + texture2D(tMap, vUv + uTexel * vec2(0., 2.)).rgb;
    s += (texture2D(tMap, vUv + uTexel * vec2(-1., 1.)).rgb + texture2D(tMap, vUv + uTexel * vec2(1., 1.)).rgb
        + texture2D(tMap, vUv + uTexel * vec2(-1., -1.)).rgb + texture2D(tMap, vUv + uTexel * vec2(1., -1.)).rgb) * 2.;
    gl_FragColor = vec4(s / 12., 1.);
  }`, { tMap: { value: null }, uTexel: { value: new THREE.Vector2() } });
upPass.m.blending = THREE.AdditiveBlending; upPass.m.transparent = true;
const finalPass = pass(`
  uniform sampler2D tMap; uniform sampler2D tBloom; uniform float uBloom, uLight, uTime, uDead; varying vec2 vUv;
  float hash(vec2 p){ return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }
  void main(){
    vec3 c = texture2D(tMap, vUv).rgb + texture2D(tBloom, vUv).rgb * uBloom;
    vec3 dark = 1. - exp(-c * 1.12);                               // highlights roll off instead of clipping
    float vig = smoothstep(1.25, .35, length(vUv - .5) * 1.6);
    dark *= mix(.72, 1., vig);
    vec3 lite = clamp(c, 0., 1.) * mix(.965, 1., vig);
    vec3 o = mix(dark, lite, uLight);
    float grey = dot(o, vec3(.299, .587, .114));
    o = mix(o, vec3(grey) * mix(.55, .92, uLight), uDead * .92);                    // not live: the colour drains out
    o += (hash(vUv * 913. + uTime) - .5) / 255.;                                    // dither against banding
    gl_FragColor = vec4(o, 1.);
  }`, { tMap: { value: null }, tBloom: { value: null }, uBloom: { value: 1 }, uLight: U.uLight, uTime: U.uTime,
       uDead: { value: 0 } });

function draw() {
  // 1. everything inside the shell and the far panes
  renderer.setRenderTarget(rtScene);
  renderer.setClearColor(theme.clear, 1); renderer.clear();
  renderer.render(scene, camera);
  // 2. the same picture, with the near panes over it as glass that refracts it
  renderer.setRenderTarget(rtMain);
  copyPass.m.uniforms.tMap.value = rtScene.texture;
  renderer.render(copyPass.s, fsCam);
  tileFront.uniforms.uScene.value = rtScene.texture;
  renderer.render(front, camera);
  // 3. bloom: bright parts, blurred down and back up
  let bloomTex = rtMain.texture;
  if (theme.bloom > 0) {
    let src = rtMain;
    rtBloom.forEach((t, i) => {
      downPass.m.uniforms.tMap.value = src.texture;
      downPass.m.uniforms.uTexel.value.set(1 / src.width, 1 / src.height);
      downPass.m.uniforms.uKnee.value = i === 0 ? 0.9 : 0;
      renderer.setRenderTarget(t); renderer.render(downPass.s, fsCam);
      src = t;
    });
    for (let i = rtBloom.length - 1; i > 0; i--) {
      upPass.m.uniforms.tMap.value = rtBloom[i].texture;
      upPass.m.uniforms.uTexel.value.set(1 / rtBloom[i].width, 1 / rtBloom[i].height);
      renderer.setRenderTarget(rtBloom[i - 1]); renderer.render(upPass.s, fsCam);
    }
    bloomTex = rtBloom[0].texture;
  }
  finalPass.m.uniforms.tMap.value = rtMain.texture;
  finalPass.m.uniforms.tBloom.value = bloomTex;
  finalPass.m.uniforms.uBloom.value = theme.bloom;
  renderer.setRenderTarget(null);
  renderer.render(finalPass.s, fsCam);
}

// ── the two readings: coverage and uptime ──────────────────────────────────
const MODE_MS = 14000, FADE_S = 1.6;
const MODE_TEXT = {
  coverage: ['What is proven', 'Panes show how far each technique is proven. Neurons fire when a collector really runs.'],
  uptime: ['Is it watching right now', 'Each pane fills with the share of the last 24 h that a collector feeding it had fresh evidence. Empty panes have no collector.'],
};
// Jev-guided: stay on what is proven; alternating is one click away, not the default.
let modeSetting = 'coverage', shown = 'coverage', mix = 0, flipAt = performance.now() + MODE_MS, lastT = 0;
function setMode(setting) {
  modeSetting = setting;
  if (setting !== 'auto') shown = setting;
  flipAt = performance.now() + MODE_MS;
  for (const b of document.querySelectorAll('#tools [data-mode]')) b.setAttribute('aria-pressed', b.dataset.mode === setting);
  paintMode();
}
function paintMode() {
  document.body.dataset.mode = shown;
  $('modename').textContent = MODE_TEXT[shown][0];
  $('modehint').textContent = MODE_TEXT[shown][1];
}
function stepMode(t) {
  const dt = Math.min(0.1, Math.max(0, t - lastT)); lastT = t;
  const held = pinned || focus || document.hidden || $('table').style.display === 'block';
  if (modeSetting === 'auto' && !held && performance.now() > flipAt) {
    shown = shown === 'coverage' ? 'uptime' : 'coverage';
    flipAt = performance.now() + MODE_MS;
    paintMode();
  }
  const goalMix = shown === 'uptime' ? 1 : 0;
  mix = calm ? goalMix : mix + (goalMix - mix) * Math.min(1, dt / FADE_S * 3);
  if (Math.abs(goalMix - mix) < 0.002) mix = goalMix;
  U.uMix.value = mix;
  return dt;
}
for (const b of document.querySelectorAll('#tools [data-mode]')) b.onclick = () => setMode(b.dataset.mode);
{ const m = new URLSearchParams(location.hash.slice(1)).get('mode'); setMode(m in MODE_TEXT || m === 'auto' ? m : modeSetting); mix = shown === 'uptime' ? 1 : 0; }
applyTheme();

// Where the panels are, so a tactic label is never drawn underneath one.
let panelBoxes = [];
function measurePanels() {
  // (offsetParent is always null for fixed elements, so visibility is asked of the style)
  panelBoxes = [...document.querySelectorAll('.panel')].filter((p) => p.id !== 'tip' && getComputedStyle(p).display !== 'none').map((p) => {
    const r = p.getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + r.height / 2, half: r.width / 2, tall: r.height / 2 };
  });
}
addEventListener('resize', measurePanels);
setInterval(measurePanels, 1000);
measurePanels();

// ── frame ──────────────────────────────────────────────────────────────────
let slow = 0, frames = 0, frameSum = 0, lastFrame = performance.now();
let wall = 0, deadMix = 0;
function frame() {
  requestAnimationFrame(frame);
  if (document.hidden) { lastFrame = performance.now(); return; }
  // Scene time only advances while the view is live: a dead view is a still one.
  const wallNow = clock.getElapsedTime(), step = Math.min(0.5, wallNow - wall); wall = wallNow;
  deadMix += ((dead ? 1 : 0) - deadMix) * Math.min(1, step * 3);
  sceneTime += step * (1 - deadMix);
  finalPass.m.uniforms.uDead.value = deadMix;
  const t = sceneTime;
  const nowMs = performance.now(), ms = nowMs - lastFrame; lastFrame = nowMs;
  // If the machine cannot keep up, trade resolution for smoothness rather than stutter.
  frames++; frameSum += ms;
  if (frames >= 90) {
    slow = frameSum / frames > 30 ? slow + 1 : 0;
    if (slow >= 2 && dpr > 1) { dpr = Math.max(1, dpr - 0.25); resize(); slow = 0; }
    frames = 0; frameSum = 0;
  }
  if (spin && !drag && !dead && nowMs - lastTouch > 2500) goal.theta += 0.0011;
  if (!drag && Math.abs(vel) > 1e-4) { goal.theta += vel; vel *= 0.94; }      // a released drag coasts
  view.theta += (goal.theta - view.theta) * 0.08;
  view.el += (goal.el - view.el) * 0.08;
  view.dist += (goal.dist - view.dist) * 0.08;
  const ce = Math.cos(view.el);
  camera.position.set(view.dist * ce * Math.cos(view.theta), view.dist * Math.sin(view.el), view.dist * ce * Math.sin(view.theta));
  camera.lookAt(0, 0, 0);

  const dt = stepMode(t);
  U.uTime.value = t;
  U.uScale.value = renderer.domElement.height / (2 * Math.tan((camera.fov * Math.PI) / 360));

  if (world) {
    const prog = world.points.geometry.attributes.aProg, nowS = Date.now() / 1000, run = U.uRun.value;
    for (const n of world.nodes) {
      prog.array[n.index] = n.c.ts ? Math.min(1, (nowS - n.c.ts) / n.c.interval) : 0;
      if (n.index < MAX_NODES) run[n.index] += ((n.c.running ? 1 : 0) - run[n.index]) * Math.min(1, dt * 6);
    }
    prog.needsUpdate = true;
    if (world.sparks.length) {
      const pos = world.motes.geometry.attributes.position;
      world.sparks.forEach((s, i) => {
        const a = s.phase + (calm ? 0 : t * 0.9);
        v3.copy(s.n.pos).addScaledVector(s.u, Math.cos(a) * 0.3).addScaledVector(s.v, Math.sin(a) * 0.3);
        pos.setXYZ(i, v3.x, v3.y, v3.z);
      });
      pos.needsUpdate = true;
    }
    // Labels near the limb of the sphere crowd together on screen. The one
    // facing the camera most keeps its place; a label that would overlap an
    // already placed one is hidden rather than drawn on top of it.
    const placed = panelBoxes.slice();
    world.wedges.map((w, i) => {
      const s = screen(w.tagPos);
      const facing = v3.copy(camera.position).normalize().dot(w.tagPos.clone().normalize());
      return { w, tag: world.tags[i], s, facing };
    }).sort((a, b) => b.facing - a.facing).forEach(({ w, tag, s, facing }) => {
      const dim = (pinned || focus) && (pinned || focus).tactic && (pinned || focus).tactic !== w.name;
      let opacity = s ? Math.max(0, Math.min(1, (facing - 0.42) * 4)) * (dim ? 0.3 : 1) : 0;
      if (opacity > 0.02) {
        const half = tag.offsetWidth / 2 + 8;
        if (placed.some((p) => Math.abs(p.x - s[0]) < p.half + half && Math.abs(p.y - s[1]) < (p.tall || 0) + 16)) opacity = 0;
        else placed.push({ x: s[0], y: s[1], half });
      }
      tag.style.opacity = opacity;
      if (s) { tag.style.left = `${s[0]}px`; tag.style.top = `${s[1]}px`; }
    });
  }
  draw();
}
frame();
