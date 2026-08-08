/* mini-charts.js - a tiny, dependency-free replacement for the two chart
   types the dashboard actually needs (a line/area chart and a donut
   chart). Pure SVG, no external library, no CDN, works completely
   offline on an isolated lab machine with zero setup. */

function miniLineChart(container, labels, values, opts){
  opts = opts || {};
  const color = opts.color || '#3FB88A';
  const gridColor = opts.gridColor || '#1E232D';
  const textColor = opts.textColor || '#7A8296';
  const w = container.clientWidth || 600;
  const h = container.clientHeight || 200;
  const padL = 36, padB = 26, padT = 14, padR = 14;
  const plotW = w - padL - padR, plotH = h - padT - padB;

  const maxVal = Math.max(1, ...values);
  const stepX = values.length > 1 ? plotW / (values.length - 1) : 0;

  const points = values.map((v, i) => {
    const x = padL + i * stepX;
    const y = padT + plotH - (v / maxVal) * plotH;
    return [x, y];
  });

  const linePath = points.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
  const areaPath = linePath +
    ` L${(points[points.length - 1] || [padL, padT + plotH])[0].toFixed(1)},${(padT + plotH).toFixed(1)}` +
    ` L${padL},${(padT + plotH).toFixed(1)} Z`;

  // Gridlines at 0, mid, max
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map(f => {
    const y = padT + plotH - f * plotH;
    const val = Math.round(maxVal * f);
    return `<line x1="${padL}" y1="${y}" x2="${w - padR}" y2="${y}" stroke="${gridColor}" stroke-width="1"/>
            <text x="${padL - 8}" y="${y + 4}" text-anchor="end" font-size="12" font-family="IBM Plex Mono" fill="${textColor}">${val}</text>`;
  }).join('');

  // A handful of x-axis labels (avoid crowding if there are many points)
  const labelStep = Math.max(1, Math.ceil(labels.length / 8));
  const xLabels = labels.map((lab, i) => {
    if (i % labelStep !== 0) return '';
    const x = padL + i * stepX;
    return `<text x="${x}" y="${h - 4}" text-anchor="middle" font-size="12" font-family="IBM Plex Mono" fill="${textColor}">${lab}</text>`;
  }).join('');

  container.innerHTML = `<svg width="100%" height="100%" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="display:block;">
    ${gridLines}
    <path d="${areaPath}" fill="${color}" opacity="0.14" stroke="none"/>
    <path d="${linePath}" fill="none" stroke="${color}" stroke-width="3"/>
    ${points.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="4" fill="${color}"/>`).join('')}
    ${xLabels}
  </svg>`;
}

function miniDonutChart(container, labels, values, colors, opts){
  opts = opts || {};
  const textColor = opts.textColor || '#E6E9EF';
  const bgColor = opts.bgColor || '#11141B';
  const size = Math.min(container.clientWidth || 180, container.clientHeight || 180);
  const cx = size / 2, cy = size / 2, r = size / 2 - 4, innerR = r * 0.6;
  const total = values.reduce((a, b) => a + b, 0);

  let segments = '';
  if (total === 0){
    segments = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${bgColor}" stroke-width="${r - innerR}"/>`;
  } else {
    let angle = -90; // start at 12 o'clock
    values.forEach((v, i) => {
      if (v <= 0) return;
      const slice = (v / total) * 360;
      const largeArc = slice > 180 ? 1 : 0;
      const startRad = (angle * Math.PI) / 180;
      const endRad = ((angle + slice) * Math.PI) / 180;
      const x1 = cx + r * Math.cos(startRad), y1 = cy + r * Math.sin(startRad);
      const x2 = cx + r * Math.cos(endRad), y2 = cy + r * Math.sin(endRad);
      const ix1 = cx + innerR * Math.cos(startRad), iy1 = cy + innerR * Math.sin(startRad);
      const ix2 = cx + innerR * Math.cos(endRad), iy2 = cy + innerR * Math.sin(endRad);
      segments += `<path d="M${ix1},${iy1} L${x1},${y1} A${r},${r} 0 ${largeArc} 1 ${x2},${y2}
                    L${ix2},${iy2} A${innerR},${innerR} 0 ${largeArc} 0 ${ix1},${iy1} Z"
                    fill="${colors[i]}" stroke="${bgColor}" stroke-width="1.5"/>`;
      angle += slice;
    });
  }

  const legend = labels.map((lab, i) =>
    `<div style="display:flex; align-items:center; gap:9px; margin-bottom:10px;">
       <span style="width:13px; height:13px; border-radius:3px; background:${colors[i]}; display:inline-block; flex-shrink:0;"></span>
       <span style="font-family:IBM Plex Sans; font-size:14px; color:${textColor};">${lab} (${values[i] || 0})</span>
     </div>`
  ).join('');

  container.innerHTML = `<div style="display:flex; align-items:center; gap:18px; height:100%;">
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="flex-shrink:0;">${segments}</svg>
    <div>${legend}</div>
  </div>`;
}
