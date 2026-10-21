---
name: PhishShield AI
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#bcc9cd'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#869397'
  outline-variant: '#3d494c'
  surface-tint: '#4cd7f6'
  primary: '#4cd7f6'
  on-primary: '#003640'
  primary-container: '#06b6d4'
  on-primary-container: '#00424f'
  inverse-primary: '#00687a'
  secondary: '#d0bcff'
  on-secondary: '#3c0091'
  secondary-container: '#571bc1'
  on-secondary-container: '#c4abff'
  tertiary: '#4edea3'
  on-tertiary: '#003824'
  tertiary-container: '#1bbd85'
  on-tertiary-container: '#00452e'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#acedff'
  primary-fixed-dim: '#4cd7f6'
  on-primary-fixed: '#001f26'
  on-primary-fixed-variant: '#004e5c'
  secondary-fixed: '#e9ddff'
  secondary-fixed-dim: '#d0bcff'
  on-secondary-fixed: '#23005c'
  on-secondary-fixed-variant: '#5516be'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  display-hero:
    fontFamily: Inter
    fontSize: 44px
    fontWeight: '700'
    lineHeight: 52px
    letterSpacing: -0.025em
  display-hero-mobile:
    fontFamily: Inter
    fontSize: 30px
    fontWeight: '700'
    lineHeight: 38px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Inter
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.015em
  headline-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: 0em
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: 0.01em
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 18px
    letterSpacing: -0.01em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.08em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-desktop: 1.5rem
  margin: 1rem
  margin-tablet: 1.5rem
  margin-desktop: 2.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
  space-2xl: 3rem
---

## Brand & Style
The design system establishes a high-trust, elite cyber-intelligence posture tailored for security analysts, SecOps leads, and enterprise IT administrators. The aesthetic combines tactical precision with cutting-edge artificial intelligence telemetry. It avoids frivolous sci-fi tropes in favor of an institutional, high-clarity command-center feel: deep space navy fields, crisp structural gridlines, subtle optical glows, and instantaneous visual prioritization of threat vectors.

### Style Directives
- **Visual Stance:** A calibrated synthesis of Technical Minimalism and Subdued Glassmorphism. Dark-mode native, high contrast, zero unnecessary visual noise.
- **Tone:** Authoritative, vigilant, rapid-scan, and surgically accurate.
- **Atmosphere:** Deep indigo/slate canvases layered with semi-translucent operational cards, illuminated by purposeful cyan and violet telemetry highlights, anchored by unmistakable threat-level signifiers.

## Colors
The color hierarchy is optimized for prolonged SOC monitoring under dim ambient conditions while ensuring instant detection of risk states.

### Palette Architecture
- **Canvas Base:** `#0A0F1D` (Absolute deep canvas), `#0F172A` (System canvas and section grouping).
- **Surfaces & Tiers:** `#161F36` (Recessed containers, table strips), `#1E293B` (Elevated cards, inspector panes, control panels).
- **Borders & Dividers:** `rgba(148, 163, 184, 0.12)` (Standard containment), `rgba(6, 182, 212, 0.35)` (Focused cyber-accent borders).
- **Primary Cyber Accent:** `#06B6D4` (Electric Cyan)—signals system readiness, live scans, active nodes, and principal calls to action.
- **Secondary Cyber Accent:** `#8B5CF6` (Electric Violet)—signals AI inference, automated heuristics, and machine learning model metrics.
- **Text & Glyph Hierarchy:**
  - High Emphasis: `#F8FAFC` (98% contrast against canvas).
  - Medium Emphasis: `#94A3B8` (Telemetry labels, secondary parameters).
  - Low Emphasis / Disabled: `#475569` (Inactive status, grid guides).

### Threat & Severity Tokens
Severity signaling adheres to strict universal semantics:
- **Critical Risk:** `#EF4444` (Crimson Red) — Active phishing attack, credential harvesting detected.
- **High Risk:** `#F97316` (Deep Amber-Orange) — Suspicious domain spoofing, anomalous DKIM/SPF mismatch.
- **Medium Risk:** `#EAB308` (Cyber Yellow) — Untrusted newly registered domain, obfuscated redirects.
- **Low / Safe:** `#10B981` (Emerald Mint) — Validated authentic infrastructure, safe baseline.

## Typography
Typography is split into dual operational roles: **Inter** handles narrative clarity, system alerts, and primary UI navigation, while **JetBrains Mono** enforces structured, tabular machine telemetry, payload hashes, raw URLs, IP addresses, and threat taxonomy chips.

### Typography Rules
- **Monospace Deployment:** Mandatory for all digital footprints: SHA-256 signatures, encoded mail headers, domain structures, and status metric pill counters.
- **Data Scannability:** Use `label-caps` for telemetry metadata headers (e.g., `SCAN_VECTOR`, `CONFIDENCE_SCORE`) in uppercase with loose tracking.
- **Font Rendering:** Enforce `-webkit-font-smoothing: antialiased` across all platforms to preserve razor-sharp legibility on dark surfaces.

## Layout & Spacing
The layout follows a responsive 12-column fluid grid system geared towards dense, multi-pane situational awareness.

### Layout Specs & Responsive Matrix
- **Mobile (&lt; 768px):** 4-column layout, `margin: 1rem`, `gutter: 1rem`. Sidebars collapse to off-canvas tactical drawers; telemetry cards stack linearly.
- **Tablet (768px - 1024px):** 8-column layout, `margin: 1.5rem`, `gutter: 1rem`. Incident feeds and live threat inspectors display in a 5:3 column split.
- **Desktop (&gt; 1024px):** 12-column layout, `margin: 2.5rem`, `gutter: 1.5rem`. Maximum content bounds pinned to `1600px` for ultra-wide SOC displays with persistent collapsed toolbars.
- **Density Standard:** High spatial economy. Information density is prioritized over wide decorative negative space. Component gaps default to `space-sm` (8px) within functional groups and `space-md` (16px) between independent diagnostic widgets.

## Elevation & Depth
Elevation is generated through translucent luminous borders and dark tonal tiering rather than heavy drop shadows, maintaining crisp visibility in dark viewports.

### Depth System
1. **Tier 0 (Base Canvas):** `#0A0F1D`. Plain background with a faint, procedural 32px SVG coordinate grid overlay rendered at `rgba(255, 255, 255, 0.02)`.
2. **Tier 1 (Structural Containers):** `#0F172A` with a 1px border of `rgba(148, 163, 184, 0.08)`.
3. **Tier 2 (Interactive Cards & Panels):** Backdrop blur of `16px`, background fill of `rgba(30, 41, 59, 0.7)`, enclosed by a 1px border of `rgba(148, 163, 184, 0.15)`.
4. **Tier 3 (Active Threat Interceptors & Modals):** Background fill of `rgba(22, 31, 54, 0.95)`, 1px accent border matching the threat tier (e.g., `rgba(239, 68, 68, 0.4)` for Critical), accompanied by a targeted ambient glow: `0 0 24px -4px rgba(239, 68, 68, 0.25)`.
5. **Cyber Accent Focus Glows:** Hovering or focusing interactive modules generates a radial outer rim glow: `0 0 16px -2px rgba(6, 182, 212, 0.35)`.

## Shapes
The shape philosophy is restrained and technical (`roundedness: 1` / Soft). This avoids both fragile sharp points and playful oversized bubbles, echoing hardened defense equipment and tactical displays.

- **Base Components (Inputs, Chips, Buttons):** `0.25rem` (4px).
- **Cards & Data Modules:** `0.5rem` (8px).
- **Overlays, Modals, Flyouts:** `0.75rem` (12px).
- **Indicator Dots & Pill Tags:** Fully pill-shaped (`9999px`) reserved strictly for status dots and micro tag counts.

## Components

### Buttons
- **Primary Cyber:** Solid `#06B6D4` background, `#0A0F1D` bold text. On hover: shifts brightness up with a `0 0 14px rgba(6, 182, 212, 0.45)` aura.
- **Secondary Heuristic:** Dark indigo surface `#1E293B`, 1px border in `rgba(139, 92, 246, 0.4)`, text in `#F8FAFC`. On hover: border expands to solid `#8B5CF6` with a soft purple rim glow.
- **Destructive/Quarantine:** Dark crimson fill `rgba(239, 68, 68, 0.12)`, 1px border `#EF4444`, text `#EF4444`.
- **Sizing:** Compact (32px height for tables/toolbars) and Standard (40px height for main forms). All typography uses `font-weight: 600`.

### Chips & Threat Badges
- **Structure:** 22px height, 4px corner radius, inline SVG indicator icon, `label-caps` typography (`JetBrains Mono`).
- **Critical Risk:** Background `rgba(239, 68, 68, 0.12)`, text `#FCA5A5`, border `rgba(239, 68, 68, 0.35)`.
- **High Risk:** Background `rgba(249, 115, 22, 0.12)`, text `#FDBA74`, border `rgba(249, 115, 22, 0.35)`.
- **Medium Risk:** Background `rgba(234, 179, 8, 0.12)`, text `#FDE047`, border `rgba(234, 179, 8, 0.35)`.
- **Safe / Neutral:** Background `rgba(16, 185, 129, 0.12)`, text `#6EE7B7`, border `rgba(16, 185, 129, 0.35)`.

### Input Fields & URL Scanners
- **Background:** Deep inset slate `#0F172A`, 1px border `rgba(148, 163, 184, 0.2)`.
- **Typography:** `JetBrains Mono` for URL parsing and search fields.
- **Active / Scan State:** Border pulses between `#06B6D4` and `#8B5CF6` via a clean linear CSS transition. Embedded prefix features clear protocol indicators (`https://` in `#06B6D4`, untrusted strings highlighted in `#EF4444`).

### Checkboxes & Radios
- **Control Base:** 16x16px, `#1E293B` container, `0.25rem` radius for checkboxes, full circle for radios, border `rgba(148, 163, 184, 0.3)`.
- **Selected State:** Fill `#06B6D4`, icon/dot `#0A0F1D`, outer ring glow `0 0 8px rgba(6, 182, 212, 0.4)`.

### Cards & Telemetry Panels
- **Structure:** Background `rgba(30, 41, 59, 0.55)`, backdrop filter blur `12px`, 1px border `rgba(148, 163, 184, 0.1)`.
- **Header:** Integrated uppercase subtitle (`label-caps`), live telemetry state indicator, and contextual action menu.
- **Metric Grids:** Split into compact key-value data matrices with micro bar indicators and sparklines rendered in `#06B6D4` or dynamic severity hues.

### Threat Inspection Drawer
- Slide-over panel docked to the right edge. Heavy backdrop blur (`24px`), dark indigo solid backdrop (`#0F172A`), dividing perimeter illuminated by a vertical 1px gradient line fading from `#06B6D4` to `#8B5CF6`. Features payload disassembly tabs and sandboxed link detonator previews.