# Zion — Text-to-Video Creative Kit (Extreme Style)

A ready-to-paste prompt kit for text-to-video models (Google **Veo 3 / Gemini**,
also usable on Sora, Kling, Runway Gen-3 with light edits). Built to be faithful
to what Zion actually *is* — a single-binary sovereign TLS edge gateway with a
zero-regex WAF — while pushing the visual language as far as it goes.

> Tip: these models perform best in **English**, so the prompts below are in
> English. The commentary is bilingual. Veo 3 clips are ~8 s each — stitch the
> four shots for a ~32 s film.

---

## 1. Creative brief — what we are dramatising

| Zion concept | Visual metaphor |
|---|---|
| Single-binary edge gateway ("the gate") | One colossal **monolithic gate / wall** — seamless, no seams = one binary |
| Logo = a golden **eye** on black | An **all-seeing eye of liquid gold**, iris made of scrolling code |
| Zero-regex WAF, Aho-Corasick, O(N) single pass | A **lattice of golden light** that ignites and vaporises threats in **one horizontal sweep** |
| DDoS / injection / bot floods | A **tsunami of blood-red packets & glyphs** crashing on the wall |
| XDP eBPF drop at the NIC (before the handshake) | A **spiked outer moat** that disintegrates packets before they touch the wall |
| ~233K req/s, TLS 1.3, hardware crypto | **Ribbons of clean gold-white light** threading *through* the gate at impossible velocity |
| Two-level RAM cache | A serene **crystalline core** glowing warm gold inside the storm |
| AIMP sovereign mesh (Ed25519 gossip) | Many identical monoliths across a dark globe, linked by **thin golden threads** |

**Palette (lock this in every prompt):** molten gold `#eab308` as the single
dominant accent, on near-black `#0a0a0c`. Threats in blood-red. Cold cyan
rim-light. Deep, crushed blacks.

**Tone:** cyberpunk brutalism × Denis Villeneuve scale × Blade Runner 2049
atmosphere. Sublime, ominous, hyperkinetic.

---

## 2. Master prompt — "ZION: THE GATE" (extreme, 8 s, 16:9)

```
Hyper-cinematic, tech-sublime, extreme scale. A colossal monolithic gate stands
alone at the edge of a black digital abyss — a single seamless slab of
obsidian-black metal veined with molten gold circuitry, gold (#eab308) glowing on
pure black (#0a0a0c). At its center a vast all-seeing eye of liquid gold snaps
open, its iris a slowly rotating ring of scrolling code.

An FPV drone camera rockets toward the gate at insane speed. A tidal wave of
malicious traffic — millions of blood-red packets, jagged glowing glyphs — crashes
against the wall like a tsunami of embers. The instant they hit, a lattice of
golden light ignites across the entire surface and in a single horizontal sweep
disintegrates the red swarm into ash: one pass, no mercy.

Simultaneously, thin ribbons of clean gold-white light thread frictionlessly
THROUGH the gate at impossible velocity, leaving long neon motion-trails. The
camera whip-pans and punches through a slit in the gate into a serene inner
sanctum: a glowing crystalline core pulsing warm gold, perfectly silent amid the
storm raging outside.

Style: cyberpunk brutalism meets Villeneuve scale. Volumetric god-rays, heavy
atmospheric haze, fine drifting gold particulate, chromatic aberration and
datamosh glitch on every impact, crushed blacks, one dominant gold accent, cold
cyan rim-light. Ultra-sharp 8K, anamorphic lens flares, aggressive speed ramps,
shallow depth of field.

Audio: sub-bass impact booms, crackling energy sweeps, a low ominous drone rising
to a single resonant gong as the eye opens, high-frequency data-shimmer whooshes
for the passing light streams.
```

**Negative prompt:**
```
text, letters, words, logos, watermark, UI, low quality, blurry, cartoon, anime,
flat lighting, washed-out colors, pastel, cluttered, slow pacing, static locked-off
camera, human faces, distorted anatomy, extra limbs, jpeg artifacts
```

---

## 3. Shot variants — build a ~32 s film (4 × 8 s)

### Shot A — "THE EYE OPENS" (macro → reveal)
```
Extreme macro on a single golden eye whose iris is made of scrolling green-gold
code, slowly rotating. A storm of red data is reflected and distorted across its
liquid-metal cornea. The pupil dilates; the camera slowly pulls back to reveal the
eye is the centerpiece of a mile-high black monolith at the edge of a void.
Villeneuve scale, volumetric haze, gold on crushed black, cyan rim-light, anamorphic
flare, ultra-sharp, ominous. Audio: deep rising drone, a single resonant gong,
faint code-shimmer.
```

### Shot B — "THE FLOOD / WAF KILL" (side profile, the money shot)
```
Wide side-profile. A blood-red tsunami of malicious packets and jagged glyphs
races across a black plain toward a monolithic gold-veined wall. A spiked outer
moat of light drops the first wave to ash before it lands (XDP). The rest slams
the wall — instantly a lattice of golden light ignites and sweeps horizontally
across the surface, vaporising the entire red swarm in one clean pass. Embers rain
down. Slow-motion into real-time speed ramp on impact. Glitch and chromatic
aberration at the moment of contact, gold on black, cinematic, brutal, 8K. Audio:
building roar, then one massive sub-bass boom and a crisp electric sweep.
```

### Shot C — "VELOCITY" (POV, ludicrous speed)
```
First-person POV flying WITH a single glowing gold packet at ludicrous speed
through a tunnel inside the monolith. It blasts through successive rings of light —
a spinning TLS handshake ring, five vertical WAF gates that flick open just in
time, a glowing cache core — motion blur, speed lines, warp-streak highlights, then
bursts out the far side into open black space trailing a comet tail. Relentless
forward momentum, gold and cyan, heavy speed ramps, anamorphic streaks, 8K. Audio:
rising doppler whoosh, rapid ticking gate-clicks, a final release whoosh.
```

### Shot D — "THE SOVEREIGN MESH" (cosmic pull-back, hero end)
```
The camera pulls back from one monolithic gate to reveal dozens of identical black
monoliths standing across the curved surface of a dark planet, each crowned with a
tiny golden eye, all connected by thin pulsing golden threads of light that flicker
as they exchange signals (a mesh, no center). Final push-in on the nearest eye as
it blinks once and locks onto the lens. Epic, silent, sovereign, gold on black,
volumetric, Villeneuve scale, 8K. Audio: sparse ambient drone, soft signal pings
traveling along the threads, one final low note.
```

---

## 4. Technical settings

- **Aspect ratio:** `16:9` for cinematic; regen as `9:16` for Reels/Shorts by
  adding `vertical composition, subject centered` to each prompt.
- **Duration / model:** Veo 3 (in Gemini) → 8 s per generation, native audio.
  Generate each shot separately, then stitch A → B → C → D in an editor.
- **Consistency across shots:** keep the *first two sentences* (the palette +
  "monolithic black gate veined with molten gold, all-seeing golden eye") verbatim
  in every prompt so the model re-locks the same world.
- **Seeds:** if the tool exposes a seed, reuse the winning seed across variants.
- **Music:** the built-in audio is a scratch track. For a final cut, drop the
  Veo audio and lay a dark industrial / synth-brutalist score under it.

---

## 5. Quick one-liner (for a fast test)

```
A mile-high black monolithic gate veined with molten gold, a giant golden eye at
its center opening as a blood-red tsunami of data crashes against it and is
vaporised by a single sweep of golden light; clean gold streams pass through at
impossible speed. Cyberpunk brutalism, Villeneuve scale, gold on crushed black,
volumetric haze, glitch on impact, 8K, ominous sub-bass score.
```

---

## 6. How to push it further / iterate

- **More extreme:** add `bullet-time freeze at the moment of impact`, `reality
  fractures into voxels`, `time reverses and the ash reassembles then shatters
  again`, `infinite-zoom from the eye's pupil into the cache core`.
- **More corporate/clean:** drop "brutalism/glitch", swap to `sleek, minimal,
  Apple-keynote lighting, seamless, elegant`.
- **Dial the threat:** name the attackers as `SQL-injection serpents`,
  `bot-swarm locusts`, `a DDoS hurricane` for more figurative imagery.
- **Keep it legible:** never ask the model to render the "Zion" wordmark or code
  text — video models mangle text. Add your logo/title in post instead.
```
