> **Technical Documentation · v1**

# RTP / RTCP / SIP Voice Quality Analyzer

A self-contained web app (a single HTML file, no server) that analyzes `.pcap`/`.pcapng` traces of voice-over-IP calls: it decodes RTP and RTCP directly from the captured packets, correlates SIP signaling when present, and calculates jitter, loss, bandwidth, clock drift, and an estimated MOS — all running in your own browser, with the trace never leaving your machine.

## 1 Loading a Trace

When you open the app you'll see a top panel with a file picker, two port fields, and several buttons. No prior setup is needed: just pick the file and click `▶ Analyze trace`.

### 1.1 Supported formats

The parsing engine implements its own binary reader (no external libraries) compatible with:

- **Classic pcap** (the "traditional" tcpdump/Wireshark format) — all four possible magic numbers are detected automatically (microsecond or nanosecond resolution, in either byte order).
- **pcapng** (the default format in modern Wireshark versions) — Section Header, Interface Description, and Enhanced Packet Block blocks are all processed, including the timestamp resolution declared by each interface.

At the link layer, **Ethernet** frames (with or without 802.1Q VLAN tags), **Linux cooked capture (SLL)** — typical of captures made with `tcpdump -i any` — and **raw IP** are all recognized. Above that, **IPv4 + UDP** is processed (RTP, RTCP, and also SIP) as well as **IPv4 + TCP** (SIP signaling only, see [2.5](#s2-5)); IPv6 isn't decoded.

### 1.2 UDP port range

Since a pcap can contain traffic from many different things at once, you need to tell the app which UDP port range corresponds to the media (RTP/RTCP) of the call you want to analyze — for example `10000` to `20000`, a common range on many PBXs and SBCs.

**Important** This range **only affects RTP/RTCP**. SIP signaling is searched for across *all* UDP traffic in the trace regardless of what you set here, since signaling and media conventionally use different ports (see [2.5](#s2-5)).

A UDP packet is considered "within range" if its **source or destination** port falls in the interval — it doesn't need to be both, since in many captures only one direction is clearly visible, or the port range differs slightly between endpoints.

### 1.3 Sample trace

The `Load sample trace` button loads a synthetic capture bundled with the app itself (it never leaves your browser, it's embedded as base64 inside the HTML file), with two RTP calls, RTCP reports, a packet loss event, a jitter spike, and a simulated clock drift — useful for seeing every feature in action without needing to upload anything of your own.

### 1.4 Status messages

After analyzing, a green or red message appears with a summary: total frames read, UDP packets within range, how many were classified as RTP/RTCP, how many SIP messages and dialogs were found, and how many flows/calls were detected in total. If any RTCP SSRC was discarded as likely noise (see [section 6](#s6)), that's noted here too.

**If nothing is detected** The error message will tell you how many UDP packets were in range versus the trace's total. If it's 0, it's almost always because the port range doesn't match what that call actually uses — widen it (e.g. to `0`–`65535`) and try again to locate it.

## 2 What the Engine Does Internally

This section explains, step by step, everything that happens between clicking "Analyze" and the results appearing. It helps you understand why the app classifies things the way it does, and what to do if a particular file doesn't behave as expected.

### 2.1 Reading the container

The file is read entirely into memory as an `ArrayBuffer` and walked frame by frame, extracting from each one its real capture timestamp (in seconds, at microsecond precision or better) and its raw bytes.

### 2.2 From Ethernet to UDP

For each frame, the link-layer header is skipped (Ethernet/SLL/raw IP), the IP version is checked to be 4 and the protocol UDP (17), and the source IP, destination IP, source port, destination port, and UDP payload are extracted. Anything that isn't IPv4+UDP is silently dropped at this step.

### 2.3 RTP vs RTCP

Every UDP payload within the port range is classified with the same heuristic Wireshark's dynamic dissectors use:

| Condition | Classification |
|----|----|
| Version (top 2 bits of the first byte) ≠ 2 | None — ignored |
| Version = 2 and second byte between 192 and 223 | **RTCP** (SR / RR / SDES / BYE / APP) |
| Version = 2, not RTCP, and at least 12 bytes | **RTP** |

A decoded RTP packet provides: version, padding, extension, CSRC count, marker, payload type (PT), sequence number, RTP timestamp, and SSRC. An RTCP packet is decoded as a *compound packet* (it can carry several concatenated sub-packets: e.g. an SR followed by an SDES), and from each reception report block the source SSRC, fraction lost, cumulative loss, highest sequence received, jitter, and (if it's an SR) the sender's own sending stats are extracted.

### 2.4 Grouping into flows

Each RTP packet is grouped into a flow identified by the tuple `source IP:port → destination IP:port | SSRC`. This means a normal bidirectional call produces **two flows** (one per direction), each with its own SSRC — the same convention Wireshark uses in its "RTP Streams".

RTCP reports are matched to a flow by the "source SSRC" field of each report block — i.e. by who the report describes, not by which port it arrived on. This is more robust than assuming the "RTP port + 1" convention, which doesn't always hold.

### 2.5 SIP signaling and SDP

Regardless of the configured port range, the app scans *all* UDP traffic for SIP messages: any payload starting with a method (`INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`, `REGISTER`, `PRACK`, `SUBSCRIBE`, `NOTIFY`, `REFER`, `MESSAGE`, `UPDATE`, `INFO`, `PUBLISH`) or a response line `SIP/2.0 <code>`.

From each message its headers are extracted (including compact forms: `i`=Call-ID, `f`=From, `t`=To, `m`=Contact, `v`=Via, `l`=Content-Length, `c`=Content-Type), and if the body is SDP, it's parsed looking for `m=audio <port> ...` lines and `a=rtpmap:<PT> <codec>/<rate>` lines.

All messages with the same Call-ID are grouped into a **dialog**. A dialog with at least one `INVITE` is treated as a real call; the rest (typically repeated `OPTIONS`) are treated as health-check traffic between network elements and summarized in a single line instead of listed one by one.

This information builds two internal maps that feed the rest of the app:

- **Negotiated port/IP → codec and rate**, to know the real clock rate of a dynamic flow (see 2.6).
- **Negotiated port/IP → Call-ID**, to link each RTP flow back to the SIP dialog that originated it (see [section 3](#s3)).

**SIP over TCP too** Many real deployments (for example Microsoft Teams Direct Routing / PSTN hub, or any SIP trunk configured for TCP or TLS transport) carry signaling over TCP instead of UDP. The app also analyzes the trace's TCP traffic: it reassembles each connection into a single byte stream ordered by sequence number (discarding retransmissions), and extracts complete SIP messages from it using the `Content-Length` header to know exactly where each one ends — necessary because in TCP a single message can be split across several packets, or several messages can arrive glued together in one. **Encrypted** SIP traffic (TLS/SIPS) can't be interpreted, since there's no decryption key available.

### 2.6 Clock rate

Calculating jitter, skew, and clock drift from RTP timestamps requires knowing the codec's sampling frequency — a value that **doesn't** travel in every RTP packet, it's only negotiated once in signaling. The app determines it with this priority, from most to least reliable:

1.  **Negotiated SDP** — if there's SIP signaling and its SDP explicitly declared that payload type with `a=rtpmap`, that frequency is used. It's the only 100% reliable source, since it's what was actually agreed for that specific call.
2.  **Static payload type (RFC 3551)** — if there's no SDP but the PT is one defined by the standard (0=PCMU/8000, 8=PCMA/8000, 18=G.729/8000, etc.), the standard's fixed frequency is used.
3.  **Automatic estimation** — for dynamic types (96–127) with no SDP, how much the RTP timestamp advances is compared against the real arrival interval, picking the common frequency (8000/16000/32000/44100/48000/90000 Hz) that best fits the observed pattern. This correctly detects cases like **Opus**, whose RTP always uses 48000 Hz even when the audio is in narrowband mode.
4.  **Manual** — if none of the above matches reality, you can force it yourself from the selector in the detail view (see [5.2](#s5-2)).

**Why this matters** Using the wrong clock rate doesn't give you a "slightly different" jitter: it wrecks it completely. We've seen real cases where assuming 8000 Hz on a flow that was actually Opus at 48000 Hz produced a calculated jitter of ~99 ms when the real one was 0.08 ms — a factor of more than 1000×. If you ever see a jitter that doesn't make sense, check first what clock rate is being used.

## 3 The "SIP Signaling" Section

Appears automatically above the calls table **only if the trace contains SIP traffic** — if there's none, the section stays hidden and doesn't get in the way.

It shows a summary ("N SIP message(s) · M dialog(s) — X call(s) with INVITE, Y check/registration exchanges") and, for each real call, a card **collapsed by default** showing only the first line:

**A:** 10.10.82.60:5071 (sip:34999991538@10.10.64.24)   **B:** 10.10.64.24:5062 (sip:5350@10.10.64.24)  
Call-ID: ddb7c66ed91c4e80b5fe0fcb128adf28 · 113.9 s · 27 messages

Clicking that header expands the full detail: each message in the dialog with an arrow showing who sent it (`──→` or `←──`, calculated from the real IP, not order of appearance), the exact IPs of that hop, and — if that particular message carried SDP — a summary of the codecs it offers right below, in purple, next to a **"View full SDP ▸"** button that expands the complete SDP body exactly as it came in the packet (every `v=`, `o=`, `s=`, `c=`, `t=`, `m=` line and any `a=` attribute, not just the codecs). At the end of the call, every codec seen anywhere in the dialog is summarized.

Response codes are color-coded by type: **1xx** provisional, **2xx** success, **3–6xx** redirect/error.

#### Link to RTP flows

Whether collapsed or expanded, every call card shows a **"🔊 RTP flow(s) for this call"** button with a chip per associated flow. Clicking it takes you straight to that flow's detail. The link is bidirectional: in a flow's detail view, if it could be matched to a SIP call, a **"📞 Associated SIP call"** note appears with the From/To and matching Call-ID.

## 4 Detected Calls Table

This is the main view after analyzing a trace: one row per detected RTP flow (or "RTCP only" pseudo-flow, see [section 6](#s6)), with its most important metrics laid out in columns for at-a-glance comparison.

### 4.1 Table columns

| Column | Source | What it shows |
|----|----|----|
| Call / flow | — | Call N-Flow X label (see 4.2) + IP:port → IP:port (PT, SSRC) |
| Duration | **RTP** | Sum of the intervals between captured packets |
| Estimated MOS | **RTP** | Heuristic from jitter and loss calculated from the packets (see 8) |
| Min / avg / max jitter | **RTP** | RFC 3550 jitter estimator over the captured packets |
| Packet loss | **RTP** | % of gaps in the RTP sequence number |
| Average bandwidth | **RTP** | Median of the instantaneous per-packet bitrate (robust to one-off bursts) |
| Nominal BW (RTP) | **RTP** | Bitrate calculated only from the RTP timestamp and total bytes — immune to capture artifacts (see 5.7) |
| Avg / max cadence (delta) | **RTP** | Real interval between consecutive packets |
| Max skew | **RTP** | Maximum cumulative displacement between real and expected arrival |
| MOS / min-avg-max jitter / loss **(RTCP)** | **RTCP** | The same concepts, but calculated exclusively from what the receiver reports over RTCP — to cross-check against the RTP columns. Shows "–" if that flow has no RTCP report. |

Every numeric cell carries a colored *chip* (green / amber / red) based on rough thresholds — explained in the [methodology](#s8) section. The table has its own horizontal scroll if it doesn't fit the screen.

### 4.2 "Call N-Flow X" labels

When it can be established that two (or more) flows belong to the same call, they're labeled together as **Call 1-Flow A** and **Call 1-Flow B** instead of as independent entries. This can be determined two ways:

1.  **Via SIP signaling** — if there's a SIP dialog that negotiated that flow (see section 3).
2.  **Via IP correlation in RTCP**, with no SIP needed — every RTCP report records both who sends it and who it's sent to. If flow A is reported by IP P (sent to IP Q), and flow B is reported by IP Q (sent to IP P), that's the classic signature of a bidirectional call between P and Q, and both flows are grouped automatically even without a single SIP packet in the trace.

Flows that can't be correlated either way are simply numbered **Flow 1**, **Flow 2**... (instead of "Call N", so as not to imply a grouping that couldn't be confirmed). This same numbering is used in the tabs, the CSV, and the exported report.

### 4.3 Filters

Above the table there's a filter panel with:

- **Source IP / port** and **destination IP / port**, as two independent text fields — so you can isolate one specific direction of a bidirectional call without the filter returning both directions just because they share the same two IPs.
- **Min/max range** for every numeric metric (MOS, jitter, loss, bandwidth, cadence, skew) — you can leave just the minimum, just the maximum, or both.

Filtering is live (no "search" button), shows a "Showing X of Y calls" counter when any filter is active, and a **Clear filters** button resets everything at once. Filters reset automatically when a new file is loaded.

**Note on exporting** Filters only affect what you see on screen. Both the CSV and the exported HTML report always include **every** detected call, filtered or not.

## 5 Flow Detail View

Opens by clicking a table row or a flow tab. Contains the full breakdown of that specific flow.

### 5.1 RTP gauges

Seven cards with the main metrics, calculated from the captured RTP packets:

Estimated MOS

4.16

Average jitter

1.88 ms

Packet loss

0.78 %

Average bandwidth

85.6 kbps

Cadence (delta)

20.0 ms

Clock drift (skew)

19.3 ms

Freq. Drift

195.6 ppm

The average jitter gauge also notes the observed minimum and maximum; the bandwidth one notes the nominal bandwidth (see 4.1) when available, or the min–max range otherwise.

**Clock drift and Freq. Drift** These two gauges show "· no sustained drift confirmed" when skew swings (sometimes quite a bit) but **not** in a sustained way through to the end of the call — typical of an isolated network hiccup, not a real desynchronized clock. The notice appears whenever the internal sustained-drift check (which requires a minimum net displacement) isn't confirmed, even if the ppm itself looks high. Always cross-check against the skew chart (5.5) before trusting the ppm: if skew returns close to 0 by the end, it's an isolated hiccup; if it keeps growing to the end, it's real drift.

### 5.2 Flow clock rate

Right below the gauges, a card shows the clock frequency used for this flow and where it came from, color-coded by confidence:

| Color | Source |
|----|----|
| **Green** | Taken from the SDP negotiated in SIP signaling — includes the codec name |
| Gray | Static payload type (RFC 3551) or manually adjusted by you |
| **Amber** | Dynamic type with no SDP available: estimated automatically by comparing RTP timestamp against real arrival |

The dropdown next to it lets you manually force 8000 / 16000 / 32000 / 44100 / 48000 / 90000 Hz — changing it recalculates **every** metric for that flow (jitter, skew, drift, charts) instantly with the new rate.

### 5.3 RTCP summary

If the flow has any associated RTCP report, this card appears with two blocks:

#### Sender self-check

If any SR report had the sender declare how many packets and bytes it has sent in total, that's compared against what was actually captured here for that same flow. If the two numbers are the same order of magnitude, it's shown in green; if the gap is enormous, in red with a warning — this can happen if RTCP is encrypted (SRTCP, see 5.7), if the counter belongs to a previous session that wasn't reset, or if the packet is corrupt.

#### Reception reports

Makes it clear, in one sentence, that this data is reported by **whoever receives** the flow, not whoever sends it. If more than one receiver is reporting on the same SSRC, they're broken out separately (one per receiver) instead of mixing their figures into a single average. It also clarifies that "SR" and "RR" don't indicate whose flow it is, but whether whoever is reporting was sending RTP at that moment (SR) or only receiving (RR).

**RTCP jitter units** RTCP's jitter field **isn't in milliseconds**: it's in the same units as the codec's RTP timestamp (RFC 3550 §6.4.1). The app already does the conversion (`ticks ÷ clock_rate × 1000`) using that flow's real clock rate — if you see the raw value in another tool without conversion, it will look much higher than it really is.

When the app can't match any RTCP report to a flow but detects that the other end did send RTCP-shaped packets, it checks whether the SSRC those packets declare changes erratically from one to the next — if so, it warns that it's likely **encrypted RTCP (SRTCP)** that can't be interpreted, instead of just saying "no reports".

### 5.4 RTCP gauges

Right below the summary, two additional cards in the same style as 5.1 but calculated only from RTCP: **Average jitter (RTCP)** and **Packet loss (RTCP)**. They only appear when the flow has both RTP *and* RTCP (in an "RTCP only" flow this information is already what the main gauges show, so it isn't duplicated).

### 5.5 RTP charts

Six time-series charts, in this order:

1.  **Jitter (ms) per packet**
2.  **Packet loss (%) per bucket** — right below the jitter one
3.  **Inter-packet interval — Delta (ms)**
4.  **Bandwidth (kbps)**
5.  **Skew (ms) — cumulative drift**, with its text explanation right below (see 5.7)
6.  **Estimated MOS per bucket** — the same MOS formula applied to segments of the flow, to see if quality drops at any specific point in the call

The **X axis shows the real elapsed seconds of the call**, and hovering over any point also shows the exact RTP sequence number for that instant in the tooltip. When a flow has many packets, data is grouped into buckets (up to 160 points) averaging each bucket, so the chart stays legible — noted with "averaged per bucket" in each chart's header.

### 5.6 RTCP charts

Two additional charts, tagged **RTCP**, showing **Reported jitter (ms)** and **Reported loss (%)** exactly as each RTCP report declared them over the call — with real points marked (not interpolated) since RTCP reports usually arrive every few seconds, not packet by packet. If more than one receiver is reporting on the same flow, each one is drawn in a different color with a legend.

### 5.7 Capture artifact detection

An amber notice can appear under the jitter chart when **all** of these conditions hold at once:

1.  The calculated average jitter is significant (≥ 2 ms).
2.  Inter-packet intervals are **bimodal**: they cluster into two well-separated groups (e.g. many around 15 ms and many others around 31 ms) instead of spreading continuously around the nominal value.
3.  The **sender's own RTP timestamp** advances perfectly evenly (≥95% of intervals are identical) — meaning the sender transmitted with no real issue.

When all three hold, the irregularity wasn't generated by the sender nor experienced by the call over the network: it was introduced **between the sender and the capture point** — packet batching while capturing, network interrupt coalescing, virtualization... If the trace is a `.pcapng` and its interface metadata mentions a known virtual adapter (vmxnet, virtio, Hyper-V, VMware, Xen, VirtualBox, QEMU, Parallels), the app confirms this explicitly, quoting the exact interface name.

In these cases, the notice also includes the **nominal bandwidth** (calculated only from the RTP timestamp, immune to this artifact) as a more representative figure than the observed "average bandwidth", which does get inflated by the artifact itself.

### 5.8 Anomaly log

Table with one-off events detected in the flow:

| Type | Severity | When it appears |
|----|----|----|
| Packets lost | **Critical** | Real gap in the RTP sequence number |
| Possible reordering | **Attention** | A packet arrives with a sequence number equal to or lower than the previous one |
| Jitter spike | **Attention** | One-off jitter \> 4× the flow's median |
| Cadence cut | **Attention** | One-off delta \> 4× the flow's median |
| Clock drift | **Attention** | Skew with a sustained net displacement (see 8) |

If there's nothing to report, a green confirmation message is shown instead of an empty table.

## 6 Flujos "solo RTCP"

Si un SSRC aparece mencionado en varios informes RTCP pero nunca se capturó ningún paquete RTP suyo (por ejemplo, porque el RTP real usa un puerto fuera del rango indicado, la ruta es asimétrica, o esos paquetes se perdieron en la propia captura), la aplicación no descarta esa información: crea un pseudo-flujo etiquetado **solo RTCP** basado exclusivamente en lo que dicen esos informes.

Estos flujos se comportan de forma distinta al resto:

- Su identificador muestra directamente **la IP y puerto de quien envía el informe** (ej. `SSRC 0x1234 · RTCP de 10.0.0.2:30001`), en vez de un origen/destino RTP que nunca se llegó a ver.
- Solo se muestran **tres medidores** (MOS, Jitter, Pérdida) — los únicos calculables sin paquetes reales.
- **No hay gráficas ni registro de anomalías** (no existen datos paquete a paquete que representar); en su lugar aparece un aviso explicando la situación, incluyendo la IP que informa.
- En la tabla y el CSV, las columnas que dependen de paquetes RTP (ancho de banda, cadencia, skew) muestran `–` / `N/D` en vez de un valor.
- Si se puede correlacionar con otro flujo "solo RTCP" de la misma llamada bidireccional (ver 4.2), ambos se agrupan como **Llamada N-Flujo A/B**.

**Filtro de ruido** Un SSRC con un único informe RTCP suelto (que nunca se repite) no se convierte en un pseudo-flujo — se descarta como probable ruido o RTCP cifrado no interpretable, cuyo síntoma típico es precisamente generar un "SSRC" distinto y aparentemente aleatorio en cada paquete. Se exige un mínimo de 2 informes del mismo SSRC para considerarlo una llamada real. Si se descarta alguno, se indica cuántos en el mensaje de estado tras analizar.

## 7 Exportar resultados

### 7.1 Exportar CSV

Descarga una fila por cada llamada/flujo con **todas** las métricas calculadas: duración, diagnóstico, MOS, jitter (mín/medio/máx), pérdida, ancho de banda (medio/mín/máx/nominal), cadencia, skew, deriva de reloj y ppm, picos detectados, y las cinco columnas equivalentes calculadas desde RTCP. El fichero se codifica en UTF-8 con BOM para que Excel muestre bien los acentos.

### 7.2 Exportar informe HTML

Genera un documento HTML **estático y autocontenido** (sin JavaScript de interacción, para poder archivarlo o enviarlo por correo) con:

- La sección de señalización SIP, ya desplegada por completo (sin necesidad de clic, porque un documento estático no puede recibir clics).
- La tabla comparativa completa, sin aplicar los filtros que tuvieras puestos en pantalla.
- Para cada llamada: medidores, resumen RTCP, medidores RTCP, gráficas RTP y RTCP (capturadas como imágenes PNG, no como gráficos interactivos) y registro de anomalías.

Todo el proceso — parseo, cálculo y generación de las imágenes — ocurre en tu navegador; nada se sube a ningún servidor.

## 8 Metodología y fórmulas

Un resumen de cómo se calcula cada cosa. La aplicación incluye también esta información en su propia sección de "Metodología", siempre visible al final de la página.

#### Jitter (RFC 3550)

Para cada paquete `i` se calcula la diferencia `D` entre el intervalo de llegada real y el esperado según el timestamp RTP:

    D(i) = (llegada[i] - llegada[i-1]) - (timestampRTP[i] - timestampRTP[i-1]) / tasaDeReloj
    J(i) = J(i-1) + (|D(i)| - J(i-1)) / 16

`J` es una media móvil exponencial — el jitter mostrado en toda la aplicación. El mínimo excluye el primer paquete (no tiene jitter calculable, no hay uno anterior con el que comparar).

#### Skew

La misma `D(i)`, pero acumulada sin suavizar: `skew(i) = skew(i-1) + D(i)`. Revela deriva sostenida porque no "olvida" el pasado como sí hace el jitter suavizado.

#### Deriva de reloj y Freq. Drift

Se ajusta una recta de regresión al skew de todo el flujo. Si la pendiente es significativa *y* el desplazamiento acumulado total supera ~20 ms, se marca como deriva sostenida (`driftDetected`). El ppm se calcula como:

    ppm = (pendiente del skew por paquete ÷ intervalo de paquetización) × 10⁶

No es un estándar cerrado de la ITU-T, es una guía de ingeniería — y, como se explica en 5.1, puede salir alto sin que haya deriva real si el skew tuvo un rebrote puntual en algún punto de la llamada.

#### Pérdida de paquetes

Huecos en el número de secuencia RTP, con reconstrucción de los ciclos de 16 bits para llamadas largas (más de 65.536 paquetes).

#### Ancho de banda

Por paquete: tamaño de trama × 8 ÷ intervalo de llegada, con un suelo mínimo de 2 ms en el intervalo (para que dos paquetes casi simultáneos no disparen el valor a cifras absurdas). El "ancho de banda medio" mostrado es la **mediana** de esos valores, no la media aritmética — mucho más resistente a que un puñado de picos puntuales distorsionen el número representativo de toda la llamada. El "ancho de banda nominal (RTP)" es distinto: bytes totales enviados ÷ duración real según el timestamp RTP del emisor, sin depender en absoluto de la hora de llegada — por eso es inmune a los artefactos de captura de la sección 5.7.

#### MOS estimado

    MOS = 4.5 − mín(jitter_medio ÷ 10, 1.5) − pérdida% × 0.2

Heurística simplificada, **no** es el modelo E completo de la ITU-T (que exige latencia extremo a extremo real, no disponible en un pcap sin más contexto). Es una guía orientativa, útil para comparar flujos entre sí, no un valor certificable.

#### Umbrales de color usados en toda la aplicación

| Métrica | **Verde** | **Ámbar** | **Rojo** |
|----|----|----|----|
| Jitter | \< 20 ms | 20–50 ms | \> 50 ms |
| Pérdida de paquetes | \< 0,5% | 0,5–3% | \> 3% |
| MOS | ≥ 4 | 3–4 | \< 3 |
| Deriva de reloj (skew) | \< 20 ms | 20–100 ms | \> 100 ms |
| Freq. Drift | \< 50 ppm | 50–150 ppm | \> 150 ppm |

## 9 Limitaciones conocidas

- **Solo IPv4.** No se decodifica IPv6. RTP y RTCP en sí solo se analizan sobre UDP (el estándar casi universal para medio); la señalización SIP sí se analiza tanto sobre UDP como sobre TCP, pero no si va cifrada por TLS.
- **RTCP cifrado (SRTCP) no se puede interpretar.** La aplicación lo detecta y avisa, pero no puede descifrarlo sin la clave — que nunca está en un pcap normal.
- **El MOS es una heurística**, no el modelo E de la ITU-T. No lo uses como valor contractual o certificable.
- **La estimación automática de tasa de reloj** puede fallar si la llamada tiene muy pocos paquetes o un patrón de envío muy irregular — el SDP, cuando está disponible, siempre es más fiable.
- **No hay cálculo de RTT** (round-trip time) a partir de RTCP en esta versión — requeriría pares SR/RR completos en ambos sentidos, con una lógica adicional no implementada todavía.
- **Ficheros muy grandes** pueden tardar varios segundos en analizarse, al ejecutarse todo en el propio navegador sin backend.

## 10 Preguntas frecuentes

#### La aplicación me da un jitter/ancho de banda muy distinto al de Wireshark, ¿quién tiene razón?

Depende del caso, pero casi siempre se reduce a la **tasa de reloj** (2.6). Si el flujo tiene un tipo de carga útil dinámico, Wireshark puede etiquetarlo con un códec por defecto (frecuentemente asumiendo 8000 Hz) sin que eso sea necesariamente correcto. Comprueba en la tarjeta de tasa de reloj (5.2) qué frecuencia está usando esta aplicación y por qué, y compárala con la real del códec.

#### El "Freq. Drift" me sale altísimo pero la llamada suena bien, ¿es un error?

No necesariamente — mira si el medidor incluye el aviso "sin deriva sostenida confirmada" (5.1) y consulta la gráfica de skew (5.5): si el skew sube de golpe y luego se recupera, es un rebrote de red puntual, no una deriva de reloj real. Dos flujos de la misma llamada bidireccional pueden dar ppm muy distintos entre sí sin que eso sea un problema, porque cada dirección la genera un dispositivo distinto con su propio reloj.

#### ¿Por qué mi llamada aparece con jitter/pérdida altísimos en un pcapng capturado en una VM?

Revisa el aviso de artefacto de captura (5.7). Adaptadores virtuales (VMware vmxnet3, virtio, Hyper-V...) suelen agrupar paquetes al entregarlos a la captura, generando un patrón de llegada bimodal que no refleja lo que pasó realmente en la red.

#### ¿Por qué no aparece la sección de Señalización SIP?

Porque no se ha detectado ningún mensaje SIP en la traza. Recuerda que la búsqueda de SIP no depende del rango de puertos que configures para RTP, y que sí se busca tanto en UDP como en TCP (ver 2.5). Si sabes con certeza que la traza lleva SIP y aun así no aparece, la explicación más probable es que vaya **cifrado por TLS** (SIPS) — en ese caso no hay forma de leerlo sin la clave de descifrado, esté donde esté.

#### ¿Mis datos salen de mi navegador en algún momento?

No. Todo el análisis — parseo del pcap, cálculos, gráficas y generación de exportaciones — se ejecuta en el propio navegador con JavaScript. La única petición de red que hace la página es cargar la librería de gráficos (Chart.js) desde una CDN pública; el pcap en sí nunca se envía a ningún sitio.
