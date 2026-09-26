# 03. System Architecture & Technical Specifications

## 1. Multi-View Architecture

```
                             +-------------------------------+
                             |    Raw ESP Packet Stream     |
                             +---------------+---------------+
                                             |
                     +-----------------------+-----------------------+
                     |                       |                       |
                     v                       v                       v
           +-------------------+   +-------------------+   +-------------------+
           |    VIEW A:        |   |    VIEW B:        |   |    VIEW C:        |
           | 14 Tabular Feats  |   | Packet Sequence   |   | Protocol Context  |
           | (Aggregate Stats) |   | (Length, log-IAT, |   | (ESP, Direction,  |
           |                   |   |  Direction, Pos)  |   |  IKE Markers)     |
           +---------+---------+   +---------+---------+   +---------+---------+
                     |                       |                       |
                     v                       v                       v
           +-------------------+   +-------------------+   +-------------------+
           |  Tabular Encoder  |   |  Transformer Seq  |   |  Context Encoder  |
           |  Linear(14 -> 32) |   |  Encoder (d=32)   |   |  Linear(4 -> 16)  |
           +---------+---------+   +---------+---------+   +---------+---------+
                     |                       |                       |
                     +-----------------------+-----------------------+
                                             |
                                             v
                           +-----------------------------------+
                           |         Multi-View Fusion         |
                           |   Concat [32 + 32 + 16] = 80-dim  |
                           |         Linear(80 -> 48)          |
                           |           GELU + LayerNorm        |
                           +-----------------+-----------------+
                                             |
                                             v
                           +-----------------------------------+
                           |        Classification Head        |
                           |          Linear(48 -> 4)          |
                           +-----------------+-----------------+
```

---

## 2. Technical Pipeline Specifications
1. **Packet Parser (`backend/app/protocols/packet_parser.py`)**: Uses Scapy to dissect Ethernet/IP/UDP/ESP headers without invoking slow external decoders.
2. **Deterministic Protocol Analyzer (`backend/app/protocols/ike.py`, `esp.py`)**: Extracts IKE Security Associations, cryptographic transform suites, SPI pairs, and replay counters.
3. **Flow Window Builder (`backend/app/features/flow_builder.py`)**: Slices ESP packet streams into non-overlapping 3.0-second flow windows.
4. **Hybrid Neural Classifier (`src/ml/sequence_models.py`)**: Fuses 14 tabular features with a 2-layer Transformer sequence encoder (Model C: 80.25% accuracy).
5. **Evidence Explanation Engine (`backend/app/evidence/explanation.py`)**: Formulates human-readable audit findings with strict source tagging.
6. **Telemetry & Evidence Store (`backend/app/database/models.py`)**: Production database built on **PostgreSQL + TimescaleDB** for hypertable time-series flow metrics and relational SA session storage.

