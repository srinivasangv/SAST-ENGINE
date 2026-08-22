"""Multi-Stage Agentic SAST Engine.

    prepare  ->  scan  ->  validate  ->  prove

Each stage lives in its own module (stage1_prepare, stage2_scan,
stage3_validate, stage4_prove) and engine/pipeline.py wires them together.
See docs/architecture.md.
"""

__version__ = "1.0.0"
