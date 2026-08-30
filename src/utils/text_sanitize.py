#!/usr/bin/env python3
"""Strip emoji / variation selectors without deleting CJK or other non-ASCII text."""

import re

# Do not use a range such as U+24C2–U+1F251: that spans CJK Unified Ideographs.
_EMOJI_RE = re.compile(
    "["
    "\U0001F600-\U0001F64F"
    "\U0001F300-\U0001F5FF"
    "\U0001F680-\U0001F6FF"
    "\U0001F700-\U0001F77F"
    "\U0001F780-\U0001F7FF"
    "\U0001F800-\U0001F8FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA00-\U0001FA6F"
    "\U0001FA70-\U0001FAFF"
    "\U0001F1E0-\U0001F1FF"
    "\U00002600-\U000026FF"
    "\U00002700-\U000027BF"
    "\U0000FE00-\U0000FE0F"
    "\U0000200D"
    "]+",
    flags=re.UNICODE,
)


def clean_emoji_characters(text):
    """Remove emoji glyphs. Preserve Chinese and other non-ASCII text."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return _EMOJI_RE.sub("", text)
