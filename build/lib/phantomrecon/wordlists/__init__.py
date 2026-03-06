from __future__ import annotations

import os
import random
from pathlib import Path
from typing import AsyncIterator, Iterator

WORDLIST_DIR = Path(__file__).parent

BUILTIN_SIZES = {
    "micro": "micro.txt",
    "small": "small.txt",
    "medium": "medium.txt",
    "large": "large.txt",
}


def get_builtin_wordlist_path(size: str) -> Path:
    filename = BUILTIN_SIZES.get(size, BUILTIN_SIZES["medium"])
    return WORDLIST_DIR / filename


def stream_wordlist(path: str | Path, shuffle: bool = True) -> Iterator[str]:
    words: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    if shuffle:
        random.shuffle(words)
    yield from words


def merge_wordlists(paths: list[str | Path], shuffle: bool = True) -> list[str]:
    seen: set[str] = set()
    words: list[str] = []
    for path in paths:
        for word in stream_wordlist(path, shuffle=False):
            if word not in seen:
                seen.add(word)
                words.append(word)
    if shuffle:
        random.shuffle(words)
    return words


def apply_extensions(paths: list[str], extensions: list[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        result.append(path)
        if not path.endswith("/"):
            for ext in extensions:
                ext = ext.lstrip(".")
                result.append(f"{path}.{ext}")
    return result


def apply_mutations(word: str) -> list[str]:
    mutations: list[str] = [word]
    mutations.append(word.lower())
    mutations.append(word.upper())
    mutations.append(word.capitalize())
    mutations.append(f"{word}_backup")
    mutations.append(f"{word}_old")
    mutations.append(f"{word}_new")
    mutations.append(f"{word}1")
    mutations.append(f"{word}2")
    mutations.append(f"{word}-old")
    mutations.append(f"{word}-backup")
    seen = set()
    result = []
    for m in mutations:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result
