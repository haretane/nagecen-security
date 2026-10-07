"""Development-only drafts. These do not affect diagnostic presentation."""
import fcntl
import json
import os
import tempfile
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

STORE_PATH = Path(__file__).resolve().parents[2] / 'development' / 'finding_edits.json'


class CatalogueEdit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=250)
    revision: int = Field(default=0, ge=0)
    literal_translation: str = Field(default='', max_length=12000)
    title: str = Field(default='', max_length=500)
    description: str = Field(default='', max_length=12000)
    solution: str = Field(default='', max_length=12000)
    prompt: str = Field(default='', max_length=20000)
    status: Literal['not_started', 'draft', 'reviewed'] = 'not_started'


def read_edits() -> dict:
    if not STORE_PATH.exists():
        return {}
    try:
        data = json.loads(STORE_PATH.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise ValueError('Invalid store')
        return data
    except (ValueError, OSError) as error:
        raise HTTPException(503, detail='保存ファイルを読み込めません。上書きせずに停止しました。') from error


def save_edit(edit: CatalogueEdit) -> dict:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with STORE_PATH.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = read_edits()
        if data.get(edit.name, {}).get('revision', 0) != edit.revision:
            raise HTTPException(409, detail='別の画面で更新されています。編集中の文章を控えてから再読み込みしてください。')
        saved = edit.model_dump()
        saved['revision'] += 1
        data[edit.name] = saved
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=STORE_PATH.parent, delete=False) as temp:
                temp_path = Path(temp.name)
                json.dump(data, temp, ensure_ascii=False, indent=2)
                temp.write('\n')
                temp.flush()
                os.fsync(temp.fileno())
            os.replace(temp_path, STORE_PATH)
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink()
        return saved
