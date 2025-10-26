import pytest

from securevault.io import file_utils


def test_read_source_file(tmp_path):
    file_path = tmp_path / "example.txt"
    file_path.write_text("hello", encoding="utf-8")
    data, is_archive = file_utils.read_source(str(file_path))
    assert not is_archive
    assert data == b"hello"


def test_read_source_directory_and_materialize(tmp_path):
    folder = tmp_path / "input_dir"
    folder.mkdir()
    (folder / "nested").mkdir()
    (folder / "nested" / "data.txt").write_text("dir content", encoding="utf-8")

    data, is_archive = file_utils.read_source(str(folder))
    assert is_archive
    assert len(data) > 0

    output_dir = tmp_path / "output_dir"
    file_utils.materialize_output(str(output_dir), data, is_archive=True)
    extracted = output_dir / "nested" / "data.txt"
    assert extracted.exists()
    assert extracted.read_text(encoding="utf-8") == "dir content"


def test_read_source_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        file_utils.read_source(str(tmp_path / "missing"))
