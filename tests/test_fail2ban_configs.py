import pathlib
import shutil

from fail2banexporter import fail2ban_configs

TESTDATA_DIR = pathlib.Path(__file__).parent / "testdata"
TESTDATA_LOCAL_PATHS = list(TESTDATA_DIR.glob("*.local"))


def test_parsing_example(tmp_path):
    (tmp_path / "jail.d").mkdir()
    for fpath in TESTDATA_LOCAL_PATHS:
        if fpath.name == "jail.local":
            shutil.copy(fpath, tmp_path)
        else:
            shutil.copy(fpath, tmp_path / "jail.d")

    config = fail2ban_configs.read(tmp_path)
    assert fail2ban_configs.read_jail_bantime(config, "nginx") == 300
    assert fail2ban_configs.read_jail_bantime(config, "sshd") == 600
