from pathlib import Path

from sudo_to_ldif import build_policy_records


def test_wrapped_policy_rows_are_stitched_and_parsed(tmp_path: Path) -> None:
    source_csv = tmp_path / "ugly_policy.csv"
    source_csv.write_text(
        "\n".join(
            [
                "louapplds123,/etc/sudoers.d/g_vas_atavision/group,Defaults:%g_vas_atavision_linux_grp, !requiretty",
                "louapplds123,/etc/sudoers.d/g_vas_atavision,group,g_vas_atavision_linux_grp, ALL=(root) NOPASSWD: \\",
                "louapplsd123,/etc/sudoers.d/g_vas_atavision,user,/bin/true, \\",
                "louapplsd123,/etc/sudoers.d/g_vas_atavision,user,/sbin/ifconfig, \\",
                "louapplsd123,/etc/sudoers.d/g_vas_atavision,user,/bin/netstat --inet --inet6 -n \\",
                "louapplsd123,/etc/sudoers.d/g_vas_atavision,user,/usr/sbin/dmidecode",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    records = build_policy_records(source_csv)

    # One Defaults record and one stitched command-grant record.
    assert len(records) == 2

    defaults_record = next(r for r in records if r.parsed.commands == tuple())
    grant_record = next(r for r in records if r.parsed.commands != tuple())

    assert defaults_record.subject_name == "g_vas_atavision_linux_grp"
    assert grant_record.subject_name == "g_vas_atavision_linux_grp"

    assert defaults_record.parsed.commands == tuple()
    assert "!requiretty" in defaults_record.parsed.option_tokens

    assert grant_record.parsed.runas_users == ("root",)
    assert "!authenticate" in grant_record.parsed.option_tokens
    assert grant_record.parsed.commands == (
        "/bin/true",
        "/sbin/ifconfig",
        "/bin/netstat --inet --inet6 -n",
        "/usr/sbin/dmidecode",
    )
