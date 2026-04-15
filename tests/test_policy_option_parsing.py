from sudo_to_ldif import parse_sudo_policy_line


def test_standalone_ldap_option_is_not_treated_as_command() -> None:
    parsed = parse_sudo_policy_line("ALL=(root) !requiretty")

    assert parsed.runas_users == ("root",)
    assert parsed.option_tokens == ("!requiretty",)
    assert parsed.commands == tuple()
